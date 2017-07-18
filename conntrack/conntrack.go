package conntrack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// NewHandle which returns interface which implements Conntrack table get/set/flush
func NewHandle() Conntrack {
	return &Handles{Syscalls: syscallwrappers.NewSyscalls()}
}

// ConntrackTableList retrieves entries from Conntract table and parse it in the conntrack flow struct
// Using vishvananda/netlink and nl packages for parsing
// returns an array of ConntrackFlow with 4 tuples, protocol and mark
func (h *Handles) ConntrackTableList(table netlink.ConntrackTableType) ([]*ConntrackFlow, error) {
	req := h.newConntrackRequest(table, syscall.AF_INET, common.IPCTNL_MSG_CT_GET, syscall.NLM_F_DUMP)

	res, err := req.Execute(syscall.NETLINK_NETFILTER, 0)
	if err != nil {
		return nil, err
	}

	var result []*ConntrackFlow
	for _, dataRaw := range res {
		result = append(result, parseRawData(dataRaw))
	}
	if result == nil {
		return nil, fmt.Errorf("No conntrack entries")
	}

	return result, nil
}

// ConntrackTableFlush will flush the Conntrack table entries
// Using vishvananda/netlink and nl packages for flushing entries
func (h *Handles) ConntrackTableFlush(table netlink.ConntrackTableType) error {
	req := h.newConntrackRequest(table, syscall.AF_INET, common.IPCTNL_MSG_CT_DELETE, syscall.NLM_F_ACK)

	_, err := req.Execute(syscall.NETLINK_NETFILTER, 0)
	return err
}

// ConntrackTableUpdate will update conntrack table attributes for specified records
// Currently supports only mark
// Also prints number of entries updated and entries not updated (because of bad parameters)
func (h *Handles) ConntrackTableUpdate(table netlink.ConntrackTableType, flows []*ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) (int, error) {

	sh, err := h.open()
	if err != nil {
		return 0, err
	}

	var ipv4ValueSrc, ipv4ValueDst, mark common.NfValue32
	var protoNum common.NfValue8
	var srcPort, dstPort common.NfValue16
	var entriesUpdated int
	var recordsNotPresent int

	for i, _ := range flows {

		isEntryPresent := checkTuplesInFlow(flows[i], ipSrc, ipDst, protonum, srcport, dstport, newmark)

		if isEntryPresent && newmark != 0 {

			ipv4ValueSrc.Set32Value(common.IP2int(net.ParseIP(ipSrc)))
			ipv4ValueDst.Set32Value(common.IP2int(net.ParseIP(ipDst)))
			protoNum.Set8Value(protonum)
			srcPort.Set16Value(srcport)
			dstPort.Set16Value(dstport)
			mark.Set32Value(newmark)

			hdr, data := buildConntrackUpdateRequest(ipv4ValueSrc, ipv4ValueDst, mark, protoNum, srcPort, dstPort)

			netlinkMsg := &syscall.NetlinkMessage{
				Header: *hdr,
				Data:   data,
			}

			// The netlink message structure is the following:
			// Header:
			// syscall.NlMsghdr
			// Data:
			// <len, Family, Version, ResID> 4 bytes
			// <len, NLA_F_NESTED|CTA_TUPLE_ORIG> 4 bytes
			// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
			// <len, CTA_IP_V4_SRC, value> 4 bytes
			// <len, CTA_IP_V4_DST, value> 4 bytes
			// <len, NLA_F_NESTED|CTA_TUPLE_PROTO> 4 bytes
			// <len, CTA_PROTO_NUM, value, pad> 4 bytes
			// <len, CTA_PROTO_SRC_PORT, value, pad> 4 bytes
			// <len, CTA_PROTO_DST_PORT, value, pad> 4 bytes
			// <len, CTA_MARK, value> 4 bytes

			err := sh.query(netlinkMsg)
			if err != nil {
				return 0, err
			}
			entriesUpdated++

		} else if !isEntryPresent {

			recordsNotPresent++
		}
	}

	if entriesUpdated >= 0 {
		return entriesUpdated, nil
	}

	if recordsNotPresent >= 0 {
		return 0, fmt.Errorf("Number of entries not updated because of bad parameters %d", recordsNotPresent)
	}

	sh.close()
	return 0, nil
}

func checkTuplesInFlow(flow *ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) bool {

	var isSrcIPPresent, isDstIPPresent, isProtoPresent, isSrcPortPresent, isDstPortPresent bool

	if common.IP2int(flow.Forward.SrcIP) == common.IP2int(net.ParseIP(ipSrc)) && common.IP2int(flow.Reverse.SrcIP) == common.IP2int(net.ParseIP(ipDst)) {

		isSrcIPPresent = true
	} else {

		isSrcIPPresent = false
	}

	if common.IP2int(flow.Forward.DstIP) == common.IP2int(net.ParseIP(ipDst)) && common.IP2int(flow.Reverse.DstIP) == common.IP2int(net.ParseIP(ipSrc)) {

		isDstIPPresent = true
	} else {

		isDstIPPresent = false
	}

	if flow.Forward.Protocol == protonum && flow.Reverse.Protocol == protonum {

		isProtoPresent = true
	} else {

		isProtoPresent = false
	}

	if flow.Forward.SrcPort == srcport && flow.Reverse.SrcPort == dstport {

		isSrcPortPresent = true
	} else {

		isSrcPortPresent = false
	}

	if flow.Forward.DstPort == dstport && flow.Reverse.DstPort == srcport {

		isDstPortPresent = true
	} else {

		isDstPortPresent = false
	}
	if isSrcIPPresent && isDstIPPresent && isSrcPortPresent && isDstPortPresent && isProtoPresent {
		return true
	}

	return false
}

func buildConntrackUpdateRequest(ipv4ValueSrc, ipv4ValueDst, mark common.NfValue32, protoNum common.NfValue8, srcPort, dstPort common.NfValue16) (*syscall.NlMsghdr, []byte) {

	hdr := common.BuildNlMsgHeader(common.NfnlConntrackTable, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_INET, common.NFNetlinkV0, 0, hdr)
	nfgenTupleOrigAttr := common.BuildNfAttrMsg(NLA_F_NESTED|CTA_TUPLE_ORIG, hdr, SizeOfNestedTupleOrig)
	nfgenTupleIpAttr := common.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_TUPLE_IP, int(SizeOfNestedTupleIP))
	nfgenTupleIpV4SrcAttr := common.BuildNfNestedAttrMsg(CTA_IP_V4_SRC, int(ipv4ValueSrc.Length()))
	nfgenTupleIpV4DstAttr := common.BuildNfNestedAttrMsg(CTA_IP_V4_DST, int(ipv4ValueDst.Length()))
	nfgenTupleProto := common.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_TUPLE_PROTO, int(SizeOfNestedTupleProto))
	nfgenTupleProtoNum := common.BuildNfAttrWithPaddingMsg(CTA_PROTO_NUM, int(protoNum.Length()))
	nfgenTupleSrcPort := common.BuildNfAttrWithPaddingMsg(CTA_PROTO_SRC_PORT, int(srcPort.Length()))
	nfgenTupleDstPort := common.BuildNfAttrWithPaddingMsg(CTA_PROTO_DST_PORT, int(dstPort.Length()))
	nfgenMark := common.BuildNfAttrMsg(CTA_MARK, hdr, mark.Length())

	nfgendata := nfgen.ToWireFormat()
	nfgendata = append(nfgendata, nfgenTupleOrigAttr.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleIpAttr.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleIpV4SrcAttr.ToWireFormat()...)
	nfgendata = append(nfgendata, ipv4ValueSrc.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleIpV4DstAttr.ToWireFormat()...)
	nfgendata = append(nfgendata, ipv4ValueDst.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleProto.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleProtoNum.ToWireFormat()...)
	nfgendata = append(nfgendata, protoNum.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleSrcPort.ToWireFormat()...)
	nfgendata = append(nfgendata, srcPort.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenTupleDstPort.ToWireFormat()...)
	nfgendata = append(nfgendata, dstPort.ToWireFormat()...)
	nfgendata = append(nfgendata, nfgenMark.ToWireFormat()...)
	nfgendata = append(nfgendata, mark.ToWireFormat()...)

	return hdr, nfgendata
}

func (h *Handles) newConntrackRequest(table netlink.ConntrackTableType, family netlink.InetFamily, operation, flags int) *nl.NetlinkRequest {

	req := h.newNetlinkRequest((int(table)<<8)|operation, flags)

	msg := &nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     common.NFNetlinkV0,
		ResId:       0,
	}
	req.AddData(msg)

	return req
}

func (h *Handles) newNetlinkRequest(proto, flags int) *nl.NetlinkRequest {

	return &nl.NetlinkRequest{
		NlMsghdr: syscall.NlMsghdr{
			Len:   uint32(syscall.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
		},
	}
}

func parseRawData(data []byte) *ConntrackFlow {
	s := &ConntrackFlow{}
	var proto uint8
	reader := bytes.NewReader(data)
	binary.Read(reader, common.NativeEndian(), &s.FamilyType)

	reader.Seek(skipNetlinkHeader, seekCurrent)

	for reader.Len() > 0 {
		nested, t, l := parseNfAttrTL(reader)
		if nested && t == CTA_TUPLE_ORIG {
			if nested, t, _ = parseNfAttrTL(reader); nested && t == CTA_TUPLE_IP {
				proto = parseIpTuple(reader, &s.Forward)
			}
		} else if nested && t == CTA_TUPLE_REPLY {
			if nested, t, _ = parseNfAttrTL(reader); nested && t == CTA_TUPLE_IP {
				parseIpTuple(reader, &s.Reverse)
				break
			} else {
				reader.Seek(int64(l), seekCurrent)
			}
		}
	}

	parseMark(reader, proto, s)

	return s
}

func parseMark(reader *bytes.Reader, proto uint8, s *ConntrackFlow) {
	if proto == common.TCP_PROTO {
		reader.Seek(toMarkTCP, seekCurrent)
		_, t, _, v := parseNfAttrTLV(reader)
		if t == CTA_MARK {
			s.Mark = uint32(v[3])
		}
	} else if proto == common.UDP_PROTO {
		reader.Seek(toMarkUDP, seekCurrent)
		_, t, _, v := parseNfAttrTLV(reader)
		if t == CTA_MARK {
			s.Mark = uint32(v[3])
		}
	}
}

func parseIpTuple(reader *bytes.Reader, tpl *ipTuple) uint8 {
	for i := 0; i < 2; i++ {
		_, t, _, v := parseNfAttrTLV(reader)
		switch t {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			tpl.SrcIP = v
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			tpl.DstIP = v
		}
	}

	reader.Seek(4, seekCurrent)

	_, t, _, v := parseNfAttrTLV(reader)
	if t == CTA_PROTO_NUM {
		tpl.Protocol = uint8(v[0])
	}

	reader.Seek(toSrcPort, seekCurrent)

	for i := 0; i < 2; i++ {
		_, t, _ := parseNfAttrTL(reader)
		switch t {
		case CTA_PROTO_SRC_PORT:
			parseBERaw16(reader, &tpl.SrcPort)
		case CTA_PROTO_DST_PORT:
			parseBERaw16(reader, &tpl.DstPort)
		}

		reader.Seek(2, seekCurrent)
	}
	return tpl.Protocol
}

func parseNfAttrTLV(r *bytes.Reader) (isNested bool, attrType, len uint16, value []byte) {
	isNested, attrType, len = parseNfAttrTL(r)
	value = make([]byte, len)
	binary.Read(r, binary.BigEndian, &value)

	return isNested, attrType, len, value
}

func parseNfAttrTL(r *bytes.Reader) (isNested bool, attrType, len uint16) {
	binary.Read(r, common.NativeEndian(), &len)
	len -= common.SizeofNfAttr
	binary.Read(r, common.NativeEndian(), &attrType)

	isNested = (attrType & NLA_F_NESTED) == NLA_F_NESTED
	attrType = attrType & (NLA_F_NESTED - 1)

	return isNested, attrType, len
}

func parseBERaw16(r *bytes.Reader, v *uint16) {
	binary.Read(r, binary.BigEndian, v)
}

// Display the table entries
func (s *ConntrackFlow) String() string {
	return fmt.Sprintf("%s\t%d src=%s dst=%s sport=%d dport=%d\tsrc=%s dst=%s sport=%d dport=%d mark=%d",
		L4ProtoMap[s.Forward.Protocol], s.Forward.Protocol,
		s.Forward.SrcIP.String(), s.Forward.DstIP.String(), s.Forward.SrcPort, s.Forward.DstPort,
		s.Reverse.SrcIP.String(), s.Reverse.DstIP.String(), s.Reverse.SrcPort, s.Reverse.DstPort, s.Mark)
}
