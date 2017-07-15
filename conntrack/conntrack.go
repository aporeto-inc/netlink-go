package conntrack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/aporeto-inc/netlink-go/commons"
	"github.com/aporeto-inc/netlink-go/commons/syscallwrappers"
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
	req := h.newConntrackRequest(table, syscall.AF_INET, commons.IPCTNL_MSG_CT_GET, syscall.NLM_F_DUMP)

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
	req := h.newConntrackRequest(table, syscall.AF_INET, commons.IPCTNL_MSG_CT_DELETE, syscall.NLM_F_ACK)

	_, err := req.Execute(syscall.NETLINK_NETFILTER, 0)
	return err
}

// ConntrackTableUpdate will update conntrack table attributes for specified records
// Currently supports only mark
// Also prints number of entries updated and entries not updated (because of bad parameters)
func (h *Handles) ConntrackTableUpdate(table netlink.ConntrackTableType, flows []*ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error {

	sh, err := h.open()
	if err != nil {
		return err
	}

	var ipv4ValueSrc, ipv4ValueDst, mark commons.NfValue32
	var protoNum commons.NfValue8
	var srcPort, dstPort commons.NfValue16
	var entriesUpdated int
	var recordsNotPresent int
	var isSrcIPPresent, isDstIPPresent, isProtoPresent, isSrcPortPresent, isDstPortPresent bool

	for i, _ := range flows {

		if commons.Ip2int(flows[i].Forward.SrcIP) == commons.Ip2int(net.ParseIP(ipSrc)) && commons.Ip2int(flows[i].Reverse.SrcIP) == commons.Ip2int(net.ParseIP(ipDst)) {

			ipv4ValueSrc.Set32Value(commons.Ip2int(net.ParseIP(ipSrc)))

			isSrcIPPresent = true
		} else {

			isSrcIPPresent = false
		}

		if commons.Ip2int(flows[i].Forward.DstIP) == commons.Ip2int(net.ParseIP(ipDst)) && commons.Ip2int(flows[i].Reverse.DstIP) == commons.Ip2int(net.ParseIP(ipSrc)) {

			ipv4ValueDst.Set32Value(commons.Ip2int(net.ParseIP(ipDst)))

			isDstIPPresent = true
		} else {

			isDstIPPresent = false
		}

		if flows[i].Forward.Protocol == protonum && flows[i].Reverse.Protocol == protonum {

			protoNum.Set8Value(protonum)

			isProtoPresent = true
		} else {

			isProtoPresent = false
		}

		if flows[i].Forward.SrcPort == srcport && flows[i].Reverse.SrcPort == dstport {

			srcPort.Set16Value(srcport)

			isSrcPortPresent = true
		} else {

			isSrcPortPresent = false
		}

		if flows[i].Forward.DstPort == dstport && flows[i].Reverse.DstPort == srcport {

			dstPort.Set16Value(dstport)

			isDstPortPresent = true
		} else {

			isDstPortPresent = false
		}

		if isSrcIPPresent && isDstIPPresent && isSrcPortPresent && isDstPortPresent && isProtoPresent && newmark != 0 {

			mark.Set32Value(newmark)

			hdr := commons.BuildNlMsgHeader(commons.NfnlConntrackTable, commons.NlmFRequest|commons.NlmFAck, 0)
			nfgen := commons.BuildNfgenMsg(syscall.AF_INET, commons.NFNetlinkV0, 0, hdr)
			nfgenTupleOrigAttr := commons.BuildNfAttrMsg(NLA_F_NESTED|CTA_TUPLE_ORIG, hdr, SizeOfNestedTupleOrig)
			nfgenTupleIpAttr := commons.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_TUPLE_IP, int(SizeOfNestedTupleIP))
			nfgenTupleIpV4SrcAttr := commons.BuildNfNestedAttrMsg(CTA_IP_V4_SRC, int(ipv4ValueSrc.Length()))
			nfgenTupleIpV4DstAttr := commons.BuildNfNestedAttrMsg(CTA_IP_V4_DST, int(ipv4ValueDst.Length()))
			nfgenTupleProto := commons.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_TUPLE_PROTO, int(SizeOfNestedTupleProto))
			nfgenTupleProtoNum := commons.BuildNfAttrWithPaddingMsg(CTA_PROTO_NUM, int(protoNum.Length()))
			nfgenTupleSrcPort := commons.BuildNfAttrWithPaddingMsg(CTA_PROTO_SRC_PORT, int(srcPort.Length()))
			nfgenTupleDstPort := commons.BuildNfAttrWithPaddingMsg(CTA_PROTO_DST_PORT, int(dstPort.Length()))
			nfgenMark := commons.BuildNfAttrMsg(CTA_MARK, hdr, mark.Length())

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

			netlinkMsg := &syscall.NetlinkMessage{
				Header: *hdr,
				Data:   nfgendata,
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
				return err
			}
			entriesUpdated++
		} else if !isSrcIPPresent || !isDstIPPresent || !isSrcPortPresent || !isDstPortPresent || !isProtoPresent {

			recordsNotPresent++
		}

	}

	fmt.Println("Number of entries updated", entriesUpdated)

	if recordsNotPresent >= 0 {
		return fmt.Errorf("Number of entries not updated because of bad parameters %d", recordsNotPresent)
	}

	sh.close()
	return nil
}

func (h *Handles) newConntrackRequest(table netlink.ConntrackTableType, family netlink.InetFamily, operation, flags int) *nl.NetlinkRequest {

	req := h.newNetlinkRequest((int(table)<<8)|operation, flags)

	msg := &nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     commons.NFNetlinkV0,
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
	binary.Read(reader, commons.NativeEndian(), &s.FamilyType)

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

	if proto == commons.TCP_PROTO {
		reader.Seek(toMarkTCP, seekCurrent)
		_, t, _, v := parseNfAttrTLV(reader)
		if t == CTA_MARK {
			s.Mark = uint32(v[3])
		}
	} else if proto == commons.UDP_PROTO {
		reader.Seek(toMarkUDP, seekCurrent)
		_, t, _, v := parseNfAttrTLV(reader)
		if t == CTA_MARK {
			s.Mark = uint32(v[3])
		}
	}

	return s
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
	binary.Read(r, commons.NativeEndian(), &len)
	len -= commons.SizeofNfAttr
	binary.Read(r, commons.NativeEndian(), &attrType)

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
