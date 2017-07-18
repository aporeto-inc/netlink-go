package conntrack

import (
	"fmt"
	"net"
	"syscall"

	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
	"github.com/vishvananda/netlink"
)

// NewHandle which returns interface which implements Conntrack table get/set/flush
func NewHandle() Conntrack {
	return &Handles{Syscalls: syscallwrappers.NewSyscalls()}
}

// ConntrackTableList retrieves entries from Conntract table and parse it in the conntrack flow struct
// Using vishvananda/netlink and nl packages for parsing
// returns an array of ConntrackFlow with 4 tuples, protocol and mark
func (h *Handles) ConntrackTableList(table netlink.ConntrackTableType) ([]*netlink.ConntrackFlow, error) {
	result, err := netlink.ConntrackTableList(table, syscall.AF_INET)
	if result == nil || err != nil {
		return nil, fmt.Errorf("Empty table")
	}
	return result, nil
}

// ConntrackTableFlush will flush the Conntrack table entries
// Using vishvananda/netlink and nl packages for flushing entries
func (h *Handles) ConntrackTableFlush(table netlink.ConntrackTableType) error {
	err := netlink.ConntrackTableFlush(table)
	if err != nil {
		return err
	}
	return nil
}

// ConntrackTableUpdate will update conntrack table attributes for specified records
// Currently supports only mark
// Also prints number of entries updated and entries not updated (because of bad parameters)
func (h *Handles) ConntrackTableUpdate(table netlink.ConntrackTableType, flows []*netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) (int, error) {

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

func checkTuplesInFlow(flow *netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) bool {

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
