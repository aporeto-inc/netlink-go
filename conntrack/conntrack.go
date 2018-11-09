// +build linux !darwin

package conntrack

import (
	"fmt"
	"net"
	"syscall"

	"go.aporeto.io/netlink-go/common"
	"go.aporeto.io/netlink-go/common/syscallwrappers"

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
	return err
}

// ConntrackTableUpdateMarkForAvailableFlow will update conntrack table mark attribute only if the flow is present
// Also returns number of entries updated
func (h *Handles) ConntrackTableUpdateMarkForAvailableFlow(flows []*netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) (int, error) {

	var entriesUpdated int

	for i := range flows {
		isEntryPresent := checkTuplesInFlow(flows[i], ipSrc, ipDst, protonum, srcport, dstport)

		if isEntryPresent && newmark != 0 {
			err := h.ConntrackTableUpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
			if err != nil {
				return 0, fmt.Errorf("Error %v", err)
			}
			entriesUpdated++
		}
	}

	if entriesUpdated >= 0 {
		return entriesUpdated, nil
	}

	return 0, fmt.Errorf("Entry not present")
}

// ConntrackTableUpdateMark will update conntrack table mark attribute
func (h *Handles) ConntrackTableUpdateMark(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error {

	var mark common.NfValue32

	hdr, data := buildConntrackUpdateRequest(ipSrc, ipDst, protonum, srcport, dstport)

	mark.Set32Value(newmark)
	data = append(data, appendMark(mark, hdr)...)

	err := h.SendMessage(hdr, data)

	return err
}

// ConntrackTableUpdateLabel will update conntrack table label attribute
// Specific to protocol (TCP or UDP)
// Also returns number of entries updated
func (h *Handles) ConntrackTableUpdateLabel(table netlink.ConntrackTableType, flows []*netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newlabels uint32) (int, error) {

	var entriesUpdated int
	var labels common.NfValue32

	for i := range flows {
		isEntryPresent := checkTuplesInFlow(flows[i], ipSrc, ipDst, protonum, srcport, dstport)

		if isEntryPresent {
			hdr, data := buildConntrackUpdateRequest(ipSrc, ipDst, protonum, srcport, dstport)

			if protonum == common.TCP_PROTO {
				data = append(data, appendProtoInfo(hdr)...)
			}

			labels.Set32Value(newlabels)
			data = append(data, appendLabel(labels, hdr)...)

			err := h.SendMessage(hdr, data)
			if err != nil {
				return 0, err
			}
			entriesUpdated++
		}
	}

	if entriesUpdated >= 0 {
		return entriesUpdated, nil
	}

	return 0, fmt.Errorf("Entry not present")
}

// checkTuplesInFlow will check the flow with the given parameters (4 tuples and protocol)
// returns true if the table has the given flow, false otherwise
func checkTuplesInFlow(flow *netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16) bool {

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

// buildConntrackUpdateRequest is generic for all conntrack attribute updates
// returns bytes till dstport from the table, if the flow is present
// to update other attributes, it is highly recommended to check the length of the NESTED attributes
func buildConntrackUpdateRequest(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16) (*syscall.NlMsghdr, []byte) {

	var ipv4ValueSrc, ipv4ValueDst common.NfValue32
	var protoNum common.NfValue8
	var srcPort, dstPort common.NfValue16

	ipv4ValueSrc.Set32Value(common.IP2int(net.ParseIP(ipSrc)))
	ipv4ValueDst.Set32Value(common.IP2int(net.ParseIP(ipDst)))
	protoNum.Set8Value(protonum)
	srcPort.Set16Value(srcport)
	dstPort.Set16Value(dstport)

	hdr := common.BuildNlMsgHeader(common.NfnlConntrackTable, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_INET, common.NFNetlinkV0, 0, hdr)
	nfgenTupleOrigAttr := common.BuildNfAttrMsg(NLA_F_NESTED|CTA_TUPLE_ORIG, hdr, SizeOfNestedTupleOrig)
	nfgenTupleIPAttr := common.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_TUPLE_IP, int(SizeOfNestedTupleIP))
	nfgenTupleIPV4SrcAttr := common.BuildNfNestedAttrMsg(CTA_IP_V4_SRC, int(ipv4ValueSrc.Length()))
	nfgenTupleIPV4DstAttr := common.BuildNfNestedAttrMsg(CTA_IP_V4_DST, int(ipv4ValueDst.Length()))
	nfgenTupleProto := common.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_TUPLE_PROTO, int(SizeOfNestedTupleProto))
	nfgenTupleProtoNum := common.BuildNfAttrWithPaddingMsg(CTA_PROTO_NUM, int(protoNum.Length()))
	nfgenTupleSrcPort := common.BuildNfAttrWithPaddingMsg(CTA_PROTO_SRC_PORT, int(srcPort.Length()))
	nfgenTupleDstPort := common.BuildNfAttrWithPaddingMsg(CTA_PROTO_DST_PORT, int(dstPort.Length()))

	buf := make([]byte, 3*int(common.SizeofNfAttr)+int(common.SizeofNfGenMsg)+2*int(common.NfaLength(uint16(common.SizeOfValue32)))+2*int(common.NfaLength(uint16(common.SizeOfValue16)))+int(common.NfaLength(uint16(common.SizeOfValue8))))
	copyIndex := nfgen.ToWireFormatBuf(buf)
	copyIndex += nfgenTupleOrigAttr.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleIPAttr.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleIPV4SrcAttr.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += ipv4ValueSrc.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleIPV4DstAttr.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += ipv4ValueDst.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleProto.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleProtoNum.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += protoNum.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleSrcPort.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += srcPort.ToWireFormatBuf(buf[copyIndex:])
	copyIndex += nfgenTupleDstPort.ToWireFormatBuf(buf[copyIndex:])
	dstPort.ToWireFormatBuf(buf[copyIndex:])

	return hdr, buf
}

// appendMark will add the given mark to the flows
func appendMark(mark common.NfValue32, hdr *syscall.NlMsghdr) []byte {
	nfgenMark := common.BuildNfAttrMsg(CTA_MARK, hdr, mark.Length())

	markData := nfgenMark.ToWireFormat()
	markData = append(markData, mark.ToWireFormat()...)

	return markData
}

// appendLabel will add the given label to the flows
func appendLabel(label common.NfValue32, hdr *syscall.NlMsghdr) []byte {
	nfgenLabel := common.BuildNfAttrMsg(CTA_LABELS, hdr, label.Length())

	buf := make([]byte, int(common.SizeOfValue32))
	common.NativeEndian().PutUint32(buf, label.Get32Value())

	labelData := nfgenLabel.ToWireFormat()
	labelData = append(labelData, buf...)

	return labelData
}

// appendProtoInfo will add protocolinfo to the bytes
// only if the protocol is TCP
func appendProtoInfo(hdr *syscall.NlMsghdr) []byte {
	var flagsOrig, flagsReply common.NfValue16
	var data []byte

	flagsOrig.Set16Value(uint16(2570))
	flagsReply.Set16Value(uint16(2570))

	protoData := common.BuildNfAttrMsg(NLA_F_NESTED|CTA_PROTOINFO, hdr, SizeofNestedProtoInfo)
	protoTCPData := common.BuildNfNestedAttrMsg(NLA_F_NESTED|CTA_PROTOINFO_TCP, int(SizeofNestedProtoInfoTCP))
	protoOriginal := common.BuildNfAttrWithPaddingMsg(CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, int(flagsOrig.Length()))
	protoReply := common.BuildNfAttrWithPaddingMsg(CTA_PROTOINFO_TCP_FLAGS_REPLY, int(flagsReply.Length()))

	data = append(data, protoData.ToWireFormat()...)
	data = append(data, protoTCPData.ToWireFormat()...)
	data = append(data, protoOriginal.ToWireFormat()...)
	data = append(data, flagsOrig.ToWireFormat()...)
	data = append(data, protoReply.ToWireFormat()...)
	data = append(data, flagsReply.ToWireFormat()...)

	return data
}

// SendMessage -- To send and receive netlink messages
// calls the private function sendmessage
func (h *Handles) SendMessage(hdr *syscall.NlMsghdr, data []byte) error {
	return h.sendMessage(hdr, data)
}

func (h *Handles) sendMessage(hdr *syscall.NlMsghdr, data []byte) error {
	sh, err := h.open()
	defer sh.close()
	if err != nil {
		return err
	}

	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   data,
	}

	err = sh.query(netlinkMsg)
	if err != nil {
		return err
	}

	return nil
}
