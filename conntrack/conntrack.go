package conntrack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func (h *Handles) ConntrackTableList(table netlink.ConntrackTableType) ([]*ConntrackFlow, error) {
	req := h.newConntrackRequest(table, syscall.AF_INET, nl.IPCTNL_MSG_CT_GET, syscall.NLM_F_DUMP)

	res, _ := req.Execute(syscall.NETLINK_NETFILTER, 0)

	var result []*ConntrackFlow
	for _, dataRaw := range res {
		result = append(result, parseRawData(dataRaw))
	}

	return result, nil
}

func (h *Handles) ConntrackTableFlush(table netlink.ConntrackTableType) error {
	req := h.newConntrackRequest(table, syscall.AF_INET, nl.IPCTNL_MSG_CT_DELETE, syscall.NLM_F_ACK)

	_, err := req.Execute(syscall.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handles) ConntrackTableUpdate(table netlink.ConntrackTableType, flows []*ConntrackFlow) error {
	h.open()

	ipv4ValueSrc := NfValue32{
		Value: ip2int(flows[0].Forward.SrcIP),
	}

	ipv4ValueDst := NfValue32{
		Value: ip2int(flows[0].Forward.DstIP),
	}

	protoNum := NfValue8{
		Value: flows[0].Forward.Protocol,
	}

	srcPort := NfValue16{
		Value: flows[0].Forward.SrcPort,
	}

	dstPort := NfValue16{
		Value: flows[0].Forward.DstPort,
	}

	mark := NfValue32{
		Value: 13,
	}

	hdr := BuildNlMsgHeader(table)

	nfgen := BuildNfgenMsg(hdr)
	nfgenTupleOrigAttr := BuildNfNestedAttrMsg(nl.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, hdr, 48)
	nfgenTupleIpAttr := BuildNfAttrMsg(nl.NLA_F_NESTED|nl.CTA_TUPLE_IP, 16)
	nfgenTupleIpV4SrcAttr := BuildNfAttrMsg(nl.CTA_IP_V4_SRC, int(ipv4ValueSrc.Length()))
	nfgenTupleIpV4DstAttr := BuildNfAttrMsg(nl.CTA_IP_V4_DST, int(ipv4ValueDst.Length()))
	nfgenTupleProto := BuildNfNestedAttrMsg(nl.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, hdr, 24)
	nfgenTupleProtoNum := BuildNfAttrNoPaddingMsg(nl.CTA_PROTO_NUM, int(protoNum.Length()))
	nfgenTupleSrcPort := BuildNfAttrNoPaddingMsg(nl.CTA_PROTO_SRC_PORT, int(srcPort.Length()))
	nfgenTupleDstPort := BuildNfAttrNoPaddingMsg(nl.CTA_PROTO_DST_PORT, int(dstPort.Length()))
	nfgenMark := BuildNfAttrMsg(nl.CTA_MARK, int(mark.Length()))

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

	fmt.Println(nfgendata)
	fmt.Println(hdr.Len)
	hdr.Len = 80
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   nfgendata,
	}

	err := h.query(netlinkMsg)
	if err != nil {
		return fmt.Errorf("Error")

	}
	h.close()
	return fmt.Errorf("No Socket open")
}

func (h *Handles) newConntrackRequest(table netlink.ConntrackTableType, family netlink.InetFamily, operation, flags int) *nl.NetlinkRequest {

	req := h.newNetlinkRequest((int(table)<<8)|operation, flags)

	msg := &nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	}
	req.AddData(msg)
	return req
}

func parseRawData(data []byte) *ConntrackFlow {
	s := &ConntrackFlow{}

	reader := bytes.NewReader(data)

	binary.Read(reader, nl.NativeEndian(), &s.FamilyType)

	reader.Seek(3, seekCurrent)

	for reader.Len() > 0 {

		nested, t, l := parseNfAttrTL(reader)
		if nested && t == nl.CTA_TUPLE_ORIG {
			if nested, t, _ = parseNfAttrTL(reader); nested && t == nl.CTA_TUPLE_IP {

				parseIpTuple(reader, &s.Forward)

			}
		} else if nested && t == nl.CTA_TUPLE_REPLY {
			if nested, t, _ = parseNfAttrTL(reader); nested && t == nl.CTA_TUPLE_IP {
				parseIpTuple(reader, &s.Reverse)

				break
			} else {

				reader.Seek(int64(l), seekCurrent)
			}
		}
	}

	return s
}

func parseIpTuple(reader *bytes.Reader, tpl *ipTuple) {

	for i := 0; i < 2; i++ {
		_, t, _, v := parseNfAttrTLV(reader)
		switch t {
		case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
			tpl.SrcIP = v
		case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
			tpl.DstIP = v
		}
	}

	reader.Seek(4, seekCurrent)
	_, t, _, v := parseNfAttrTLV(reader)
	if t == nl.CTA_PROTO_NUM {
		tpl.Protocol = uint8(v[0])
	}

	reader.Seek(3, seekCurrent)
	for i := 0; i < 2; i++ {
		_, t, _ := parseNfAttrTL(reader)
		switch t {
		case nl.CTA_PROTO_SRC_PORT:
			parseBERaw16(reader, &tpl.SrcPort)
		case nl.CTA_PROTO_DST_PORT:
			parseBERaw16(reader, &tpl.DstPort)
		}

		reader.Seek(2, seekCurrent)
	}
}

func parseMark(reader *bytes.Reader, mark *int) {
	_, t, _, v := parseNfAttrTLV(reader)
	switch t {
	case nl.CTA_MARK:
		fmt.Println("This is Mark", v)
	}
}

func parseNfAttrTLV(r *bytes.Reader) (isNested bool, attrType, len uint16, value []byte) {
	isNested, attrType, len = parseNfAttrTL(r)

	value = make([]byte, len)

	binary.Read(r, binary.BigEndian, &value)

	return isNested, attrType, len, value
}

func parseNfAttrTL(r *bytes.Reader) (isNested bool, attrType, len uint16) {
	binary.Read(r, nl.NativeEndian(), &len)

	len -= nl.SizeofNfattr

	binary.Read(r, nl.NativeEndian(), &attrType)

	isNested = (attrType & nl.NLA_F_NESTED) == nl.NLA_F_NESTED

	attrType = attrType & (nl.NLA_F_NESTED - 1)

	return isNested, attrType, len
}

func parseBERaw16(r *bytes.Reader, v *uint16) {
	binary.Read(r, binary.BigEndian, v)
}
