package conntrack

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"fmt"
)

import "github.com/vishvananda/netlink"

const (
	nlMsgAlignTo = 4 //Align to nibble boundaries
	nfaAlignTo   = 4
)

//BuildNlMsgHeader -- Build syscall.NlMsgHdr structure
//msgType: the type of table to be used
//Len: Len of the payload including the sizeof nlmsghdr
func BuildNlMsgHeader(table netlink.ConntrackTableType, len uint32) *syscall.NlMsghdr {
	return &syscall.NlMsghdr{
		Len:   NlMsgLength(len),
		Type:  uint16((int(table) << 8) | IPCTNL_MSG_CT_NEW),
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
	}
}

//BuildNfgenMsg -- Build nfgen msg strcuure
//hdr - syscall.NlMsghdr to adjust length after adding nfgen
func BuildNfgenMsg(hdr *syscall.NlMsghdr) *NfGenMsg {
	hdr.Len = NlMsgLength(SizeofNfgenmsg)
	return &NfGenMsg{
		NfgenFamily: uint8(syscall.AF_INET),
		Version:     NFNETLINK_V0,
		ResID:       0,
	}
}

//BuildNfAttrMsg -- Build nfattr message
//attrType -- Type of attr being added
//dataLEn -- Length of the attribute
func BuildNfAttrMsg(attrType uint16, dataLen int) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = NfaLength(uint16((dataLen)))
	return attr
}

//BuildNfAttrMsg -- Build nfnestedattr message
//attrType -- Type of nested attr being added
//n -- syscall.NlMsghdr to adjust length after adding nfgen
//dataLen -- Length of the attribute
func BuildNfNestedAttrMsg(attrType uint16, n *syscall.NlMsghdr, dataLen int) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = NfaLength(uint16((dataLen)))
	n.Len += uint32(NfaLength(uint16(dataLen)))
	return attr
}

//BuildNfAttrWithPaddingMsg -- Build nfattrWithPadding message
//attrType -- Type of attr which needs padding
//dataLen -- Length of the attribute
func BuildNfAttrWithPaddingMsg(attrType uint16, dataLen int) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = uint16(dataLen) + nfaAlignTo
	return attr
}

//ToWireFormat -- Convert NfGenMsg to byte slice
func (r *NfGenMsg) ToWireFormat() []byte {
	buf := make([]byte, SizeofNfgenmsg)
	copy(buf, []byte{r.NfgenFamily})
	copy(buf[1:], []byte{r.Version})
	NativeEndian().PutUint16(buf[2:], r.ResID)
	return buf
}

//ToWireFormat -- Convert NfAttr to byte slice
func (r *NfAttr) ToWireFormat() []byte {
	buf := make([]byte, int(SizeofNfattr))
	NativeEndian().PutUint16(buf, r.nfaLen)
	NativeEndian().PutUint16(buf[2:], r.nfaType)
	return buf
}

//ToWireFormat -- Convert NfValue8 to byte slice
func (r *NfValue8) ToWireFormat() []byte {
	buf := make([]byte, int(SizeOfValue32))
	buf[0] = r.value
	return buf
}

//ToWireFormat -- Convert NfValue16 to byte slice
func (r *NfValue16) ToWireFormat() []byte {
	buf := make([]byte, int(SizeOfValue32))
	binary.BigEndian.PutUint16(buf, r.value)
	return buf
}

//ToWireFormat -- Convert NfValue32 to byte slice
func (r *NfValue32) ToWireFormat() []byte {
	buf := make([]byte, int(SizeOfValue32))
	binary.BigEndian.PutUint32(buf, r.value)
	return buf
}

//NetlinkMessageToStruct -- Convert netlink message byte slice to struct and payload
func NetlinkMessageToStruct(buf []byte) (*syscall.NlMsghdr, []byte, error) {
	if len(buf) <= 15 {
		return nil, []byte{}, fmt.Errorf("Buffer is empty")
	}
	hdr := &syscall.NlMsghdr{}
	hdr.Len = NativeEndian().Uint32(buf)
	hdr.Type = NativeEndian().Uint16(buf[4:])
	hdr.Flags = NativeEndian().Uint16(buf[6:])
	return hdr, buf[8:], nil
}

//NetlinkMessageToNfGenStruct -- Convert netlink byte slice to nfgen msg structure
func NetlinkMessageToNfGenStruct(buf []byte) (*NfGenMsg, []byte, error) {
	hdr := &NfGenMsg{}
	hdr.NfgenFamily = buf[0]
	hdr.Version = buf[1]
	hdr.ResID = binary.BigEndian.Uint16(buf[2:])
	return hdr, buf[4:], nil
}

//NetlinkErrMessagetoStruct -- parse byte slice and return syscall.NlMsgerr
func NetlinkErrMessagetoStruct(buf []byte) (*syscall.NlMsghdr, *syscall.NlMsgerr) {
	err := &syscall.NlMsgerr{}
	err.Error = int32(NativeEndian().Uint32(buf))
	hdr, _, _ := NetlinkMessageToStruct(buf[4:])
	return hdr, err

}

//NlMsgLength -- adjust length to end on 4 byte multiple
func NlMsgLength(len uint32) uint32 {
	return len + NlMsgAlign(syscall.SizeofNlMsghdr)
}

//NlMsgAlign -- Align to 4 byte boundary
func NlMsgAlign(len uint32) uint32 {
	return (len + nlMsgAlignTo - 1) &^ (nlMsgAlignTo - 1)
}

//NfaLength -- adjust length to end on 4 byte multiple
func NfaLength(len uint16) uint16 {
	return NfaAlign(len + SizeofNfattr)
}

//NfaAlign -- Align to 4 byte boundary
func NfaAlign(len uint16) uint16 {
	return (len + nfaAlignTo - 1) &^ (nfaAlignTo - 1)
}

//Length -- Return length of struct
func (r *NfValue32) Length() uint32 {
	return uint32(unsafe.Sizeof(NfValue32{}))
}

//Length -- Return length of struct
func (r *NfValue16) Length() uint16 {
	return uint16(unsafe.Sizeof(NfValue16{}))
}

//Length -- Return length of struct
func (r *NfValue8) Length() uint8 {
	return uint8(unsafe.Sizeof(NfValue8{}))
}

// To convert net.IP to uint32
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// To convert uint32 to net.IP
func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// Display the table entries
func (s *ConntrackFlow) String() string {
	return fmt.Sprintf("%s\t%d src=%s dst=%s sport=%d dport=%d\tsrc=%s dst=%s sport=%d dport=%d mark=%d",
		L4ProtoMap[s.Forward.Protocol], s.Forward.Protocol,
		s.Forward.SrcIP.String(), s.Forward.DstIP.String(), s.Forward.SrcPort, s.Forward.DstPort,
		s.Reverse.SrcIP.String(), s.Reverse.DstIP.String(), s.Reverse.SrcPort, s.Reverse.DstPort, s.Mark)
}
