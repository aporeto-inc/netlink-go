package conntrack

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"fmt"

	"github.com/vishvananda/netlink/nl"
)

import "github.com/vishvananda/netlink"

const (
	nlMsgAlignTo = 4 //Align to nibble boundaries
	nfaAlignTo   = 4
)

func BuildNlMsgHeader(table netlink.ConntrackTableType) *syscall.NlMsghdr {
	return &syscall.NlMsghdr{
		Len:   uint32(syscall.SizeofNlMsghdr),
		Type:  uint16((int(table) << 8) | nl.IPCTNL_MSG_CT_NEW),
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
	}
}

func BuildNfgenMsg(hdr *syscall.NlMsghdr) *NfqGenMsg {
	hdr.Len = NlMsgLength(SizeofNfGenMsg)
	return &NfqGenMsg{
		NfgenFamily: uint8(syscall.AF_INET),
		Version:     nl.NFNETLINK_V0,
		ResID:       0,
	}
}

func BuildNfNestedAttrMsg(attrType uint16, n *syscall.NlMsghdr, dataLen int) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = NfaLength(uint16((dataLen)))

	n.Len += uint32(NfaLength(uint16(dataLen)))
	return attr
}

func BuildNfAttrMsg(attrType uint16, dataLen int) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = NfaLength(uint16((dataLen)))

	return attr
}

func BuildNfAttrNoPaddingMsg(attrType uint16, dataLen int) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = uint16(dataLen) + nfaAlignTo

	return attr
}

func (r *NfqGenMsg) ToWireFormat() []byte {

	buf := make([]byte, SizeofNfGenMsg)
	copy(buf, []byte{r.NfgenFamily})
	copy(buf[1:], []byte{r.Version})
	NativeEndian().PutUint16(buf[2:], r.ResID)

	return buf
}

//ToWireFormat -- Convert NfAttr to byte slice
func (r *NfAttr) ToWireFormat() []byte {

	buf := make([]byte, int(SizeofNfAttr))
	NativeEndian().PutUint16(buf, r.nfaLen)
	NativeEndian().PutUint16(buf[2:], r.nfaType)

	return buf
}

func (r *NfValue8) ToWireFormat() []byte {

	buf := make([]byte, int(SizeOfValue32))
	buf[0] = r.Value
	return buf
}

func (r *NfValue16) ToWireFormat() []byte {

	buf := make([]byte, int(SizeOfValue32))
	binary.BigEndian.PutUint16(buf, r.Value)

	return buf
}

func (r *NfValue32) ToWireFormat() []byte {

	buf := make([]byte, int(SizeOfValue32))
	binary.BigEndian.PutUint32(buf, r.Value)

	return buf
}

//ToWireFormat -- Convert NfqMsgConfigQueueLen to byte slice
func (r *conntrackMarkHdr) ToWireFormat() []byte {
	buf := make([]byte, SizeOfConntrackLength)
	binary.BigEndian.PutUint32(buf, r.mark)
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

func NetlinkMessageToNfGenStruct(buf []byte) (*NfqGenMsg, []byte, error) {
	hdr := &NfqGenMsg{}
	hdr.NfgenFamily = buf[0]
	hdr.Version = buf[1]
	hdr.ResID = binary.BigEndian.Uint16(buf[2:])
	return hdr, buf[4:], nil
}

//NetlinkMessageToNfAttrStruct -- Convert byte slice representing nfattr to nfattr struct slice
func NetlinkMessageToNfAttrStruct(buf []byte, hdr []*NfAttrResponsePayload) {
	//hdr := make([]*NfAttrResponsePayload, nfqaMax)

}

func NetlinkErrMessagetoStruct(buf []byte) (*syscall.NlMsghdr, *syscall.NlMsgerr) {
	err := &syscall.NlMsgerr{}
	err.Error = int32(NativeEndian().Uint32(buf))
	hdr, _, _ := NetlinkMessageToStruct(buf[4:])
	return hdr, err

}

//Length -- Return length of struct
func (r *conntrackMarkHdr) Length() uint32 {
	return uint32(unsafe.Sizeof(conntrackMarkHdr{}))
}

//NlMsgLength -- adjust length to end on 4 byte multiple
func NlMsgLength(len uint32) uint32 {
	return len + NlMsgAlign(syscall.SizeofNlMsghdr)
}

//NlMsgAlign -- Align to 4 byte boundary
func NlMsgAlign(len uint32) uint32 {
	return (len + nlMsgAlignTo - 1) &^ (nlMsgAlignTo - 1)
}

func NfaLength(len uint16) uint16 {

	return NfaAlign(len + SizeofNfAttr)
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

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
