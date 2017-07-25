package common

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

//NlMsgType Returns the Messagetype
func NlMsgType(h *syscall.NlMsghdr) uint16 {
	return h.Type & 0x00ff
}

//NlMsgSubsysID returns the subsystem id -- 3 for queue
func NlMsgSubsysID(h *syscall.NlMsghdr) uint16 {
	return (h.Type & 0xff00) >> 8
}

//NlMsgAlign -- Align to 4 byte boundary
func NlMsgAlign(len uint32) uint32 {
	return (len + nlMsgAlignTo - 1) &^ (nlMsgAlignTo - 1)
}

//NfaAlign -- Align to 4 byte boundary
func NfaAlign(len uint16) uint16 {
	return (len + nfaAlignTo - 1) &^ (nfaAlignTo - 1)
}

//NfaAlign32 -- Align to 4 byte boundary
func NfaAlign32(len uint32) uint32 {
	return (len + nfaAlignTo - 1) &^ (nfaAlignTo - 1)
}

//NlMsgLength -- adjust length to end on 4 byte multiple
func NlMsgLength(len uint32) uint32 {
	return len + NlMsgAlign(syscall.SizeofNlMsghdr)
}

//NlMsgSpace -- Space required to hold this message
func NlMsgSpace(len uint32) uint32 {
	return NlMsgAlign(NlMsgLength(len))
}

//NfaLength -- adjust length to end on 4 byte multiple
func NfaLength(len uint16) uint16 {
	return NfaAlign(len + SizeofNfAttr)
}

//BuildNlMsgHeader -- Build syscall.NlMsgHdr structure
//msgType: The message type to be send | SUBSYSID - 3 for us
//Len: Len of the payload including the sizeof nlmsghdr
//msgFlags: Request Flags
func BuildNlMsgHeader(msgType msgTypes, msgFlags NlmFlags, len uint32) *syscall.NlMsghdr {
	return &syscall.NlMsghdr{
		Len:   NlMsgLength(len),
		Type:  uint16(msgType),
		Flags: uint16(msgFlags),
		Pid:   0,
		Seq:   0,
	}
}

//BuildNfgenMsg -- Build nfgen msg strcuure
//family -- SOCK FAMILY
//Version -- Version
//resId -- queuenum
//n - syscall.NlMsghdr to adjust length after adding nfgen
func BuildNfgenMsg(family int, version uint8, resID uint16, n *syscall.NlMsghdr) *NfqGenMsg {
	n.Len = NlMsgLength(SizeofNfGenMsg)
	return &NfqGenMsg{
		nfgenFamily: uint8(family),
		version:     uint8(version),
		resID:       uint16(resID),
	}
}

//BuildNfAttrMsg -- Build nfattr message
//length -- length of the attr payload -- unused
//attrType -- Type of attr being added
//data --- The actual data being added. We only use this to figure out the size of payload.
//The payload needs to be appended separately
//n -- syscall.NlMsgHdr adjust length after building the nfattr
func BuildNfAttrMsg(attrType uint16, n *syscall.NlMsghdr, dataLen uint32) *NfAttr {
	n.Len += uint32(NfaLength(uint16((dataLen))))
	return &NfAttr{
		nfaLen:  NfaLength(uint16((dataLen))),
		nfaType: attrType,
	}
}

//SerializeNlMsgHdr -- Serialize syscall.NlMsgHdr to byte slice
func SerializeNlMsgHdr(hdr *syscall.NlMsghdr) []byte {
	buf := make([]byte, syscall.SizeofNlMsghdr)
	NativeEndian().PutUint32(buf[0:4], hdr.Len)
	NativeEndian().PutUint16(buf[4:6], hdr.Type)
	NativeEndian().PutUint16(buf[6:8], hdr.Flags)
	NativeEndian().PutUint32(buf[8:12], hdr.Seq)
	NativeEndian().PutUint32(buf[12:16], hdr.Pid)
	return buf
}

//SerializeNlMsgHdrBuf -- Serialize into passed buffer and returns number of bytes copied
func SerializeNlMsgHdrBuf(hdr *syscall.NlMsghdr, buf []byte) int {
	NativeEndian().PutUint32(buf[0:4], hdr.Len)
	NativeEndian().PutUint16(buf[4:6], hdr.Type)
	NativeEndian().PutUint16(buf[6:8], hdr.Flags)
	NativeEndian().PutUint32(buf[8:12], hdr.Seq)
	NativeEndian().PutUint32(buf[12:16], hdr.Pid)
	return syscall.SizeofNlMsghdr

}

//BuildNfAttrMsg -- Build nfattr message
//attrType -- Type of attr being added
//dataLEn -- Length of the attribute
func BuildNfNestedAttrMsg(attrType uint16, dataLen int) *NfAttr {
	return &NfAttr{
		nfaLen:  NfaLength(uint16((dataLen))),
		nfaType: attrType,
	}
}

//BuildNfAttrWithPaddingMsg -- Build nfattrWithPadding message
//attrType -- Type of attr which needs padding
//dataLen -- Length of the attribute
func BuildNfAttrWithPaddingMsg(attrType uint16, dataLen int) *NfAttr {
	return &NfAttr{
		nfaLen:  uint16(dataLen) + SizeofNfAttr,
		nfaType: attrType,
	}
}

//ToWireFormat -- Convert NfqGenMsg to byte slice
func (r *NfqGenMsg) ToWireFormat() []byte {
	buf := make([]byte, SizeofNfGenMsg)
	copy(buf, []byte{r.nfgenFamily})
	copy(buf[1:], []byte{r.version})
	//The queue needs to store in network order
	binary.BigEndian.PutUint16(buf[2:], r.resID)
	return buf
}

//ToWireFormatBuf -- Convert struct to []byte and copy it to passed buffer
func (r *NfqGenMsg) ToWireFormatBuf(buf []byte) int {
	copy(buf, []byte{r.nfgenFamily})
	copy(buf[1:], []byte{r.version})
	//The queue needs to store in network order
	binary.BigEndian.PutUint16(buf[2:], r.resID)
	return int(r.Length())
}

//Length  -- Return length of struct
func (r *NfqGenMsg) Length() uint32 {
	return SizeofNfGenMsg

}

//ToWireFormat -- Convert NfAttr to byte slice
func (r *NfAttr) ToWireFormat() []byte {
	buf := make([]byte, int(SizeofNfAttr))

	NativeEndian().PutUint16(buf, r.nfaLen)
	NativeEndian().PutUint16(buf[2:], r.nfaType)

	return buf
}

//ToWireFormatBuf -- Convert struct to []byte and copy it to passed buffer
func (r *NfAttr) ToWireFormatBuf(buf []byte) int {
	NativeEndian().PutUint16(buf, r.nfaLen)
	NativeEndian().PutUint16(buf[2:], r.nfaType)
	return int(r.Length())
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

//Length -- Return length of struct
func (r *NfAttr) Length() uint32 {
	return uint32(unsafe.Sizeof(NfAttr{}))
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

//NetlinkMessageToStruct -- Convert netlink message byte slice to struct and payload
func NetlinkMessageToStruct(buf []byte) (*syscall.NlMsghdr, []byte, error) {
	if len(buf) <= 15 {
		return nil, []byte{}, fmt.Errorf("Buffer is empty")
	}
	hdr := &syscall.NlMsghdr{}
	hdr.Len = NativeEndian().Uint32(buf)
	hdr.Type = NativeEndian().Uint16(buf[4:])
	hdr.Flags = NativeEndian().Uint16(buf[6:])
	hdr.Seq = NativeEndian().Uint32(buf[8:])
	hdr.Pid = NativeEndian().Uint32(buf[12:])

	return hdr, buf[16:], nil
}

//NetlinkMessageToNfGenStruct -- Convert netlink byte slice to nfqgen msg structure
func NetlinkMessageToNfGenStruct(buf []byte) (*NfqGenMsg, []byte, error) {
	hdr := &NfqGenMsg{}
	hdr.nfgenFamily = buf[0]
	hdr.version = buf[1]
	hdr.resID = binary.BigEndian.Uint16(buf[2:])
	return hdr, buf[4:], nil
}

//NetlinkMessageToNfAttrStruct -- Convert byte slice representing nfattr to nfattr struct slice
func NetlinkMessageToNfAttrStruct(buf []byte, hdr []*NfAttrResponsePayload) ([]*NfAttrResponsePayload, []byte, error) {
	//hdr := make([]*NfAttrResponsePayload, nfqaMax)
	i := 0
	for i < len(buf) {
		if (i + 4) > len(buf) {
			i = i + 4
			break
		}
		nfaLen32 := uint32(NativeEndian().Uint16(buf[i:]))
		nfaType := NativeEndian().Uint16(buf[i+2:])
		i = i + 4

		if i+int(nfaLen32)-4 <= len(buf) {
			if nfaType < uint16(nfqaMax) {
				hdr[nfaType].data = buf[i : i+int(nfaLen32)-4]
			}
		} else {
			return hdr, nil, fmt.Errorf("Bad Attr")
		}
		i = i + int(nfaLen32) - 4
		i = int(NfaAlign32(uint32(i)))
	}

	if i >= len(buf) {
		return hdr, nil, nil
	}
	return hdr, buf[i:], nil
}

//NetlinkErrMessagetoStruct -- parse byte slice and return syscall.NlMsgerr
func NetlinkErrMessagetoStruct(buf []byte) (*syscall.NlMsghdr, *syscall.NlMsgerr) {
	err := &syscall.NlMsgerr{}
	err.Error = int32(NativeEndian().Uint32(buf))
	hdr, _, _ := NetlinkMessageToStruct(buf[4:])
	return hdr, err
}

func NativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// IP2int converts net.IP to uint32
func IP2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

//IP2int converts uint32 to net.IP
func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
