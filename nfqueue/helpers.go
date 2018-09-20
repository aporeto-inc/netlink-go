package nfqueue

import (
	"encoding/binary"
	"fmt"

	"unsafe"

	"go.aporeto.io/netlink-go/common"
)

//GetPacketInfo -- Extract packet info from netlink response
//Returns mark,packetid and packet payload
//Mark is uint32
func GetPacketInfo(attr map[int]*common.NfAttrResponsePayload) (int, int, []byte) {
	var packetID, mark int

	if nfqaPacketHdr, ok := attr[int(NfqaPacketHdr)]; ok {
		packetID = int(native.Uint32(nfqaPacketHdr.GetNetlinkData()))
	}
	if nfqaMark, ok := attr[int(NfqaMark)]; ok {
		mark = int(binary.BigEndian.Uint32(nfqaMark.GetNetlinkData()))
	}
	if nfqaPayload, ok := attr[int(NfqaPayload)]; ok {
		fmt.Println(packetID, mark, nfqaPayload.GetNetlinkData())
		return packetID, mark, nfqaPayload.GetNetlinkData()
	}

	return packetID, mark, []byte{}
}

//ToWireFormat -- Convert NfqMsgVerdictHdr to byte slice
func (r *NfqMsgVerdictHdr) ToWireFormat() []byte {
	buf := make([]byte, SizeofNfqMsgVerdictHdr)
	binary.BigEndian.PutUint32(buf, r.verdict)
	native.PutUint32(buf[4:], r.id)
	return buf
}

//ToWireFormatBuf -- Convert structure to []byte and copy the []byte to passed buffer
func (r *NfqMsgVerdictHdr) ToWireFormatBuf(buf []byte) int {
	binary.BigEndian.PutUint32(buf, r.verdict)
	native.PutUint32(buf[4:], r.id)
	return int(r.Length())
}

//Length  -- return length of struct
func (r *NfqMsgVerdictHdr) Length() uint32 {
	return SizeofNfqMsgVerdictHdr
}

//ToWireFormat -- Convert  NfqMsgMarkHdr to byte slice
func (r *NfqMsgMarkHdr) ToWireFormat() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, r.mark)
	return buf
}

//ToWireFormatBuf -- Convert struct to []byte and copy it passed buf
func (r *NfqMsgMarkHdr) ToWireFormatBuf(buf []byte) int {
	binary.BigEndian.PutUint32(buf, r.mark)
	return int(r.Length())
}

//Length -- Return length of struct
func (r *NfqMsgMarkHdr) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgMarkHdr{}))
}

//ToWireFormat -- Convert NfqMsgConfigCommand to byte slice
func (r *NfqMsgConfigCommand) ToWireFormat() []byte {

	buf := make([]byte, SizeofMsgConfigCommand)
	buf[0] = byte(r.Command)
	buf[1] = r._pad
	binary.BigEndian.PutUint16(buf[2:], r.pf)
	return buf
}

//Length -- Return length of struct
func (r *NfqMsgConfigCommand) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgConfigCommand{}))
}

//ToWireFormat -- Convert NfqMsgConfigParams to byte slice
func (r *NfqMsgConfigParams) ToWireFormat() []byte {
	buf := make([]byte, SizeOfNfqMsgConfigParams)
	binary.BigEndian.PutUint32(buf, r.copyRange)
	buf[4] = byte(r.copyMode)
	return buf
}

//Length -- Return length of struct
func (r *NfqMsgConfigParams) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgConfigParams{}))
}

//ToWireFormat -- Convert NfqMsgConfigQueueLen to byte slice
func (r *NfqMsgConfigQueueLen) ToWireFormat() []byte {
	buf := make([]byte, SizeOfNfqMsgConfigQueueLen)
	binary.BigEndian.PutUint32(buf, r.queueLen)
	return buf
}

//Length -- Return length of struct
func (r *NfqMsgConfigQueueLen) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgConfigQueueLen{}))
}

//ParseNfAttrResponse -- Parse the Nfattrresponse payload
// func ParseNfAttrResponse(element *NfAttrResponsePayload) (uint16, uint16, []byte) {
// 	return element.attr.nfaLen, element.attr.nfaType, element.data
// }

//QueueID  return queueid
func QueueID(msg *common.NfqGenMsg) uint16 {
	return msg.GetNfgenResID()
}
