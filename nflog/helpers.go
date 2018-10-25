// +build linux !darwin

package nflog

import (
	"encoding/binary"
	"unsafe"
)

//Length -- Return length of struct
func (r *NflMsgConfigCommand) Length() uint32 {
	return uint32(unsafe.Sizeof(NflMsgConfigCommand{}))
}

//Length -- Return length of struct
func (r *NflMsgConfigMode) Length() uint32 {
	return uint32(unsafe.Sizeof(NflMsgConfigMode{}))
}

//ToWireFormat -- Convert NflMsgConfigCommand to byte slice
func (r *NflMsgConfigCommand) ToWireFormat() []byte {

	buf := make([]byte, SizeofMsgConfigCommand)
	buf[0] = r.command

	return buf
}

//ToWireFormat -- Convert NflMsgConfigMode to byte slice
func (r *NflMsgConfigMode) ToWireFormat() []byte {

	buf := make([]byte, SizeofMsgConfigMode)
	binary.BigEndian.PutUint32(buf, r.copyRange)
	buf[4] = r.copyMode

	return buf
}

//NfaAlign16 -- To align payload
func NfaAlign16(v uint16) uint16 {
	return (v + 3) & 0xFFFC
}
