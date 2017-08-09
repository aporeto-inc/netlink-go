// +build linux !darwin
//nolint
package common

import (
	"syscall"

	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
)

//Types for various enums needed by the nfqueue subsys in linux
type msgTypes int
type nfqaAttr int
type nfqConfigCommands uint8

//NlmFlags -- The flags passed to NlMsgHdr
type NlmFlags uint32

//We will write a method to serialize these messages into a byte slice. So so need to be packed

//NfqMsgPacketHdr PacketHdr
//packetID --  unique ID of packet in queue
//hwProtocol -- hw protocol (network order)
//hook -- netfilter hook
//lint complains -- uncomment when needed
// type NfqMsgPacketHdr struct {
// 	packetID   uint32
// 	hwProtocol uint16
// 	hook       uint8
// }

//Not needed for our usecase

//NfqMsgPacketHwAddress -- HwAddress
//lint complains -- uncomment when needed
// type NfqMsgPacketHwAddress struct { //nolint: structcheck
// 	hwAddrLen uint16
// 	_pad      uint16 //nolint
// 	hwaddr    [8]uint8
// }

//NfqMsgVerdictHdr -- Verdict Hdr struct
//verdict -- accept/drop
//id -- packetid
type NfqMsgVerdictHdr struct {
	verdict uint32
	id      uint32
}

//NfqMsgMarkHdr -- Mark Payload
//mark -- markval
type NfqMsgMarkHdr struct {
	mark uint32
}

//NfqMsgVerdictPayload -- unused
// type NfqMsgVerdictPayload struct { //nolint: structcheck
// 	iovecs []syscall.Iovec
// }

//NfqMsgConfigCommand -- config command
//Command -- the config command
//pf -- family
type NfqMsgConfigCommand struct {
	Command nfqConfigCommands
	_pad    uint8 //nolint
	pf      uint16
}

//NfqMsgConfigParams -- Config params
//copyRange -- Range of bytes to copy
//copyMode -- copyMode meta/none/packet
type NfqMsgConfigParams struct {
	copyRange uint32
	copyMode  uint8
}

//NfqMsgConfigQueueLen -- Queue length
//queueLen -- The length of queue
type NfqMsgConfigQueueLen struct {
	queueLen uint32
}

//SockHandles -- Sock handle of netlink socket
//fd -- fd of socket
//rcvbufSize -- rcv buffer Size
//lsa -- local address
type SockHandles struct {
	Syscalls   syscallwrappers.Syscalls
	fd         int
	rcvbufSize uint32
	buf        []byte
	lsa        syscall.SockaddrNetlink
}

//NfqGenMsg -- the nfgen msg structure
//nfGenFamily -- Family
//version -- netlink version
//resId -- queueNum in big endian format
type NfqGenMsg struct {
	nfgenFamily uint8
	version     uint8
	resID       uint16
}

//NfAttr -- attr struct header
//nfaLen -- sizeof struct + payload
//nfaType --  nfaType
type NfAttr struct {
	nfaLen  uint16
	nfaType uint16
}

//NfValue8 -- uint8 type attribute structure
//value -- the value for a uint8 type attribute
type NfValue8 struct {
	value uint8
}

//NfValue16 -- uint16 type attribute structure
//value -- the value for a uint16 type attribute
type NfValue16 struct {
	value uint16
}

//NfValue32 -- uint32 type attribute structure
//value -- the value for a uint32 type attribute
type NfValue32 struct {
	value uint32
}

//NfAttrResponsePayload -- Response of attr from netlink
//attr -- NfAttr
//data -- payload for response
type NfAttrResponsePayload struct {
	//attr *NfAttr
	data []byte
}

// NfAttrSlice is an array of attributes
type NfAttrSlice [nfqaMax]NfAttrResponsePayload

//NfqNetlinkRequest -- netlink request to send
//NlMsgHdr fields
//serialized data of structure passed to netlink
type NfqNetlinkRequest struct {
	syscall.NlMsghdr
	Data []byte
}
