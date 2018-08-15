package nfqueue

import (
	"syscall"

	"go.aporeto.io/netlink-go/common/syscallwrappers"
)

//Types for various enums needed by the nfqueue subsys in linux
type nfqaAttr int
type nfqConfigCommands uint8
type nfqConfigMode int

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

//NfqSockHandle -- Sock handle of netlink socket
//fd -- fd of socket
//rcvbufSize -- rcv buffer Size
//lsa -- local address
type NfqSockHandle struct {
	Syscalls   syscallwrappers.Syscalls
	fd         int
	rcvbufSize uint32
	buf        []byte
	lsa        syscall.SockaddrNetlink
}
