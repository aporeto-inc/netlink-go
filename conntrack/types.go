package conntrack

import (
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

type msgTypes int
type nfqaAttr int
type nfqConfigCommands uint8
type nfqConfigMode int

//NlmFlags -- The flags passed to NlMsgHdr
type NlmFlags uint32

type NfqGenMsg struct {
	NfgenFamily uint8
	Version     uint8
	ResID       uint16
}

type NfValue32 struct {
	Value uint32
}

type NfValue8 struct {
	Value uint8
}

type NfValue16 struct {
	Value uint16
}

type conntrackMarkHdr struct {
	mark uint32
}

type NfAttr struct {
	nfaLen  uint16
	nfaType uint16
}

type NfAttrResponsePayload struct {
	data []byte
}

type SockHandles struct {
	fd         int
	rcvbufSize uint32
	buf        []byte
	lsa        syscall.SockaddrNetlink
}

type Handles struct {
	NfValue32
	NfValue8
	NfValue16
	SockHandles
	sockets map[int]*nl.SocketHandle
}

type ipTuple struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
}

type ConntrackFlow struct {
	FamilyType uint8
	Forward    ipTuple
	Reverse    ipTuple
}
