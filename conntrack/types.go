package conntrack

import (
	"net"
	"syscall"
)

//NfqGenMsg -- the nfgen msg structure
//nfGenFamily -- Family
//version -- netlink version
//resId -- queueNum in big endian format
type NfGenMsg struct {
	NfgenFamily uint8
	Version     uint8
	ResID       uint16
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

//NfAttr -- attr struct header
//nfaLen -- sizeof struct + payload
//nfaType --  nfaType
type NfAttr struct {
	nfaLen  uint16
	nfaType uint16
}

//NfAttrResponsePayload -- Response of attr from netlink
//data -- payload for response
type NfAttrResponsePayload struct {
	data []byte
}

//NfqSockHandle -- Sock handle of netlink socket
//fd -- fd of socket
//rcvbufSize -- rcv buffer Size
//lsa -- local address
type SockHandles struct {
	fd         int
	rcvbufSize uint32
	buf        []byte
	lsa        syscall.SockaddrNetlink
}

//Handles -- Handle for Conntrack table manipulations (get/set)
//SockHandles --  Sock handle of netlink socket
type Handles struct {
	SockHandles
}

// ipTuple -- Conntrack flow structure for ipTuple
type ipTuple struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
}

//ConntrackFlow -- ConntrackFlow for parsing
//http://git.netfilter.org/libnetfilter_conntrack/tree/include/internal/object.h
type ConntrackFlow struct {
	FamilyType uint8
	Forward    ipTuple
	Reverse    ipTuple
	Mark       uint32
}
