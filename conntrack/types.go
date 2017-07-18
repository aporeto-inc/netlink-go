package conntrack

import (
	"net"
	"syscall"

	"github.com/aporeto-inc/netlink-go/commons/syscallwrappers"
)

//SockHandle -- Sock handle of netlink socket
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

//Handles -- Handle for Conntrack table manipulations (get/set)
//SockHandles --  Sock handle of netlink socket
type Handles struct {
	Syscalls syscallwrappers.Syscalls
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
