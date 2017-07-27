// +build linux !darwin

package conntrack

import (
	"syscall"

	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
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
