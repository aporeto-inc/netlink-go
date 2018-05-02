package sockets

import (
	"syscall"

	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
)

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
