// +build linux !darwin

package sockets

import "syscall"

// SockHandle Opaque interface with unexported functions
type SockHandle interface {
	Open(socketType, proto int) (SockHandle, error)
	Query(msg *syscall.NetlinkMessage) error
	Recv() error
	Send(msg *syscall.NetlinkMessage) error
	GetFd() int
	GetRcvBufSize() uint32
	GetLocalAddress() syscall.SockaddrNetlink
	Close()
}
