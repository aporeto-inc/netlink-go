// +build linux !darwin

package nflog

import "syscall"

// NFLog -- This is the interface which has all the necessary functions to read logs from kernel
// This is needed if we don't want to call BindAndListenForLogs()
// Useful for testing and debugging
type NFLog interface {
	NFlogOpen() (SockHandle, error)
	NFlogUnbind() error
	NFlogBind() error
	NFlogBindGroup(group []uint16, data func(packet *NfPacket, callback interface{}), errorCallback func(err error)) error
	NFlogSetMode(groups []uint16, copyrange uint32) error
	ReadLogs()
	NFlogClose()
	parseLog(buf []byte) error
	parsePacket(buffer []byte) error
}

// SockHandle Opaque interface with unexported functions
type SockHandle interface {
	query(msg *syscall.NetlinkMessage) error
	recv() error
	send(msg *syscall.NetlinkMessage) error
	getFd() int
	getRcvBufSize() uint32
	getLocalAddress() syscall.SockaddrNetlink
	close()
}
