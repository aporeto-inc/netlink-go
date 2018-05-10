// +build linux !darwin

package sockets

import (
	"fmt"
	"syscall"

	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
)

// NewSocketHandlers creates a handler for sockets
func NewSocketHandlers() SockHandle {

	return &SockHandles{
		Syscalls: syscallwrappers.NewSyscalls(),
	}
}

// Open opens a socket and returns the handler
func (sh *SockHandles) Open(socketType, proto int) (SockHandle, error) {

	fd, err := sh.Syscalls.Socket(syscall.AF_NETLINK, socketType, proto)
	if err != nil {
		return nil, err
	}
	sh.fd = fd
	sh.rcvbufSize = common.NfnlBuffSize
	sh.lsa.Family = syscall.AF_NETLINK

	err = sh.Syscalls.Bind(fd, &sh.lsa)
	if err != nil {
		return nil, err
	}

	return sh, nil
}

// Query sends and waits for netlink response
func (sh *SockHandles) Query(msg *syscall.NetlinkMessage) error {
	err := sh.Send(msg)
	if err != nil {
		return err
	}

	return sh.Recv()
}

// Recv receives the response from netlink
func (sh *SockHandles) Recv() error {
	buf := sh.buf
	n, _, err := sh.Syscalls.Recvfrom(sh.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("Recvfrom returned error %v", err)
	}

	hdr, next, err := common.NetlinkMessageToStruct(buf[:n])
	if err != nil {
		return err
	}

	if hdr.Type == syscall.NLMSG_ERROR {
		_, err := common.NetlinkErrMessagetoStruct(next)
		if err.Error != 0 {
			return fmt.Errorf("Netlink Returned errror %d", err.Error)
		}
	}

	_, _, err = common.NetlinkMessageToNfGenStruct(next)
	if err != nil {
		return fmt.Errorf("NfGen struct format invalid : %v", err)
	}
	return nil
}

// Send sends message to kernel
func (sh *SockHandles) Send(msg *syscall.NetlinkMessage) error {
	buf := make([]byte, syscall.SizeofNlMsghdr+len(msg.Data))
	sh.buf = buf
	common.NativeEndian().PutUint32(buf[0:4], msg.Header.Len)
	common.NativeEndian().PutUint16(buf[4:6], msg.Header.Type)
	common.NativeEndian().PutUint16(buf[6:8], msg.Header.Flags)
	common.NativeEndian().PutUint32(buf[8:12], msg.Header.Seq)
	common.NativeEndian().PutUint32(buf[12:16], msg.Header.Pid)
	copy(buf[16:], msg.Data)
	return sh.Syscalls.Sendto(sh.fd, buf, 0, &sh.lsa)
}

// GetFd gets the fd
func (sh *SockHandles) GetFd() int {
	return sh.fd
}

// GetRcvBufSize gets the rcvbufsize
func (sh *SockHandles) GetRcvBufSize() uint32 {
	return sh.rcvbufSize
}

// GetLocalAddress gets the local address
func (sh *SockHandles) GetLocalAddress() syscall.SockaddrNetlink {
	return sh.lsa
}

// Close closes the socket
func (sh *SockHandles) Close() {
	sh.Syscalls.Close(sh.fd)
}
