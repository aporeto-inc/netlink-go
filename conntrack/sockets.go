package conntrack

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

func (sh *SockHandles) open() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	sh.fd = fd
	sh.rcvbufSize = NfnlBuffSize
	sh.lsa.Family = syscall.AF_NETLINK

	err = syscall.Bind(fd, &sh.lsa)
	if err != nil {
		return err
	}
	return nil
}

func (sh *SockHandles) query(msg *syscall.NetlinkMessage) error {
	err := sh.send(msg)
	if err != nil {
		return err
	}
	return sh.recv()
}

func (sh *SockHandles) recv() error {
	buf := sh.buf
	n, _, err := syscall.Recvfrom(sh.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("Recvfrom returned error %v", err)
	}

	hdr, next, err := NetlinkMessageToStruct(buf[:n])
	if err != nil {
		return err
	}

	if hdr.Type == syscall.NLMSG_ERROR {
		_, err := NetlinkErrMessagetoStruct(next)
		if err.Error != 0 {
			return fmt.Errorf("Netlink Returned errror %d", err.Error)
		}
	}

	_, _, err = NetlinkMessageToNfGenStruct(next)
	if err != nil {
		return fmt.Errorf("NfGen struct format invalid : %v", err)
	}
	return nil
}

func (sh *SockHandles) send(msg *syscall.NetlinkMessage) error {
	buf := make([]byte, syscall.SizeofNlMsghdr+len(msg.Data))
	sh.buf = buf
	NativeEndian().PutUint32(buf[0:4], msg.Header.Len)
	NativeEndian().PutUint16(buf[4:6], msg.Header.Type)
	NativeEndian().PutUint16(buf[6:8], msg.Header.Flags)
	NativeEndian().PutUint32(buf[8:12], msg.Header.Seq)
	NativeEndian().PutUint32(buf[12:16], msg.Header.Pid)
	copy(buf[16:], msg.Data)
	return syscall.Sendto(sh.fd, buf, 0, &sh.lsa)
}

func (sh *SockHandles) getFd() int {
	return sh.fd
}

func (sh *SockHandles) getRcvBufSize() uint32 {
	return sh.rcvbufSize
}

func (sh *SockHandles) getLocalAddress() syscall.SockaddrNetlink {
	return sh.lsa
}

func (sh *SockHandles) close() {
	syscall.Close(sh.fd)
}

func NativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
