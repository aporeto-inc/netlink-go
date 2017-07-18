package conntrack

import (
	"fmt"
	"syscall"

	"github.com/aporeto-inc/netlink-go/commons"
)

func (h *Handles) open() (SockHandle, error) {
	sh := &SockHandles{Syscalls: h.Syscalls}
	fd, err := h.Syscalls.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	sh.fd = fd
	sh.rcvbufSize = common.NfnlBuffSize
	sh.lsa.Family = syscall.AF_NETLINK

	err = h.Syscalls.Bind(fd, &sh.lsa)
	if err != nil {
		return nil, err
	}

	return sh, nil
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

func (sh *SockHandles) send(msg *syscall.NetlinkMessage) error {
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
	sh.Syscalls.Close(sh.fd)
}
