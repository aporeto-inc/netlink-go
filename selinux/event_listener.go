package selinux

import (
	"context"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"go.aporeto.io/netlink-go/common"
	"go.aporeto.io/netlink-go/common/syscallwrappers"
)

var native binary.ByteOrder

func init() {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		native = binary.BigEndian
	} else {
		native = binary.LittleEndian
	}
}

// InetDiag holds the state for running an inet_diag_req_v2
type EventListener struct {
	syswrap  syscallwrappers.Syscalls
	fd       int
	sockaddr syscall.SockaddrNetlink
	cancel   context.CancelFunc
}

// NewInetDiag establishes state for running an inet_diag_req_v2 - including creating a socket.
// NOTE: you **must** call `Close` on the returned InetDiag in order to release the fd for the socket.
func NewEventListener(ctx context.Context) (*EventListener, error) {
	syswrap := syscallwrappers.NewSyscalls()
	fd, err := syswrap.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_SELINUX)
	if err != nil {
		return nil, err
	}
	avcListener := &EventListener{
		syswrap: syswrap,
		fd:      fd,
		sockaddr: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
			Pid:    0,
			Groups: common.SELNL_GRP_ALL,
		},
	}

	// I don't think we need those, but keeping it here for reference
	/*
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		if (!blocking && fcntl(fd, F_SETFL, O_NONBLOCK)) {
			close(fd);
			rc = -1;
			goto out;
		}
	*/

	// taken this from nfqueue, not sure if this is needed
	err = avcListener.syswrap.Bind(fd, &avcListener.sockaddr)
	if err != nil {
		return nil, err
	}
	opt := 1
	sockbuf := 500 * int(common.NfnlBuffSize)
	avcListener.syswrap.SetsockoptInt(fd, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, opt)
	avcListener.syswrap.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, sockbuf)
	avcListener.syswrap.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, sockbuf)
	//This is a hunch it looks like the kernel does not support this flag for netlink socket
	//Will need to try if this is honored from a path i did not see af_netlink.c
	lingerconf := &syscall.Linger{
		Onoff:  1,
		Linger: 0,
	}
	syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER, lingerconf)

	receiveCtx, cancel := context.WithCancel(ctx)
	avcListener.cancel = cancel
	go avcListener.loop(receiveCtx)

	return avcListener, nil
}

// Close closes the fd for the socket
func (a *EventListener) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	a.syswrap.Close(a.fd)
}

func (a *EventListener) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := a.receive()
			if err != nil {
				fmt.Printf("ERROR: error from netlink recvfrom: %s", err)
				continue
			}

		}
	}
}

func (a *EventListener) receive() error {
	var err error
	buf := make([]byte, common.NfnlBuffSize)
	n, _, err := a.syswrap.Recvfrom(a.fd, buf, syscall.MSG_WAITALL)
	if err != nil {
		return fmt.Errorf("unable to read from socket %v", err)
	}
	hdr, payload, err := common.NetlinkMessageToStruct(buf[:n])

	if hdr.Type == common.NlMsgError {
		_, err := common.NetlinkErrMessagetoStruct(payload)
		if err.Error != 0 {
			return fmt.Errorf("netlink returned errror %d", err.Error)
		}
	}
	if err != nil {
		//fmt.Printf("HEader Type %v,Header Length %v Flags %x\n", hdr.Type, hdr.Len, hdr.Flags)
		return fmt.Errorf("netlink message format invalid : %v", err)
	}

	switch hdr.Type {
	case common.SELNL_MSG_SETENFORCE:
		buf := make([]byte, len(payload))
		copy(buf, payload)
		msg := (*common.SelnlMsgSetenforce)(unsafe.Pointer(&buf[0]))
		fmt.Printf("received SELNL_MSG_SETENFORCE: %#v\n", msg)
	case common.SELNL_MSG_POLICYLOAD:
		buf := make([]byte, len(payload))
		copy(buf, payload)
		msg := (*common.SelnlMsgPolicyload)(unsafe.Pointer(&buf[0]))
		fmt.Printf("received SELNL_MSG_POLICYLOAD: %#v\n", msg)
	default:
		return fmt.Errorf("unexpected netlink message type 0x%x", hdr.Type)
	}

	return nil
}
