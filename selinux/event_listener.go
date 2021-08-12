package selinux

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"go.aporeto.io/netlink-go/common"
	"go.aporeto.io/netlink-go/common/syscallwrappers"
)

// EventListener holds the state for listening to SELinux event notifications
type EventListener struct {
	syswrap          syscallwrappers.Syscalls
	fd               int
	sockaddr         syscall.SockaddrNetlink
	cancel           context.CancelFunc
	setenforceMsgCh  chan common.SelnlMsgSetenforce
	policyloadMsgCh  chan common.SelnlMsgPolicyload
	errorCounter     uint
	errorCounterLock sync.RWMutex
}

// NewEventListener establishes state for running an inet_diag_req_v2 - including creating a socket.
// NOTE: you **must** call `Close` on the returned EventListener in order to release the fd for the socket.
// Do not use the EventListener again once you called Close.
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
		setenforceMsgCh: make(chan common.SelnlMsgSetenforce, 10),
		policyloadMsgCh: make(chan common.SelnlMsgPolicyload, 10),
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
	if a.policyloadMsgCh != nil {
		close(a.policyloadMsgCh)
		a.policyloadMsgCh = nil
	}
	if a.setenforceMsgCh != nil {
		close(a.setenforceMsgCh)
		a.setenforceMsgCh = nil
	}
}

// PolicyLoadMsgCh receives SELNL_MSG_POLICYLOAD messages
func (a *EventListener) PolicyLoadMsgCh() <-chan common.SelnlMsgPolicyload {
	return a.policyloadMsgCh
}

// SetenforceMsgCh receives SELNL_MSG_SETENFORCE messages
func (a *EventListener) SetenforceMsgCh() <-chan common.SelnlMsgSetenforce {
	return a.setenforceMsgCh
}

func (a *EventListener) ErrorCount() uint {
	a.errorCounterLock.RLock()
	defer a.errorCounterLock.RUnlock()
	return a.errorCounter
}

func (a *EventListener) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := a.receive()
			if err != nil {
				a.errorCounterLock.Lock()
				a.errorCounter++
				a.errorCounterLock.Unlock()
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
		if a.setenforceMsgCh != nil {
			select {
			case a.setenforceMsgCh <- *msg:
			default:
				return fmt.Errorf("failed to send setenforce message")
			}
		}
	case common.SELNL_MSG_POLICYLOAD:
		buf := make([]byte, len(payload))
		copy(buf, payload)
		msg := (*common.SelnlMsgPolicyload)(unsafe.Pointer(&buf[0]))
		if a.policyloadMsgCh != nil {
			select {
			case a.policyloadMsgCh <- *msg:
			default:
				return fmt.Errorf("failed to send policyload message")
			}
		}
	default:
		return fmt.Errorf("unexpected netlink message type 0x%x", hdr.Type)
	}

	return nil
}
