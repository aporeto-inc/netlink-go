package conntrack

import (
	"fmt"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

// Empty handle used by the netlink package methods
var pkgHandle = &Handles{}

// SupportsNetlinkFamily reports whether the passed netlink family is supported by this Handle
func (h *Handles) SupportsNetlinkFamily(nlFamily int) bool {
	_, ok := h.sockets[nlFamily]
	return ok
}

// NewHandle returns a netlink handle on the current network namespace.
// Caller may specify the netlink families the handle should support.
// If no families are specified, all the families the netlink package
// supports will be automatically added.
func NewHandle(nlFamilies ...int) (*Handles, error) {
	return newHandle(netns.None(), netns.None(), nlFamilies...)
}

// SetSocketTimeout sets the send and receive timeout for each socket in the
// netlink handle. Although the socket timeout has granularity of one
// microsecond, the effective granularity is floored by the kernel timer tick,
// which default value is four milliseconds.
func (h *Handles) SetSocketTimeout(to time.Duration) error {
	if to < time.Microsecond {
		return fmt.Errorf("invalid timeout, minimul value is %s", time.Microsecond)
	}
	tv := syscall.NsecToTimeval(to.Nanoseconds())
	for _, sh := range h.sockets {
		fd := sh.Socket.GetFd()
		err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewHandle returns a netlink handle on the network namespace
// specified by ns. If ns=netns.None(), current network namespace
// will be assumed
func NewHandleAt(ns netns.NsHandle, nlFamilies ...int) (*Handles, error) {
	return newHandle(ns, netns.None(), nlFamilies...)
}

// NewHandleAtFrom works as NewHandle but allows client to specify the
// new and the origin netns Handle.
func NewHandleAtFrom(newNs, curNs netns.NsHandle) (*Handles, error) {
	return newHandle(newNs, curNs)
}

func newHandle(newNs, curNs netns.NsHandle, nlFamilies ...int) (*Handles, error) {
	h := &Handles{sockets: map[int]*nl.SocketHandle{}}
	fams := nl.SupportedNlFamilies
	if len(nlFamilies) != 0 {
		fams = nlFamilies
	}
	for _, f := range fams {
		s, err := nl.GetNetlinkSocketAt(newNs, curNs, f)
		if err != nil {
			return nil, err
		}
		h.sockets[f] = &nl.SocketHandle{Socket: s}
	}
	return h, nil
}

// Delete releases the resources allocated to this handle
func (h *Handles) Delete() {
	for _, sh := range h.sockets {
		sh.Close()
	}
	h.sockets = nil
}

func (h *Handles) newNetlinkRequest(proto, flags int) *nl.NetlinkRequest {
	// Do this so that package API still use nl package variable nextSeqNr
	if h.sockets == nil {
		return nl.NewNetlinkRequest(proto, flags)
	}
	return &nl.NetlinkRequest{
		NlMsghdr: syscall.NlMsghdr{
			Len:   uint32(syscall.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
		},
		Sockets: h.sockets,
	}
}
