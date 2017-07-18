package conntrack

import (
	"syscall"

	"github.com/vishvananda/netlink"
)

// Conntrack interface has Conntrack manipulations (get/set/flush)
type Conntrack interface {
	// ConntrackTableList is used to retrieve the conntrack entries from kernel
	ConntrackTableList(table netlink.ConntrackTableType) ([]*ConntrackFlow, error)
	// ConntrackTableFlush is used to flush the conntrack entries
	ConntrackTableFlush(table netlink.ConntrackTableType) error
	// ConntrackTableUpdate is used to update conntrack attributes in the kernel. (Currently supports only mark)
	ConntrackTableUpdate(table netlink.ConntrackTableType, flows []*ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) (int, error)
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
