package conntrack

import (
	"syscall"

	"github.com/vishvananda/netlink"
)

type Conntrack interface {
	ConntrackTableList(table netlink.ConntrackTableType, family netlink.InetFamily) ([]*netlink.ConntrackFlow, error)
	ConntrackTableUpdate()
	ConntrackTableFlush(table netlink.ConntrackTableType) error
	ConntrackTableDelete()
}

//SockHandle Opaque interface with unexported functions
type SockHandle interface {
	query(msg *syscall.NetlinkMessage) error
	recv() error
	send(msg *syscall.NetlinkMessage) error
	getFd() int
	getRcvBufSize() uint32
	getLocalAddress() syscall.SockaddrNetlink
	close()
}
