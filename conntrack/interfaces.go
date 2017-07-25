package conntrack

import (
	"syscall"

	"github.com/vishvananda/netlink"
)

// Conntrack interface has Conntrack manipulations (get/set/flush)
type Conntrack interface {
	// ConntrackTableList is used to retrieve the conntrack entries from kernel
	ConntrackTableList(table netlink.ConntrackTableType) ([]*netlink.ConntrackFlow, error)
	// ConntrackTableFlush is used to flush the conntrack entries
	ConntrackTableFlush(table netlink.ConntrackTableType) error
	// ConntrackTableUpdateMarkForAvailableFlow will update mark only if the flow is present
	ConntrackTableUpdateMarkForAvailableFlow(flows []*netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) (int, error)
	// ConntrackTableUpdateMark is used to update conntrack mark attribute in the kernel
	ConntrackTableUpdateMark(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error
	// ConntrackTableUpdateLabel is used to update conntrack label attribute in the kernel
	ConntrackTableUpdateLabel(table netlink.ConntrackTableType, flows []*netlink.ConntrackFlow, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newlabels uint32) (int, error)
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
