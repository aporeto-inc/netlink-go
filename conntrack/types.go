// +build linux !darwin

package conntrack

import (
	"github.com/aporeto-inc/netlink-go/common/sockets"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
)

//Handles -- Handle for Conntrack table manipulations (get/set)
//SockHandles --  Sock handle of netlink socket
type Handles struct {
	Syscalls       syscallwrappers.Syscalls
	socketHandlers sockets.SockHandles
}
