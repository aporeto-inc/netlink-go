package iproute

import (
	"net"

	"github.com/aporeto-inc/netlink-go/common/sockets"
)

// Iproute is the wrapper around netlinkHandle
type Iproute struct {
	socketHandlers sockets.SockHandle
}

// Rule represents a netlink rule.
type Rule struct {
	Priority          int
	Family            int
	Table             int
	Mark              int
	Mask              int
	TunID             uint
	Goto              int
	Src               *net.IPNet
	Dst               *net.IPNet
	Flow              int
	IifName           string
	OifName           string
	SuppressIfgroup   int
	SuppressPrefixlen int
	Invert            bool
}

// Scope is an enum representing a route scope.
type Scope uint8

type NextHopFlag int

type Destination interface {
	Family() int
	Decode([]byte) error
	Encode() ([]byte, error)
	String() string
	Equal(Destination) bool
}

type Encap interface {
	Type() int
	Decode([]byte) error
	Encode() ([]byte, error)
	String() string
	Equal(Encap) bool
}

// Route represents a netlink route.
type Route struct {
	LinkIndex  int
	ILinkIndex int
	Scope      Scope
	Dst        *net.IPNet
	Src        net.IP
	Gw         net.IP
	MultiPath  []*NexthopInfo
	Protocol   int
	Priority   int
	Table      int
	Type       int
	Tos        int
	Flags      int
	MPLSDst    *int
	NewDst     Destination
	Encap      Encap
	MTU        int
	AdvMSS     int
}

type flagString struct {
	f NextHopFlag
	s string
}

// RouteUpdate is sent when a route changes - type is RTM_NEWROUTE or RTM_DELROUTE
type RouteUpdate struct {
	Type uint16
	Route
}

type NexthopInfo struct {
	LinkIndex int
	Hops      int
	Gw        net.IP
	Flags     int
	NewDst    Destination
	Encap     Encap
}

type nexthopInfoSlice []*NexthopInfo
