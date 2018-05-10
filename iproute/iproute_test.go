package iproute

import (
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/aporeto-inc/netlink-go/common/sockets"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func sampleTestRule() *Rule {
	srcNet := &net.IPNet{IP: net.IPv4(172, 16, 0, 1), Mask: net.CIDRMask(16, 32)}
	dstNet := &net.IPNet{IP: net.IPv4(172, 16, 1, 1), Mask: net.CIDRMask(24, 32)}

	rule := &Rule{}
	rule.Table = unix.RT_TABLE_MAIN
	rule.Src = srcNet
	rule.Dst = dstNet
	rule.Priority = 5
	rule.OifName = "lo"
	rule.IifName = "lo"
	rule.Invert = true

	return rule
}

func sampleTestRoute() *Route {

	route := &Route{}
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	src := net.IPv4(127, 1, 1, 1)

	route.Src = src
	route.Dst = dst

	return route
}

func TestAddRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new iproute handle", t, func() {
		newIPRoute, err := NewIPRouteHandle()
		So(newIPRoute, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("When I try to add a rule ", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(25, nil, nil)
			mockSyscalls.EXPECT().Close(5).Times(1).Return(nil)

			rule := sampleTestRule()
			err := newIPRoute.AddRule(rule)

			Convey("Then I should not see any error", func() {
				So(err, ShouldBeNil)
			})
		})
		Convey("When I try to add a rule but the recv buffer is empty", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(0, nil, nil)

			route := sampleTestRoute()
			err := newIPRoute.DeleteRoute(route)

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, fmt.Errorf("Buffer is empty"))
			})
		})
	})
}

func TestDeleteRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new iproute handle", t, func() {
		newIPRoute, err := NewIPRouteHandle()
		So(newIPRoute, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("When I try to delete a rule ", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(25, nil, nil)
			mockSyscalls.EXPECT().Close(5).Times(1).Return(nil)

			rule := sampleTestRule()
			err := newIPRoute.DeleteRule(rule)

			Convey("Then I should not see any error", func() {
				So(err, ShouldBeNil)
			})
		})
		Convey("When I try to delete a rule but the recv buffer is empty", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(0, nil, nil)

			route := sampleTestRoute()
			err := newIPRoute.DeleteRoute(route)

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, fmt.Errorf("Buffer is empty"))
			})
		})
	})
}

func TestAddRoute(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new iproute handle", t, func() {
		newIPRoute, err := NewIPRouteHandle()
		So(newIPRoute, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("When I try to add a route ", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(25, nil, nil)
			mockSyscalls.EXPECT().Close(5).Times(1).Return(nil)

			route := sampleTestRoute()
			err := newIPRoute.AddRoute(route)

			Convey("Then I should not see any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to add a route but the recv buffer is empty", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(0, nil, nil)

			route := sampleTestRoute()
			err := newIPRoute.AddRoute(route)

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, fmt.Errorf("Buffer is empty"))
			})
		})
	})
}

func TestDeleteRoute(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new iproute handle", t, func() {
		newIPRoute, err := NewIPRouteHandle()
		So(newIPRoute, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("When I try to delete a route ", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(25, nil, nil)
			mockSyscalls.EXPECT().Close(5).Times(1).Return(nil)

			route := sampleTestRoute()
			err := newIPRoute.DeleteRoute(route)

			Convey("Then I should not see any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I try to delete a route but the recv buffer is empty", func() {
			sockets := &sockets.SockHandles{
				Syscalls: mockSyscalls,
			}
			newIPRoute.(*Iproute).socketHandlers = sockets

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().Recvfrom(5, gomock.Any(), gomock.Any()).Times(1).Return(0, nil, nil)

			route := sampleTestRoute()
			err := newIPRoute.DeleteRoute(route)

			Convey("Then I should get error", func() {
				So(err, ShouldResemble, fmt.Errorf("Buffer is empty"))
			})
		})
	})
}
