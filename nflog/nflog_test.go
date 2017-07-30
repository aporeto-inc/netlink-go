package nflog

import (
	"syscall"
	"testing"

	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNFlogOpen(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nflog handle", t, func() {
		newNflog := NewNFLog()
		So(newNflog, ShouldNotBeNil)

		Convey("When I try to open a socket ", func() {

			newNflog.(*NfLog).Syscalls = mockSyscalls

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)

			nfSockHandle, err := newNflog.NFlogOpen()

			Convey("Then I should not see any error", func() {
				So(nfSockHandle, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestNFlogUnbind(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nflog handle", t, func() {
		newNflog := NewNFLog()
		So(newNflog, ShouldNotBeNil)

		Convey("When I try to Unbind a socket ", func() {

			newNflog.(*NfLog).Syscalls = mockSyscalls
			buf := []byte{0x1C, 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)

				nfSockHandle, err := newNflog.NFlogOpen()

				Convey("Then I should not get any error", func() {
					So(nfSockHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket, then I expect the buffer to be populated", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1)
					mockSyscalls.EXPECT().Recvfrom(5, buf, 0).Times(1).Return(15, nil, nil)
					newNflog.NFlogUnbind()
				})
			})
		})
	})
}

func TestNFlogBind(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nflog handle", t, func() {
		newNflog := NewNFLog()
		So(newNflog, ShouldNotBeNil)

		Convey("When I try to bind a socket ", func() {

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)

			newNflog.(*NfLog).Syscalls = mockSyscalls
			unbindbuf := []byte{0x1C, 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00}
			bindbuf := []byte{0x1C, 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				nfSockHandle, err := newNflog.NFlogOpen()

				Convey("Then I should not get any error", func() {
					So(nfSockHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket, then I should the buffer to be populated", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1)
					mockSyscalls.EXPECT().Recvfrom(5, unbindbuf, 0).Times(1).Return(15, nil, nil)
					newNflog.NFlogUnbind()

					Convey("When I try to bind a socket, then I should the buffer to be populated", func() {
						mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).Times(1)
						mockSyscalls.EXPECT().Recvfrom(5, bindbuf, 0).Times(1).Return(15, nil, nil)
						newNflog.NFlogBind()
					})
				})
			})
		})
	})
}
