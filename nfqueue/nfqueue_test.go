package nfqueue

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"go.aporeto.io/netlink-go/common"
	"go.aporeto.io/netlink-go/common/syscallwrappers"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

var isCalled int

func passVerdict(buf *NFPacket, data interface{}) {
	if isCalled < 4 {
		buf.QueueHandle.SetVerdict2(uint32(buf.QueueHandle.QueueNum), 1, 11, uint32(len(buf.Buffer)), uint32(buf.ID), buf.Buffer)
		isCalled++
	}
	os.Exit(0)
}

func errorCallback(err error, data interface{}) {
}

func TestNfqOpen(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to open a socket ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)
			mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
			mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
			mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
			mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
			nfqHandle, err := newNFQ.NfqOpen()

			Convey("Then I should not see any error", func() {
				So(nfqHandle, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestUnbindPf(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to Unbind a socket ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()

				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)
					})
				})
			})
		})
	})
}

func TestBindPf(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to bind a socket ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)
			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()

				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)
					})

					Convey("When I try to bind a socket", func() {
						err := newNFQ.BindPf()
						Convey("Then I should not get any error", func() {
							So(err, ShouldBeNil)
						})
					})
				})
			})
		})
	})
}

func TestCreateQueue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to bind a socket ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)
			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()
				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)
					})

					Convey("When I try to bind a socket", func() {
						err := newNFQ.BindPf()
						Convey("Then I should not get any error", func() {
							So(err, ShouldBeNil)
						})

						Convey("When I try to create a queue", func() {
							err := newNFQ.CreateQueue(10, passVerdict, errorCallback, nil)
							Convey("Then I should not get any error", func() {
								So(err, ShouldBeNil)
							})
						})
					})
				})
			})
		})
	})
}

func TestNfqSetMode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to set mode for queue ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)
			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()
				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)
					})

					Convey("When I try to bind a socket", func() {
						err := newNFQ.BindPf()
						Convey("Then I should not get any error", func() {
							So(err, ShouldBeNil)
						})

						Convey("When I try to create a queue", func() {
							err := newNFQ.CreateQueue(10, passVerdict, errorCallback, nil)
							Convey("Then I should not get any error", func() {
								So(err, ShouldBeNil)

							})

							Convey("When I try to set a mode queue", func() {
								err := newNFQ.NfqSetMode(NfqnlCopyPacket, 0xffff)
								Convey("Then I should not get any error", func() {
									So(err, ShouldBeNil)
								})
							})
						})
					})
				})
			})
		})
	})
}

func TestNfqSetQueueMaxLen(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to set mode for queue ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)
			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()
				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)

					})

					Convey("When I try to bind a socket", func() {
						err := newNFQ.BindPf()
						Convey("Then I should not get any error", func() {
							So(err, ShouldBeNil)
						})

						Convey("When I try to create a queue", func() {
							err := newNFQ.CreateQueue(10, passVerdict, errorCallback, nil)
							Convey("Then I should not get any error", func() {
								So(err, ShouldBeNil)
							})

							Convey("When I try to set a mode queue", func() {
								err := newNFQ.NfqSetMode(NfqnlCopyPacket, 0xffff)
								Convey("Then I should not get any error", func() {
									So(err, ShouldBeNil)
								})

								Convey("When I try to set max packets in queue", func() {
									err := newNFQ.NfqSetQueueMaxLen(10)
									Convey("Then I should not get any error", func() {
										So(err, ShouldBeNil)
									})
								})
							})
						})
					})
				})
			})
		})
	})
}

func TestNfqClose(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to set mode for queue ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()
				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)
					})

					Convey("When I try to bind a socket", func() {

						err := newNFQ.BindPf()
						Convey("Then I should not get any error", func() {
							So(err, ShouldBeNil)
						})

						Convey("When I try to create a queue", func() {
							err := newNFQ.CreateQueue(10, passVerdict, errorCallback, nil)
							Convey("Then I should not get any error", func() {
								So(err, ShouldBeNil)
							})

							Convey("When I try to set a mode queue", func() {
								err := newNFQ.NfqSetMode(NfqnlCopyPacket, 0xffff)
								Convey("Then I should not get any error", func() {
									So(err, ShouldBeNil)
								})

								Convey("When I try to set max packets in queue", func() {
									err := newNFQ.NfqSetQueueMaxLen(10)
									Convey("Then I should not get any error", func() {
										So(err, ShouldBeNil)
									})

									Convey("When I try to close the socket for this queue, It should close successfully", func() {
										mockSyscalls.EXPECT().Close(5).Times(1)
										newNFQ.NfqClose()
									})
								})
							})
						})
					})
				})
			})
		})
	})
}

func TestNfqDestroyQueue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to set mode for queue ", func() {
			sockrcvbuf := 500 * int(common.NfnlBuffSize)

			newNFQ.(*NfQueue).Syscalls = mockSyscalls
			newNFQ.(*NfQueue).buf = []byte{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x40, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}

			Convey("When I try to open a socket", func() {
				mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(5, nil)
				mockSyscalls.EXPECT().Bind(5, gomock.Any()).Times(1).Return(nil)
				mockSyscalls.EXPECT().SetsockoptInt(5, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
				mockSyscalls.EXPECT().SetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
				nfqHandle, err := newNFQ.NfqOpen()
				Convey("Then I should not get any error", func() {
					So(nfqHandle, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})

				Convey("When I try to unbind a socket", func() {
					mockSyscalls.EXPECT().Sendto(5, gomock.Any(), 0, gomock.Any()).AnyTimes()
					mockSyscalls.EXPECT().Recvfrom(5, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
					err := newNFQ.UnbindPf()
					Convey("Then I should not get any error", func() {
						So(err, ShouldBeNil)
					})

					Convey("When I try to bind a socket", func() {

						err := newNFQ.BindPf()
						Convey("Then I should not get any error", func() {
							So(err, ShouldBeNil)
						})

						Convey("When I try to create a queue", func() {
							err := newNFQ.CreateQueue(10, passVerdict, errorCallback, nil)
							Convey("Then I should not get any error", func() {
								So(err, ShouldBeNil)
							})

							Convey("When I try to set a mode queue", func() {
								err := newNFQ.NfqSetMode(NfqnlCopyPacket, 0xffff)
								Convey("Then I should not get any error", func() {
									So(err, ShouldBeNil)
								})

								Convey("When I try to set max packets in queue", func() {
									err := newNFQ.NfqSetQueueMaxLen(10)
									Convey("Then I should not get any error", func() {
										So(err, ShouldBeNil)
									})

									Convey("When I try to destroy the queue for this queue, It should unbind successfully", func() {
										err := newNFQ.NfqDestroyQueue()
										Convey("Then I should not get any error", func() {
											So(err, ShouldBeNil)
										})
									})
								})
							})
						})
					})
				})
			})
		})
	})
}

func TestCreateQueueWithoutSocket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		Convey("When I try to create queue with no socket open ", func() {

			newNFQ.(*NfQueue).Syscalls = mockSyscalls

			mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(-1, fmt.Errorf("Error with Socket creation"))
			nfqHandle, err := newNFQ.NfqOpen()

			Convey("Then I should not get any error", func() {
				So(nfqHandle, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})

			Convey("When I try to unbind a socket which doesnt exist", func() {
				err := newNFQ.UnbindPf()
				Convey("Then I should get error for no Socket", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("When I try to bind a socket which doesnt exist", func() {
					err := newNFQ.BindPf()
					Convey("Then I should get error for no Socket", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("When I try to create a queue with no socket open", func() {
						err := newNFQ.CreateQueue(10, passVerdict, errorCallback, nil)
						Convey("Then I should get error for no Socket", func() {
							So(err, ShouldNotBeNil)
						})
						Convey("When I try to set a mode without socket", func() {
							err := newNFQ.NfqSetMode(NfqnlCopyPacket, 0xffff)
							Convey("Then I should get error for no Socket", func() {
								So(err, ShouldNotBeNil)
							})

							Convey("When I try to set max packets in queue without open socket", func() {
								err := newNFQ.NfqSetQueueMaxLen(10)
								Convey("Then I should get error for no Socket", func() {
									So(err, ShouldNotBeNil)
								})

								Convey("When I try to destroy the queue for without socket", func() {
									err := newNFQ.NfqDestroyQueue()
									Convey("Then I should get error for no Socket", func() {
										So(err, ShouldNotBeNil)
									})
								})
							})
						})
					})
				})
			})
		})
	})
}

func TestProcessPackets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSyscalls := syscallwrappers.NewMockSyscalls(ctrl)

	Convey("Given I create a new nfqueue", t, func() {
		queueNum := 10
		newNFQ := NewNFQueue()
		So(newNFQ, ShouldNotBeNil)

		newNFQ.(*NfQueue).Syscalls = mockSyscalls
		newNFQ.(*NfQueue).buf = []byte{0x78, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x09, 0x00, 0x00, 0x06, 0x00, 0x00, 0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x5d, 0x7a, 0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x69, 0xe3, 0x2c, 0x00, 0x0a, 0x00, 0x45, 0x00, 0x00, 0x28, 0x6c, 0x1d, 0x00, 0x00, 0x40, 0x06, 0xf6, 0xa2, 0x0a, 0x00, 0x02, 0x02, 0x0a, 0x00, 0x02, 0x0f, 0x00, 0x50, 0xde, 0xba, 0x01, 0x7c, 0xdc, 0x02, 0xb5, 0x09, 0xc5, 0x27, 0x50, 0x11, 0xff, 0xff, 0x61, 0x08, 0x00, 0x00}

		sockrcvbuf := 500 * int(common.NfnlBuffSize)

		mockSyscalls.EXPECT().Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER).Times(1).Return(3, nil)
		mockSyscalls.EXPECT().Bind(3, gomock.Any()).Times(1).Return(nil)
		mockSyscalls.EXPECT().SetsockoptInt(3, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, 1).Times(1)
		mockSyscalls.EXPECT().SetsockoptInt(3, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf).Times(1)
		mockSyscalls.EXPECT().SetsockoptInt(3, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf).Times(1)
		nfqHandle, err := newNFQ.NfqOpen()
		So(nfqHandle, ShouldNotBeNil)
		So(err, ShouldBeNil)

		mockSyscalls.EXPECT().Sendto(3, gomock.Any(), 0, gomock.Any()).AnyTimes()
		mockSyscalls.EXPECT().Recvfrom(3, newNFQ.(*NfQueue).buf, 0).AnyTimes().Return(15, nil, nil)
		err = newNFQ.UnbindPf()
		So(err, ShouldBeNil)

		err = newNFQ.BindPf()
		So(err, ShouldBeNil)

		err = newNFQ.CreateQueue(uint16(queueNum), passVerdict, errorCallback, nil)
		So(err, ShouldBeNil)

		oldHeaderSlice := make([]byte, int(syscall.SizeofNlMsghdr)+int(common.SizeofNfGenMsg)+int(common.NfaLength(uint16(SizeofNfqMsgVerdictHdr)))+int(common.NfaLength(uint16(SizeofNfqMsgMarkHdr))))

		err = newNFQ.NfqSetMode(NfqnlCopyPacket, 0xffff)
		So(err, ShouldBeNil)

		err = newNFQ.NfqSetQueueMaxLen(10)
		So(err, ShouldBeNil)
		Convey("Then my queue number should be same", func() {
			So(queueNum, ShouldEqual, newNFQ.(*NfQueue).QueueNum)
		})

		Convey("Then my header should be populated", func() {
			So(oldHeaderSlice, ShouldNotResemble, newNFQ.(*NfQueue).buf)
		})
		Convey("When I try to process packets, I expect the callback to be called", func() {
			mockSyscalls.EXPECT().Recvfrom(3, newNFQ.(*NfQueue).buf, 256).AnyTimes().Return(120, nil, nil)
			mockSyscalls.EXPECT().Syscall(uintptr(46), uintptr(3), gomock.Any(), uintptr(0)).AnyTimes()
			newNFQ.ProcessPackets(context.Background())
		})
	})
}
