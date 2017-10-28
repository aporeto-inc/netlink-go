package nfqueue

import (
	"syscall"

	"github.com/aporeto-inc/netlink-go/common"
)

// CallbackFunc is a function signature to provide a new packet to the application.
// The packet is not reused if the callback returns false. In such a case, its the
// applications responsibility to call a Free on the NFPacket
type CallbackFunc func(*NFPacket, interface{}) bool

// ErrorCallbackFunc is the function signature to report errors file doing packet operations
type ErrorCallbackFunc func(error, interface{})

//Verdict -- Interface exposing functionality to get a copy of the received packet and set a verdict
type Verdict interface {
	SetVerdict2(queueNum uint32, verdict uint32, mark uint32, packetLen uint32, packetID uint32, packet []byte)
	SetVerdict(queueNum uint32, verdict uint32, packetLen uint32, packetID uint32, packet []byte)
	GetNotificationChannel() chan *NFPacket
	StopQueue() error
}

//NFQueue -- Interface exposing internal Nfqueue functions. This is needed if we want to create and manage queues. Instead of calling the CreateAndStart function directly from the package
type NFQueue interface {
	Verdict
	NfqOpen() (SockHandle, error)
	UnbindPf() error

	CreateQueue(num uint16, callback CallbackFunc, errorCallback ErrorCallbackFunc, privateData interface{}) error
	NfqSetMode(mode nfqConfigMode, packetSize uint32) error
	NfqSetQueueMaxLen(queuelen uint32) error
	NfqClose()
	NfqDestroyQueue() error
	Recv() (*common.NfqGenMsg, *common.NfAttrSlice, error)
	ProcessPackets()
	BindPf() error
	setSockHandle(handle SockHandle) //private unexported function for tests
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
