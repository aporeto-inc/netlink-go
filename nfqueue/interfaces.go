package nfqueue

import (
	"context"
	"syscall"

	"github.com/aporeto-inc/netlink-go/common"
)

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

	CreateQueue(num uint16, data func(packet *NFPacket, callback interface{}), errorCallback func(err error, data interface{}), privateData interface{}) error
	NfqSetMode(mode nfqConfigMode, packetSize uint32) error
	NfqSetQueueMaxLen(queuelen uint32) error
	NfqClose()
	NfqDestroyQueue() error
	Recv() (*common.NfqGenMsg, map[int]*common.NfAttrResponsePayload, error)
	ProcessPackets(ctx context.Context)
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
