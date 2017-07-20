package nfqueue

import (
	"github.com/Workiva/go-datastructures/queue"
	"github.com/aporeto-inc/netlink-go/common"
)

//NFPacket -- message format sent on channel
type NFPacket struct {
	Buffer      []byte
	ID          int
	Mark        int
	QueueHandle *NfQueue
	queue       *queue.RingBuffer
	buf         [common.NfnlBuffSize]byte
}

//Free replenishes the packets to the driver
func (nfp *NFPacket) Free() {
	nfp.queue.Put(nfp)
}
