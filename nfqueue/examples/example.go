// Here is a sample code which uses the library to create 4 queues and uses 2 callbacks to setverdict2
// on packets that come up these queues.
// For this program to see packets you will have a create iptable rules to capture and send packets on
// the corresponding queues.

package main

import (
	"time"

	"github.com/aporeto-inc/netlink-go/nfqueue"
)

func passNetVerdict(buf *nfqueue.NFPacket, data interface{}) bool {

	buf.QueueHandle.SetVerdict2(uint32(buf.QueueHandle.QueueNum), 1, 11, uint32(len(buf.Buffer)), uint32(buf.ID), buf.Buffer)

	return true
}

func passVerdict(buf *nfqueue.NFPacket, data interface{}) bool {

	buf.QueueHandle.SetVerdict2(uint32(buf.QueueHandle.QueueNum), 1, 11, uint32(len(buf.Buffer)), uint32(buf.ID), buf.Buffer)

	return true
}

func errorCallback(err error, data interface{}) {
}

func main() {

	nfqAppHdl := make([]nfqueue.Verdict, 2)
	nfqNetHdl := make([]nfqueue.Verdict, 2)
	for i := 10; i < 12; i++ {
		nfqAppHdl[i-10], _ = nfqueue.CreateAndStartNfQueue(uint16(i), 2000, 0xffff, passVerdict, errorCallback, nil)
	}
	for i := 12; i < 14; i++ {
		nfqNetHdl[i-12], _ = nfqueue.CreateAndStartNfQueue(uint16(i), 2000, 0xffff, passNetVerdict, errorCallback, nil)
	}

	for {
		time.Sleep(100 * time.Second)
	}
}
