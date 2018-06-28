// +build linux !darwin

// This is a sample code that uses the library to bind to a group and listen for logs
// To see logs you have to create an iptable rule that matches with the nflog groups
// Callback is just to display packets received from the kernel to userspace

package main

import (
	"fmt"
	"log"
	"time"

	"go.aporeto.io/netlink-go/nflog"
)

func packetCallback(buf *nflog.NfPacket, data interface{}) {
	fmt.Println(buf)
}

func errorCallback(err error) {

}

func main() {

	var groups []uint16
	var copyrange uint32

	groups = []uint16{32}
	copyrange = 64

	_, err := nflog.BindAndListenForLogs(groups, copyrange, packetCallback, errorCallback)
	if err != nil {
		log.Println(err)
	}

	for {
		time.Sleep(100 * time.Second)
	}

}
