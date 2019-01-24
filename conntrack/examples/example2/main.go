package main

import (
	"log"
	"runtime"

	"go.aporeto.io/netlink-go/conntrack"
)

func main() {

	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()

	handle := conntrack.NewHandle()

	if err := conntrack.UDPFlowCreate(5, 2000, "127.0.0.10", 3000); err != nil {
		log.Println(err)
	}

	err := handle.ConntrackTableUpdateMark("10.0.2.15", "10.0.2.2", 6, 22, 57766, 24)
	if err != nil {
		log.Println(err)
	}
}
