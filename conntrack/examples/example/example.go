// +build linux !darwin

// This is a sample conntrack mark update which uses the conntrack library
// In this example we update the first entry in the conntrack with the given mark
// For this example to work the conntrack should not be empty
// Use conntrack -L or print the updated table by calling display
package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/conntrack"
)

func display(result []*netlink.ConntrackFlow) {
	fmt.Println(result[0])
}

func main() {

	handle := conntrack.NewHandle()

	result, err := handle.ConntrackTableList(common.ConntrackTable)
	if err != nil {
		fmt.Println("Empty conntrack entries", err)
	}
	// Use ConntrackTableUpdateMark(...) if the 4 tuples and protocol are already known
	entriesUpdated, err := handle.ConntrackTableUpdateMarkForAvailableFlow(result, result[0].Forward.SrcIP.String(), result[0].Forward.DstIP.String(), result[0].Forward.Protocol, result[0].Forward.SrcPort, result[0].Forward.DstPort, 42)
	fmt.Println("Number of entries updated", entriesUpdated)
	if err != nil {
		fmt.Println("Error Updating Mark", err)
	}

	finalResult, err := handle.ConntrackTableList(common.ConntrackTable)
	if err != nil {
		fmt.Println("Empty conntrack entries", err)
	}

	display(finalResult)
}
