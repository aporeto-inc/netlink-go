package conntrack

import (
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

// func init() {
// 	handles := NewHandle()
// 	result, _ := handles.ConntrackTableList(ConntrackTable)
// 	err := handles.ConntrackTableUpdate(ConntrackTable, result, "10.0.2.2", "10.0.2.15", 6, 49486, 22, 20)
// 	fmt.Println(err)
// 	resultFin, _ := handles.ConntrackTableList(ConntrackTable)
// 	for i, _ := range resultFin {
// 		fmt.Println(resultFin[i])
// 	}
// }

func udpFlowCreate(t *testing.T, flows, srcPort int, dstIP string, dstPort int) {
	for i := 0; i < flows; i++ {
		ServerAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dstIP, dstPort))

		LocalAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", srcPort+i))

		Conn, _ := net.DialUDP("udp", LocalAddr, ServerAddr)

		Conn.Write([]byte("Hello World"))
		Conn.Close()
	}
}

func TestMark(t *testing.T) {
	var mark int

	Convey("Given I try to create a new handle and 5 udp flows", t, func() {
		handle := NewHandle()

		Convey("Given I try to flush the entries from conntrack", func() {
			err := handle.ConntrackTableFlush(ConntrackTable)

			Convey("I should not gen any error", func() {
				So(err, ShouldBeNil)
			})
		})

		//udpFlows -- 5
		udpFlowCreate(t, 5, 2000, "127.0.0.10", 3000)

		Convey("Given I retrieve Conntrack table entries through netlink socket", func() {
			result, err := handle.ConntrackTableList(ConntrackTable)

			Convey("I should not gen any error", func() {
				So(result, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("Given I try to update mark for given attributes", func() {
				for i := 0; i < 5; i++ {
					handle.ConntrackTableUpdate(1, result, "127.0.0.1", "127.0.0.10", 17, 2000+uint16(i), 3000, 50)
				}

				Convey("I should see 5 mark entries to be updated", func() {
					resultFin, _ := handle.ConntrackTableList(ConntrackTable)
					for i, _ := range resultFin {
						if resultFin[i].Mark == 50 {
							mark++
						}
					}
					So(mark, ShouldEqual, 5)
				})
			})
		})
	})
}
