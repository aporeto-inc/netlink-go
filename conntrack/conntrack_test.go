package conntrack

import (
	"testing"

	"github.com/aporeto-inc/netlink-go/common"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMark(t *testing.T) {

	var mark int

	Convey("Given I try to create a new handle and 5 udp flows", t, func() {
		handle := NewHandle()

		Convey("Given I try to flush the entries from conntrack", func() {
			err := handle.ConntrackTableFlush(common.ConntrackTable)

			Convey(" Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("Given I try to create 5 flows", func() {
			//udpFlows -- 5
			err := UDPFlowCreate(5, 2000, "127.0.0.10", 3000)
			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("Given I try to retrieve Conntrack table entries through netlink socket", func() {
			result, err := handle.ConntrackTableList(common.ConntrackTable)
			Convey("Then I should not get any error", func() {
				So(len(result), ShouldBeGreaterThanOrEqualTo, 5)
				So(err, ShouldBeNil)
			})

			Convey("Given I try to update mark for given attributes", func() {
				for i := 0; i < 5; i++ {
					k, err := handle.ConntrackTableUpdateMarkForAvailableFlow(result, "127.0.0.1", "127.0.0.10", 17, 2000+uint16(i), 3000, 23)
					So(err, ShouldBeNil)
					So(k, ShouldEqual, 1)
				}

				Convey("Then I should see 5 mark entries to be updated", func() {
					resultFin, err := handle.ConntrackTableList(common.ConntrackTable)
					So(err, ShouldBeNil)

					for i := range resultFin {
						if resultFin[i].Mark == 23 {
							mark++
						}
					}
					So(mark, ShouldEqual, 5)
				})
			})

			Convey("Given I try to flush the entries from conntrack", func() {
				err := handle.ConntrackTableFlush(common.ConntrackTable)

				Convey(" Then I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})
}

func TestFlush(t *testing.T) {

	var resultLenBefore, resultLenAfter int
	Convey("Given I try to create a new handle and 5 udp flows", t, func() {
		handle := NewHandle()

		Convey("Given I try to create 5 flows", func() {
			//udpFlows -- 5
			err := UDPFlowCreate(5, 2000, "127.0.0.1", 3000)
			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("Given I try to retrieve Conntrack table entries through netlink socket", func() {
			result, err := handle.ConntrackTableList(common.ConntrackTable)
			resultLenBefore = len(result)

			Convey("Then I should not get any error", func() {
				So(resultLenBefore, ShouldBeGreaterThanOrEqualTo, 5)
				So(err, ShouldBeNil)
			})
		})

		Convey("Given I try to flush the entries from conntrack", func() {
			err := handle.ConntrackTableFlush(common.ConntrackTable)

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})

			Convey("Given I try to retrieve Conntrack table entries again after flushing through netlink socket", func() {
				result, _ := handle.ConntrackTableList(common.ConntrackTable)
				resultLenAfter = len(result)

				Convey("Then the conntrack table should be empty and I should get error", func() {
					So(resultLenAfter, ShouldBeLessThan, resultLenBefore)
				})
			})
		})
	})
}

//
// func TestLabel(t *testing.T) {
//
// 	var entriesUpdated int
// 	Convey("Given I try to create a new handle and 5 udp flows", t, func() {
// 		handle := NewHandle()
//
// 		Convey("Given I try to flush the entries from conntrack", func() {
// 			err := handle.ConntrackTableFlush(common.ConntrackTable)
//
// 			Convey(" Then I should not get any error", func() {
// 				So(err, ShouldBeNil)
// 			})
// 		})
//
// 		//udpFlows -- 5
// 		udpFlowCreate(t, 5, 2000, "127.0.0.10", 3000)
//
// 		Convey("Given I try to retrieve Conntrack table entries through netlink socket", func() {
// 			result, err := handle.ConntrackTableList(common.ConntrackTable)
//
// 			Convey("Then I should not get any error", func() {
// 				So(len(result), ShouldBeGreaterThanOrEqualTo, 5)
// 				So(err, ShouldBeNil)
// 			})
//
// 			Convey("Given I try to update label for given attributes", func() {
// 				for i := 0; i < 5; i++ {
// 					entries, err := handle.ConntrackTableUpdateLabel(common.ConntrackTable, result, "127.0.0.1", "127.0.0.10", 17, 2000+uint16(i), 3000, ENCRYPTED)
// 					So(err, ShouldBeNil)
// 					entriesUpdated += entries
// 				}
//
// 				Convey("Then I should see 5 entries to be updated", func() {
// 					So(entriesUpdated, ShouldEqual, 5)
// 				})
// 			})
// 			Convey("Given I try to flush the entries from conntrack", func() {
// 				err := handle.ConntrackTableFlush(common.ConntrackTable)
//
// 				Convey(" Then I should not get any error", func() {
// 					So(err, ShouldBeNil)
// 				})
// 			})
// 		})
// 	})
// }
