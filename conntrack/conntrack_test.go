package conntrack

import (
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

//Test to check mark has been updated once
//Since the tuples have just one entries in the conntrack table
func TestMark(t *testing.T) {
	var mark int
	Convey("Given I create a new handle", t, func() {
		handle := NewHandle()

		Convey("Given I retrieve Conntrack table entries through netlink socket", func() {
			result, err := handle.ConntrackTableList(ConntrackTable)

			Convey("I should not gen any error", func() {
				So(result, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("Given I try to update mark for given attributes", func() {
				handle.ConntrackTableUpdate(1, result, "10.0.2.15", "10.0.2.2", 6, 22, 53341, 25)

				Convey("I should see one entry mark to be updated", func() {
					resultFin, _ := handle.ConntrackTableList(ConntrackTable)
					for i, _ := range resultFin {
						if resultFin[i].Mark == 25 {
							mark++
						}
					}
					So(mark, ShouldEqual, 1)
				})
			})
		})
	})
}
