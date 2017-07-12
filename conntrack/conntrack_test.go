package conntrack

import "testing"

func init() {
	handles, _ := NewHandle()
	result, _ := handles.ConntrackTableList(1)
	handles.ConntrackTableUpdate(1, result)
}
func TestSample(t *testing.T) {

}
