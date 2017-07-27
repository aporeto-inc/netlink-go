// +build !linux darwin

package conntrack

type Conntrack interface {
	ConntrackTableList(table interface{}) ([]*interface{}, error)
	ConntrackTableFlush(table interface{}) error
	ConntrackTableUpdateMarkForAvailableFlow(flows []*interface{}, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) (int, error)
	ConntrackTableUpdateMark(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error
	ConntrackTableUpdateLabel(table interface{}, flows []*interface{}, ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newlabels uint32) (int, error)
}

// NewHandle which returns interface which implements Conntrack table get/set/flush
func NewHandle() Conntrack {
	return nil
}
