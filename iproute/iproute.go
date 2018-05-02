// +build linux

package iproute

import (
	"syscall"
	"time"

	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/common/sockets"
	"github.com/vishvananda/netlink"
)

// Iproute is the wrapper around netlinkHandle
type Iproute struct {
	socketHandlers *sockets.SockHandles
}

// NewIPRouteHandle returns a reference IpRoute structure
func NewIPRouteHandle() (IPRoute, error) {
	return &Iproute{socketHandlers: sockets.NewSocketHandlers()}, nil

}

// AddRule add rule to the rule table
func (i *Iproute) AddRule(rule *netlink.Rule) error {
	//mask of the high bits
	seq := time.Now().Unix() & 0x00000000ffffffff
	nlmsghdr := common.BuildNlMsgHeader(
		syscall.RTM_NEWRULE,
		syscall.NLM_F_ATOMIC|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_MATCH,
		syscall.SizeofNlMsghdr)
	nlmsghdr.Seq = uint32(seq)
	rtmsgbuf := rtmsgToWire(syscall.AF_INET, uint8(rule.Table), syscall.RTPROT_BOOT, syscall.RTN_UNICAST)
	priobuf := priorityAttrToWire(uint32(rule.Priority))
	markbuf := markAttrToWire(uint32(rule.Mark))
	maskbuf := markMaskAttrToWire(uint32(rule.Mask))
	nlmsghdr.Len = syscall.SizeofNlMsghdr + uint32(len(rtmsgbuf)+len(priobuf)+len(markbuf)+len(maskbuf))
	var buf []byte
	buf = append(buf, rtmsgbuf...)
	buf = append(buf, markbuf...)
	buf = append(buf, maskbuf...)
	buf = append(buf, priobuf...)
	return i.send(nlmsghdr, buf)
}

// DeleteRule  deletes a rule from the rule table
func (i *Iproute) DeleteRule(rule *netlink.Rule) error {
	//mask of the high bits
	seq := time.Now().Unix() & 0x00000000ffffffff
	nlmsghdr := common.BuildNlMsgHeader(
		syscall.RTM_DELRULE,
		syscall.NLM_F_ATOMIC|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_MATCH,
		syscall.SizeofNlMsghdr)
	nlmsghdr.Seq = uint32(seq)
	rtmsgbuf := rtmsgToWire(syscall.AF_INET, uint8(rule.Table), syscall.RTPROT_BOOT, syscall.RTN_UNICAST)
	priobuf := priorityAttrToWire(uint32(rule.Priority))
	markbuf := markAttrToWire(uint32(rule.Mark))
	nlmsghdr.Len = syscall.SizeofNlMsghdr + uint32(len(rtmsgbuf)+len(priobuf)+len(markbuf))
	var buf []byte
	buf = append(buf, rtmsgbuf...)
	buf = append(buf, priobuf...)
	buf = append(buf, markbuf...)
	return i.send(nlmsghdr, buf)
}

// AddRoute add a route a specific table
func (i *Iproute) AddRoute(route *netlink.Route) error {
	seq := time.Now().Unix() & 0x00000000ffffffff
	nlmsghdr := common.BuildNlMsgHeader(
		syscall.RTM_NEWROUTE,
		syscall.NLM_F_ATOMIC|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_MATCH,
		syscall.SizeofNlMsghdr)
	nlmsghdr.Seq = uint32(seq)
	rtmsgbuf := rtmsgToWire(syscall.AF_INET, uint8(route.Table), syscall.RTPROT_BOOT, syscall.RTN_UNICAST)
	ipbuf := ipgwToWire(route.Gw)
	devbuf := ipifindexToWire(uint32(route.LinkIndex))
	nlmsghdr.Len = syscall.SizeofNlMsghdr + uint32(len(rtmsgbuf)+len(ipbuf)+len(devbuf))
	var buf []byte
	buf = append(buf, rtmsgbuf...)
	buf = append(buf, ipbuf...)
	buf = append(buf, devbuf...)
	return i.send(nlmsghdr, buf)
}

// DeleteRoute deletes the route from a specific table.
func (i *Iproute) DeleteRoute(route *netlink.Route) error {
	seq := time.Now().Unix() & 0x00000000ffffffff
	nlmsghdr := common.BuildNlMsgHeader(
		syscall.RTM_DELROUTE,
		syscall.NLM_F_ATOMIC|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_MATCH,
		syscall.SizeofNlMsghdr)
	nlmsghdr.Seq = uint32(seq)
	rtmsgbuf := rtmsgToWire(syscall.AF_INET, uint8(route.Table), syscall.RTPROT_BOOT, syscall.RTN_UNICAST)
	ipbuf := ipgwToWire(route.Gw)
	devbuf := ipifindexToWire(uint32(route.LinkIndex))
	nlmsghdr.Len = syscall.SizeofNlMsghdr + uint32(len(rtmsgbuf)+len(ipbuf)+len(devbuf))
	var buf []byte
	buf = append(buf, rtmsgbuf...)
	buf = append(buf, ipbuf...)
	buf = append(buf, devbuf...)
	return i.send(nlmsghdr, buf)
}

func (i *Iproute) send(hdr *syscall.NlMsghdr, data []byte) error {

	_, err := i.socketHandlers.Open(syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}

	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   data,
	}

	err = i.socketHandlers.Query(netlinkMsg)
	if err != nil {
		return err
	}

	i.socketHandlers.Close()
	return nil

}
