// +build linux !darwin

package iproute

import (
	"github.com/vishvananda/netlink"
)

// IPRoute is the interface for iproute handlers
type IPRoute interface {
	// AddRule add rule to the rule table
	AddRule(rule *netlink.Rule) error
	// DeleteRule  deletes a rule from the rule table
	DeleteRule(rule *netlink.Rule) error
	// AddRoute add a route a specific table
	AddRoute(route *netlink.Route) error
	// DeleteRoute deletes the route from a specific table.
	DeleteRoute(route *netlink.Route) error
}
