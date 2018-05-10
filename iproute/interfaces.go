// +build linux !darwin

package iproute

// IPRoute is the interface for iproute handlers
type IPRoute interface {
	// AddRule add rule to the rule table
	AddRule(rule *Rule) error
	// DeleteRule  deletes a rule from the rule table
	DeleteRule(rule *Rule) error
	// AddRoute add a route a specific table
	AddRoute(route *Route) error
	// DeleteRoute deletes the route from a specific table.
	DeleteRoute(route *Route) error
}
