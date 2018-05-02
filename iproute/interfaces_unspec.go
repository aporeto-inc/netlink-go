// +build !linux darwin

package iproute

type IPRoute interface {
	AddRule(rule interface{}) error
	DeleteRule(rule interface{}) error
	AddRoute(route interface{}) error
	DeleteRoute(route interface{}) error
}

func NewIPRouteHandle() IPRoute {
	return nil
}
