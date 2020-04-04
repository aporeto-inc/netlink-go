module go.aporeto.io/netlink-go

go 1.13

require (
	github.com/golang/mock v1.4.3
	github.com/smartystreets/goconvey v1.6.4
	github.com/stretchr/testify v1.5.1
	github.com/vishvananda/netlink v1.1.0
	go.uber.org/zap v1.14.1
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859
)

replace github.com/vulcand/oxy => github.com/aporeto-inc/oxy v1.3.1-0.20200314064302-4c2778768cee
