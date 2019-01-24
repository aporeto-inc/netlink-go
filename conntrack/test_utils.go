package conntrack

import (
	"fmt"
	"net"
)

// UDPFlowCreate creates udp flows
func UDPFlowCreate(flows, srcPort int, dstIP string, dstPort int) error {
	for i := 0; i < flows; i++ {
		ServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dstIP, dstPort))
		if err != nil {
			return err
		}

		LocalAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", srcPort+i))
		if err != nil {
			return err
		}

		Conn, err := net.DialUDP("udp", LocalAddr, ServerAddr)
		if err != nil {
			return err
		}

		Conn.Write([]byte("Hello World"))
		if err := Conn.Close(); err != nil {
			return err
		}
	}
	return nil
}
