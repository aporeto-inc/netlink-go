// +build linux !darwin

package nflog

import (
	"net"
	"syscall"

	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
	"github.com/google/gopacket/layers"
)

// NfLog -- Nflog struct
// Groups -- Nflog group to bind with. max 32
// CopyRange -- Nflog packetsize. 0: Unlimited
type NfLog struct {
	Groups        []uint16
	CopyRange     uint16
	callback      func(buf *NfPacket, data interface{})
	errorCallback func(err error)
	Socket        SockHandle
	NflogHandle   *NfLog
	Syscalls      syscallwrappers.Syscalls
}

// nflogHeader -- unexported header struct for parsing
type nflogHeader struct {
	Family  uint8
	Version uint8
	ResId   uint16 // BigEndian
}

// nflogTlv -- unexported attribute struct for parsing
type nflogTlv struct {
	Len  uint16
	Type uint16
}

// NflMsgConfigCommand -- NflMsgConfigCommand struct for configs (ex: bind)
type NflMsgConfigCommand struct {
	command uint8
}

// NflMsgConfigMode -- NflMsgConfigMode struct for copy range and mode (ex: copy meta)
type NflMsgConfigMode struct {
	copyRange uint32
	copyMode  uint8
	_pad      uint8
}

//SockHandle -- Sock handle of netlink socket
//fd -- fd of socket
//rcvbufSize -- rcv buffer Size
//lsa -- local address
type SockHandles struct {
	Syscalls   syscallwrappers.Syscalls
	fd         int
	rcvbufSize uint32
	buf        []byte
	lsa        syscall.SockaddrNetlink
}

// NfPacket -- NfPacket struct for parsing logs
// Payload -- Complete packet with ethernet,tcp and ip
// IPLayer -- Iplayer struct
// TCPLayer -- Tcplayer struct
// PacketPayload -- Tcp payload
type NfPacket struct {
	Prefix  string
	Payload []byte
	IPLayer
	Ports
	PacketPayload
}

// IPLayer -- IPLayer struct
type IPLayer struct {
	SrcIP    net.IP
	DstIP    net.IP
	Version  uint8
	Protocol layers.IPProtocol
	Length   uint16
}

// Ports -- Generic struct for TCP and UDP ports
type Ports struct {
	SrcPort int
	DstPort int
}

// PacketPayload -- PacketPayload struct
type PacketPayload struct {
	AppPayload []byte
}
