package diag

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"go.aporeto.io/netlink-go/common"
	"go.aporeto.io/netlink-go/common/syscallwrappers"
)

var native binary.ByteOrder

func init() {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		native = binary.BigEndian
	} else {
		native = binary.LittleEndian
	}
}

// InetDiag holds the state for running an inet_diag_req_v2
type InetDiag struct {
	syswrap  syscallwrappers.Syscalls
	fd       int
	sockaddr syscall.SockaddrNetlink
}

// NewInetDiag establishes state for running an inet_diag_req_v2 - including creating a socket.
// NOTE: you **must** call `Close` on the returned InetDiag in order to release the fd for the socket.
func NewInetDiag() (*InetDiag, error) {
	syswrap := syscallwrappers.NewSyscalls()
	fd, err := syswrap.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	return &InetDiag{
		syswrap: syswrap,
		fd:      fd,
		sockaddr: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
			Pid:    0,
			Groups: 0,
		},
	}, nil
}

// Close closes the fd for the socket
func (d *InetDiag) Close() {
	d.syswrap.Close(d.fd)
}

// GetConnections will run an inet_diag_req_v2 for the specified family and protocol.
// If no states are given, it is being assumed that the caller is asking for all states.
// If states are given, then all connections are being returned filtered by all the specified states
func (d *InetDiag) GetConnections(family AddressFamily, protocol IPProtocol, states ...ConnectionState) ([]Connection, error) {
	var statesArg uint32
	if len(states) > 0 {
		var tmp uint32
		for _, state := range states {
			tmp |= (1 << uint32(state))
		}
		statesArg = tmp
	} else {
		statesArg = tcp_all
	}
	fmt.Printf("%x\n", statesArg)
	// build request
	hdr := common.BuildNlMsgHeader(common.DiagSockDiagByFamily, common.NlmFlags(syscall.NLM_F_DUMP)|common.NlmFRequest, 0)
	req := common.BuildInetDiagReqV2(uint8(family), uint8(protocol), statesArg, hdr)
	reqNlmsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   req.ToWireFormat(),
	}

	// send request
	if err := d.send(reqNlmsg); err != nil {
		return nil, fmt.Errorf("netlink socket send: %w", err)
	}

	// receive responses
	respNlmsgs, err := d.receive()
	if err != nil {
		return nil, fmt.Errorf("netlink socket receive: %w", err)
	}

	// process responses and build return
	ret := make([]Connection, 0, len(respNlmsgs))
	for _, respMsg := range respNlmsgs {
		// error handling
		if respMsg.Header.Type == syscall.NLMSG_ERROR {
			msgerr := (*syscall.NlMsgerr)(unsafe.Pointer(&respMsg.Data[0]))
			return nil, fmt.Errorf("netlink response error: %s (%d)",
				syscall.Errno(-msgerr.Error).Error(),
				-msgerr.Error,
			)
		}
		inetDiagMsg, err := common.ParseInetDiagMsg(respMsg.Data)
		if err != nil {
			return nil, fmt.Errorf("inet_diag_msg parse: %w", err)
		}
		var src, dst net.IP
		switch inetDiagMsg.IDiagFamily {
		case syscall.AF_INET6:
			s := inetDiagMsg.Id.IDiagSrc
			src = append(src,
				s[0][0], s[0][1], s[0][2], s[0][3],
				s[1][0], s[1][1], s[1][2], s[1][3],
				s[2][0], s[2][1], s[1][2], s[2][3],
				s[3][0], s[3][1], s[3][2], s[3][3],
			)
			d := inetDiagMsg.Id.IDiagDst
			dst = append(dst,
				d[0][0], d[0][1], d[0][2], d[0][3],
				d[1][0], d[1][1], d[1][2], d[1][3],
				d[2][0], d[2][1], d[1][2], d[2][3],
				d[3][0], d[3][1], d[3][2], d[3][3],
			)
		default:
			srcTmp := inetDiagMsg.Id.IDiagSrc[0]
			src = net.IPv4(srcTmp[0], srcTmp[1], srcTmp[2], srcTmp[3])
			dstTmp := inetDiagMsg.Id.IDiagDst[0]
			dst = net.IPv4(dstTmp[0], dstTmp[1], dstTmp[2], dstTmp[3])
		}
		ret = append(ret, Connection{
			Source:          src,
			Destination:     dst,
			SourcePort:      port(inetDiagMsg.Id.IDiagSport),
			DestinationPort: port(inetDiagMsg.Id.IDiagDport),
			UID:             uint(inetDiagMsg.IDiagUid),
			Inode:           uint(inetDiagMsg.IDiagInode),
			State:           ConnectionState(inetDiagMsg.IDiagState),
		})
	}

	return ret, nil
}

func (d *InetDiag) send(msg *syscall.NetlinkMessage) error {
	buf := make([]byte, syscall.SizeofNlMsghdr+len(msg.Data))
	binary.LittleEndian.PutUint32(buf[0:4], msg.Header.Len)
	native.PutUint16(buf[4:6], msg.Header.Type)
	native.PutUint16(buf[6:8], msg.Header.Flags)
	native.PutUint32(buf[8:12], msg.Header.Seq)
	native.PutUint32(buf[12:16], msg.Header.Pid)
	copy(buf[16:], msg.Data)
	return d.syswrap.Sendto(d.fd, buf, 0, &d.sockaddr)
}

func (d *InetDiag) receive() ([]syscall.NetlinkMessage, error) {
	buf := make([]byte, syscall.Getpagesize())
	len, _, err := d.syswrap.Recvfrom(d.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	if len < syscall.NLMSG_HDRLEN {
		return nil, fmt.Errorf("netlink message too short")
	}
	buf = buf[:len]
	return syscall.ParseNetlinkMessage(buf)
}

// ConnectionState is a type to hold the state of a connection
type ConnectionState uint8

// String converts a connection state into a user-readable string
func (s ConnectionState) String() string {
	str, ok := tcpStatesMap[s]
	if !ok {
		return "unknown"
	}
	return str
}

// Connection returns a golang usable connection information of an inet_diag_msg as returned by an inet_diag_req_v2.
type Connection struct {
	Source          net.IP
	Destination     net.IP
	SourcePort      uint16
	DestinationPort uint16
	UID             uint
	Inode           uint
	State           ConnectionState
}

// String returns a user-readable string of a connecion object
func (c Connection) String() string {
	return fmt.Sprintf("Src:%s:%d Dst:%s:%d UID:%d Inode:%d State:%s",
		c.Source, c.SourcePort,
		c.Destination, c.DestinationPort,
		c.UID,
		c.Inode,
		c.State,
	)
}

func port(bytes [2]byte) uint16 {
	return binary.BigEndian.Uint16([]byte{bytes[0], bytes[1]})
}

const (
	_               ConnectionState = iota
	TCP_ESTABLISHED ConnectionState = iota
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
)

const (
	tcp_all uint32 = 0xFFF
)

var tcpStatesMap = map[ConnectionState]string{
	TCP_ESTABLISHED: "established",
	TCP_SYN_SENT:    "syn_sent",
	TCP_SYN_RECV:    "syn_recv",
	TCP_FIN_WAIT1:   "fin_wait1",
	TCP_FIN_WAIT2:   "fin_wait2",
	TCP_TIME_WAIT:   "time_wait",
	TCP_CLOSE:       "close",
	TCP_CLOSE_WAIT:  "close_wait",
	TCP_LAST_ACK:    "last_ack",
	TCP_LISTEN:      "listen",
	TCP_CLOSING:     "closing",
}

// AddressFamily is the address family type - can be AF_INET or AF_INET6 essentially
type AddressFamily uint8

const (
	// AddressFamilyInet is AF_INET
	AddressFamilyInet AddressFamily = AddressFamily(syscall.AF_INET)
	// AddressFamilyInet6 is AF_INET6
	AddressFamilyInet6 AddressFamily = AddressFamily(syscall.AF_INET6)
)

// IPProtocol is the protocol type - can be only IPPROTO_TCP right now
type IPProtocol uint8

const (
	// IPProtocolTCP is IPPROTO_TCP
	IPProtocolTCP IPProtocol = IPProtocol(syscall.IPPROTO_TCP)
)
