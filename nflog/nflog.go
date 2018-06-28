// +build linux !darwin

package nflog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"syscall"

	"go.aporeto.io/netlink-go/common"
	"go.aporeto.io/netlink-go/common/syscallwrappers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NewNFLog -- Create a new Nflog handle
func NewNFLog() NFLog {
	n := &NfLog{Syscalls: syscallwrappers.NewSyscalls()}
	return n
}

// BindAndListenForLogs -- a complete set to open/unbind/bind/bindgroup and listen for logs
// group -- group to bind with and listen
// packetSize -- max expected packetSize (0:unlimited)
func BindAndListenForLogs(groups []uint16, packetSize uint32, callback func(*NfPacket, interface{}), errorCallback func(err error)) (NFLog, error) {
	nflHandle := NewNFLog()

	nflog, err := nflHandle.NFlogOpen()
	if err != nil {
		return nil, fmt.Errorf("Error opening NFLog handle: %v ", err)
	}

	if err := nflHandle.NFlogUnbind(); err != nil {
		nflHandle.NFlogClose()
		return nil, fmt.Errorf("Error unbinding existing NFLog handler from AfInet protocol family: %v ", err)
	}

	if err := nflHandle.NFlogBind(); err != nil {
		nflHandle.NFlogClose()
		return nil, fmt.Errorf("Error binding to AfInet protocol family: %v ", err)
	}

	if err := nflHandle.NFlogBindGroup(groups, callback, errorCallback); err != nil {
		nflHandle.NFlogClose()
		return nil, fmt.Errorf("Error binding to nflog group: %v ", err)
	}

	if err := nflHandle.NFlogSetMode(groups, packetSize); err != nil {
		nflHandle.NFlogClose()
		return nil, fmt.Errorf("Unable to set copy packet mode: %v ", err)
	}

	go nflHandle.ReadLogs()
	return nflog, nil
}

// NFlogOpen Open a new netlink socket
// Create a new sock handle and return the handle
// Open a new socket and return it in the NflogHandle.
// The fd for the socket is stored in an unexported handle
func (nl *NfLog) NFlogOpen() (NFLog, error) {
	sh := &SockHandles{Syscalls: nl.Syscalls}
	fd, err := nl.Syscalls.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	sh.fd = fd
	sh.rcvbufSize = common.NfnlBuffSize
	sh.lsa.Family = syscall.AF_NETLINK

	err = nl.Syscalls.Bind(fd, &sh.lsa)
	if err != nil {
		return nil, err
	}
	nl.Socket = sh
	nl.NflogHandle = nl

	return nl.NflogHandle, nil
}

// NFlogUnbind -- passes an unbind command to nfnetlink for AF_INET.
func (nl *NfLog) NFlogUnbind() error {

	config := &NflMsgConfigCommand{
		command: NFULNL_CFG_CMD_PF_UNBIND,
	}

	hdr := common.BuildNlMsgHeader(common.NfnlNFLog,
		common.NlmFRequest|common.NlmFAck,
		0,
	)

	nfgen := common.BuildNfgenMsg(syscall.AF_INET, common.NFNetlinkV0, 0, hdr)
	attr := common.BuildNfAttrMsg(NFULA_CFG_CMD, hdr, config.Length())
	data := nfgen.ToWireFormat()
	data = append(data, attr.ToWireFormat()...)
	data = append(data, config.ToWireFormat()...)

	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   data,
	}

	if nl.Socket != nil {
		return nl.Socket.query(netlinkMsg)
	}

	return fmt.Errorf("NFlogOpen was not called. No Socket open")
}

// NFlogBind -- Bind to a PF family
func (nl *NfLog) NFlogBind() error {

	config := &NflMsgConfigCommand{
		command: NFULNL_CFG_CMD_PF_BIND,
	}

	hdr := common.BuildNlMsgHeader(common.NfnlNFLog,
		common.NlmFRequest|common.NlmFAck,
		0,
	)

	nfgen := common.BuildNfgenMsg(syscall.AF_INET, common.NFNetlinkV0, 0, hdr)
	attr := common.BuildNfAttrMsg(NFULA_CFG_CMD, hdr, config.Length())
	data := nfgen.ToWireFormat()
	data = append(data, attr.ToWireFormat()...)
	data = append(data, config.ToWireFormat()...)

	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   data,
	}

	if nl.Socket != nil {
		return nl.Socket.query(netlinkMsg)
	}

	return fmt.Errorf("NFlogOpen was not called. No Socket open")
}

// NFlogBindGroup -- Bind to a group
// group -- group to bind with
func (nl *NfLog) NFlogBindGroup(groups []uint16, callback func(*NfPacket, interface{}), errorCallback func(err error)) error {

	nl.callback = callback
	nl.errorCallback = errorCallback

	for _, g := range groups {
		config := &NflMsgConfigCommand{
			command: NFULNL_CFG_CMD_BIND,
		}

		hdr := common.BuildNlMsgHeader(common.NfnlNFLog,
			common.NlmFRequest|common.NlmFAck,
			0,
		)

		nfgen := common.BuildNfgenMsg(syscall.AF_INET, common.NFNetlinkV0, g, hdr)
		attr := common.BuildNfAttrMsg(NFULA_CFG_CMD, hdr, config.Length())
		data := nfgen.ToWireFormat()
		data = append(data, attr.ToWireFormat()...)
		data = append(data, config.ToWireFormat()...)

		netlinkMsg := &syscall.NetlinkMessage{
			Header: *hdr,
			Data:   data,
		}

		if nl.Socket != nil {
			err := nl.Socket.query(netlinkMsg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// NFlogSetMode -- Set queue mode CopyMeta
// packetSize -- The range of bytes from packets to copy
func (nl *NfLog) NFlogSetMode(groups []uint16, packetSize uint32) error {

	for _, g := range groups {
		config := &NflMsgConfigMode{
			copyMode:  NFULNL_COPY_PACKET,
			copyRange: packetSize,
		}

		hdr := common.BuildNlMsgHeader(common.NfnlNFLog,
			common.NlmFRequest|common.NlmFAck,
			0,
		)

		nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, g, hdr)
		attr := common.BuildNfAttrMsg(NFULA_CFG_MODE, hdr, config.Length())
		data := nfgen.ToWireFormat()
		data = append(data, attr.ToWireFormat()...)
		data = append(data, config.ToWireFormat()...)

		netlinkMsg := &syscall.NetlinkMessage{
			Header: *hdr,
			Data:   data,
		}

		if nl.Socket != nil {
			err := nl.Socket.query(netlinkMsg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ReadLogs -- Listen for logs on the current socket
func (nl *NfLog) ReadLogs() {

	defer nl.NFlogClose()
	buffer := make([]byte, 65536)

	for {
		s, _, err := nl.Syscalls.Recvfrom(nl.Socket.getFd(), buffer, 0)

		if err != nil {
			if nl.errorCallback != nil {
				nl.errorCallback(fmt.Errorf("Netlink error %v", err))
			}
			if err == syscall.ENOBUFS {
				continue
			}
			return
		}
		err = nl.parseLog(buffer[:s])
		if err != nil {
			if nl.errorCallback != nil {
				nl.errorCallback(fmt.Errorf("Parse error %v", err))
			}
		}
	}
}

// parseLog -- parse the log and call parsePacket
func (nl *NfLog) parseLog(buffer []byte) error {

	for len(buffer) > 0 {
		reader := bytes.NewReader(buffer)

		var header syscall.NlMsghdr
		binary.Read(reader, binary.LittleEndian, &header)

		msgLen := header.Len

		if msgLen > uint32(len(buffer)) {
			return fmt.Errorf("Message was truncated")
		}

		if header.Type == ((common.NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET) {
			err := nl.parsePacket(buffer[16 : msgLen-1])
			if err != nil {
				return fmt.Errorf("Failed to parse NFPacket: %v", err)
			}
		}
		buffer = buffer[msgLen:]
	}

	return nil
}

// parsePacket -- parse packet and set callback for any further processing
func (nl *NfLog) parsePacket(buffer []byte) error {
	reader := bytes.NewReader(buffer)

	var header nflogHeader
	binary.Read(reader, binary.LittleEndian, &header)

	var m NfPacket

	var tlvHeader nflogTlv
	for reader.Len() != 0 {
		err := binary.Read(reader, binary.LittleEndian, &tlvHeader)
		if err != nil {
			return err
		}

		payloadLen := tlvHeader.Len - 4

		switch tlvHeader.Type {
		case NFULA_PREFIX:
			payload := make([]byte, NfaAlign16(payloadLen))
			reader.Read(payload)
			m.Prefix = string(payload[:payloadLen-1])
		case NFULA_PAYLOAD:
			payload := make([]byte, NfaAlign16(payloadLen))
			reader.Read(payload)
			ipPacket := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
			ipLayer := ipPacket.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				m.SrcIP = ip.SrcIP
				m.DstIP = ip.DstIP
				m.Version = ip.Version
				m.Protocol = ip.Protocol
				m.Length = ip.Length
			}
			if m.Protocol.String() == "UDP" {
				udpLayer := ipPacket.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					m.SrcPort = int(udp.SrcPort)
					m.DstPort = int(udp.DstPort)
				}
			} else if m.Protocol.String() == "TCP" {
				tcpLayer := ipPacket.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					m.SrcPort = int(tcp.SrcPort)
					m.DstPort = int(tcp.DstPort)
				}
			}
			m.Payload = payload[:payloadLen]

			nl.callback(&NfPacket{
				Payload:       m.Payload,
				IPLayer:       m.IPLayer,
				Ports:         m.Ports,
				Prefix:        m.Prefix,
				PacketPayload: m.PacketPayload,
				NflogHandle:   nl,
			}, nil)

		default:
			reader.Seek(int64(NfaAlign16(payloadLen)), io.SeekCurrent)
		}
	}

	return nil
}

// GetNFloghandle -- Get the nflog handle created
func (nl *NfLog) GetNFloghandle() NFLog {

	return nl.NflogHandle
}

// NFlogClose -- close the current socket
func (nl *NfLog) NFlogClose() {
	if nl.Socket != nil {
		nl.Socket.close()
	}
}
