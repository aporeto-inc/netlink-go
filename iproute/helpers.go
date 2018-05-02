package iproute

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
)

func priorityAttrToWire(priority uint32) []byte {
	buf := make([]byte, syscall.SizeofRtAttr+unsafe.Sizeof(priority))

	common.NativeEndian().PutUint16(buf, syscall.SizeofRtAttr+uint16(unsafe.Sizeof(priority)))
	common.NativeEndian().PutUint16(buf[2:], RTA_PRIORITY)
	common.NativeEndian().PutUint32(buf[4:], (priority))
	return buf
}

func markAttrToWire(mark uint32) []byte {
	buf := make([]byte, syscall.SizeofRtAttr+unsafe.Sizeof(mark))

	common.NativeEndian().PutUint16(buf, syscall.SizeofRtAttr+uint16(unsafe.Sizeof(mark)))
	common.NativeEndian().PutUint16(buf[2:], RTA_MARK)
	common.NativeEndian().PutUint32(buf[4:], mark)
	return buf
}

func markMaskAttrToWire(mask uint32) []byte {
	buf := make([]byte, syscall.SizeofRtAttr+unsafe.Sizeof(mask))

	common.NativeEndian().PutUint16(buf, syscall.SizeofRtAttr+uint16(unsafe.Sizeof(mask)))
	common.NativeEndian().PutUint16(buf[2:], RTA_MARK_MASK)
	common.NativeEndian().PutUint32(buf[4:], mask)
	return buf
}
func rtmsgToWire(family uint8, Table uint8, Protocol uint8, Type uint8) []byte {
	/*type RtMsg struct {
		Family   uint8
		Dst_len  uint8
		Src_len  uint8
		Tos      uint8
		Table    uint8
		Protocol uint8
		Scope    uint8
		Type     uint8
		Flags    uint32
	}*/
	buf := make([]byte, syscall.SizeofRtMsg)
	buf[0] = byte(syscall.AF_INET)
	buf[4] = Table
	buf[5] = Protocol
	buf[7] = Type
	return buf
}

func ipgwToWire(ip net.IP) []byte {
	buf := make([]byte, syscall.SizeofRtAttr+4)
	common.NativeEndian().PutUint16(buf, syscall.SizeofRtAttr+uint16(4))
	common.NativeEndian().PutUint16(buf[2:], RTA_GATEWAY)
	copy(buf[4:], ip.To4())
	return buf
}

func ipifindexToWire(index uint32) []byte {
	buf := make([]byte, syscall.SizeofRtAttr+unsafe.Sizeof(index))
	common.NativeEndian().PutUint16(buf, syscall.SizeofRtAttr+uint16(unsafe.Sizeof(index)))
	common.NativeEndian().PutUint16(buf[2:], RTA_OIF)
	common.NativeEndian().PutUint32(buf[4:], uint32(index))

	return buf
}

func send(buf []byte) error {
	fd, err := syscallwrappers.NewSyscalls().Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	lsa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}
	var n int
	if err = syscallwrappers.NewSyscalls().Bind(fd, lsa); err != nil {
		return fmt.Errorf("Error %s while binding netlink socket", err)
	}
	if err = syscallwrappers.NewSyscalls().Sendto(fd, buf, 0, lsa); err != nil {
		return fmt.Errorf("Error %s while sending on netlink socket", err)
	}
	if n, _, err = syscallwrappers.NewSyscalls().Recvfrom(fd, buf, 0); err == nil {
		hdr, next, _ := common.NetlinkMessageToStruct(buf[:n+1])
		if hdr.Type == common.NlMsgError {
			_, nerr := common.NetlinkErrMessagetoStruct(next)
			if nerr.Error != 0 {
				return fmt.Errorf("Netlink Returned errror %d", nerr.Error)
			}
		}
		return nil
	}
	return fmt.Errorf("Error %s while receiving on netlink socket", err)

}
