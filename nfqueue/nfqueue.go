package nfqueue

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/aporeto-inc/netlink-go/common"
	"github.com/aporeto-inc/netlink-go/common/syscallwrappers"
)

//General structure of all message passed to nfnetlink for netlink.h in kernel
/* ========================================================================
 *         Netlink Messages and Attributes Interface (As Seen On lxr)
 * ------------------------------------------------------------------------
 *                          Messages Interface
 * ------------------------------------------------------------------------
 *
 * Message Format:
 *    <--- nlmsg_total_size(payload)  --->
 *    <-- nlmsg_msg_size(payload) ->
 *   +----------+- - -+-------------+- - -+-------- - -
 *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
 *   +----------+- - -+-------------+- - -+-------- - -
 *   nlmsg_data(nlh)---^                   ^
 *   nlmsg_next(nlh)-----------------------+
 *
 * Payload Format:
 *    <---------------------- nlmsg_len(nlh) --------------------->
 *    <---nfgen hdrlen ----->       <- nlmsg_attrlen(nlh, hdrlen) ->
 *                                 <-----------  nfaLen ----------->
 *                                 <-------- 4 bytes |data -------->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 */

//NFPacket -- message format sent on channel
type NFPacket struct {
	Buffer      []byte
	Mark        int
	Xbuffer     []byte
	QueueHandle *NfQueue
	ID          int
}

//NfQueue Struct to hold global val for all instances of netlink socket
type NfQueue struct {
	SubscribedSubSys    uint32
	QueueNum            uint16
	callback            func(buf *NFPacket, data interface{})
	errorCallback       func(err error, data interface{})
	privateData         interface{}
	queueHandle         SockHandle
	NotificationChannel chan *NFPacket
	buf                 []byte
	nfattrresponse      []*common.NfAttrResponsePayload
	hdrSlice            []byte
	Syscalls            syscallwrappers.Syscalls
}

var native binary.ByteOrder

//NewNFQueue -- create a new NfQueue handle
func NewNFQueue() NFQueue {
	nfqueueinit()
	n := &NfQueue{
		Syscalls:            syscallwrappers.NewSyscalls(),
		NotificationChannel: make(chan *NFPacket, 100),
		buf:                 make([]byte, common.NfnlBuffSize),
		nfattrresponse:      make([]*common.NfAttrResponsePayload, nfqaMax),
		hdrSlice:            make([]byte, int(syscall.SizeofNlMsghdr)+int(common.SizeofNfGenMsg)+int(common.NfaLength(uint16(SizeofNfqMsgVerdictHdr)))+int(common.NfaLength(uint16(SizeofNfqMsgMarkHdr)))),
	}

	for i := 0; i < int(nfqaMax); i++ {
		n.nfattrresponse[i] = common.SetNetlinkData(common.NfnlBuffSize)
	}

	return n
}

//CreateAndStartNfQueue -- Wrapper to create/bind to queue set all its params and start listening for packets.
//queueID -- the queue to create/bind
//maxPacketsInQueue -- max number of packets in Queue
//packetSize -- The max expected packetsize
//privateData -- We will return this on NFpacket.Opaque data for this system.
func CreateAndStartNfQueue(queueID uint16, maxPacketsInQueue uint32, packetSize uint32, callback func(*NFPacket, interface{}), errorCallback func(err error, data interface{}), privateData interface{}) (Verdict, error) {

	queuingHandle := NewNFQueue()

	var err error
	if _, err = queuingHandle.NfqOpen(); err != nil {
		return nil, fmt.Errorf("Error opening NFQueue handle: %v ", err)
	}
	if err := queuingHandle.UnbindPf(); err != nil {
		queuingHandle.NfqClose()
		return nil, fmt.Errorf("Error unbinding existing NFQ handler from AfInet protocol family: %v ", err)
	}
	if err := queuingHandle.BindPf(); err != nil {
		queuingHandle.NfqClose()
		return nil, fmt.Errorf("Error binding to AfInet protocol family: %v ", err)
	}

	if err := queuingHandle.CreateQueue(queueID, callback, errorCallback, privateData); err != nil {
		queuingHandle.NfqClose()
		return nil, fmt.Errorf("Error binding to queue: %v ", err)
	}
	if err := queuingHandle.NfqSetMode(NfqnlCopyPacket, packetSize); err != nil {
		queuingHandle.NfqDestroyQueue()
		queuingHandle.NfqClose()
		return nil, fmt.Errorf("Unable to set packets copy mode: %v ", err)
	}
	if err := queuingHandle.NfqSetQueueMaxLen(maxPacketsInQueue); err != nil {
		queuingHandle.NfqDestroyQueue()
		queuingHandle.NfqClose()
		return nil, fmt.Errorf("Unable to set max packets in queue: %v ", err)
	}
	go queuingHandle.ProcessPackets()
	return queuingHandle, nil
}

//NfqOpen Open a new netlink socket
//Create a new queue handle and return the handle
//Open a new socket and return it in the NfqHandle.
//The fd for the socket is stored in an unexported handle
func (q *NfQueue) NfqOpen() (SockHandle, error) {
	nfqHandle := &NfqSockHandle{Syscalls: q.Syscalls, buf: q.buf}
	q.SubscribedSubSys |= (0x1 << common.NFQUEUESUBSYSID)
	fd, err := q.Syscalls.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	nfqHandle.fd = fd
	nfqHandle.rcvbufSize = common.NfnlBuffSize

	nfqHandle.lsa.Family = syscall.AF_NETLINK
	err = q.Syscalls.Bind(fd, &nfqHandle.lsa)
	if err != nil {
		return nil, err
	}
	opt := 1
	sockrcvbuf := 500 * int(common.NfnlBuffSize)
	q.Syscalls.SetsockoptInt(fd, common.SolNetlink, syscall.NETLINK_NO_ENOBUFS, opt)
	q.Syscalls.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockrcvbuf)
	q.Syscalls.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockrcvbuf)
	//This is a hunch it looks like the kernel does not support this flag for netlink socket
	//Will need to try if this is honored from a path i did not see af_netlink.c
	lingerconf := &syscall.Linger{
		Onoff:  1,
		Linger: 0,
	}
	syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER, lingerconf)
	q.queueHandle = nfqHandle
	return nfqHandle, nil
}

//query : Allows a send and a block until ack is received.
//Returns an error is Send Failed or netlink returned an error
//This is called with a Qhandle is a private function for the package
func (qh *NfqSockHandle) query(msg *syscall.NetlinkMessage) error {

	err := qh.send(msg)
	if err != nil {
		return err
	}
	return qh.recv()
}

func (qh *NfqSockHandle) getFd() int {
	return qh.fd
}

func (qh *NfqSockHandle) getRcvBufSize() uint32 {
	return qh.rcvbufSize

}

func (qh *NfqSockHandle) getLocalAddress() syscall.SockaddrNetlink {
	return qh.lsa
}

func (qh *NfqSockHandle) close() {
	qh.Syscalls.Close(qh.fd)
}

//recv --- private function to receive message on the socket corresponding to this queue.
// Returns an error is recvfrom errors or netlink returns an error message
func (qh *NfqSockHandle) recv() error {
	buf := qh.buf
	n, _, err := qh.Syscalls.Recvfrom(qh.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("Recvfrom returned error %v", err)
	}
	hdr, next, _ := common.NetlinkMessageToStruct(buf[:n+1])

	if hdr.Type == common.NlMsgError {
		_, err := common.NetlinkErrMessagetoStruct(next)
		if err.Error != 0 {
			return fmt.Errorf("Netlink Returned errror %d", err.Error)
		}
	}

	return nil

}

//send -- private function to send messages over the socket for this queue
//returns an error if Sendto Fails
func (qh *NfqSockHandle) send(msg *syscall.NetlinkMessage) error {
	buf := make([]byte, syscall.SizeofNlMsghdr+len(msg.Data))

	native.PutUint32(buf[0:4], msg.Header.Len)
	native.PutUint16(buf[4:6], msg.Header.Type)
	native.PutUint16(buf[6:8], msg.Header.Flags)
	native.PutUint32(buf[8:12], msg.Header.Seq)
	native.PutUint32(buf[12:16], msg.Header.Pid)
	copy(buf[16:], msg.Data)
	return qh.Syscalls.Sendto(qh.fd, buf, 0, &qh.lsa)

}

//UnbindPf -- passes an unbind command to nfnetlink for AF_INET.
func (q *NfQueue) UnbindPf() error {

	config := &NfqMsgConfigCommand{
		Command: NfqnlCfgCmdPfUnbind,
		_pad:    116,
		pf:      syscall.AF_INET, //nolint
	}
	/* NfqnlMsgConfig */
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgConfig,
		common.NlmFRequest|common.NlmFAck,
		0,
	)

	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, 0, hdr)
	attr := common.BuildNfAttrMsg(NfqaCfgCmd, hdr, config.Length())
	data := nfgen.ToWireFormat()
	data = append(data, attr.ToWireFormat()...)
	data = append(data, config.ToWireFormat()...)
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   data,
	}

	if q.queueHandle != nil {
		return q.queueHandle.query(netlinkMsg)
	}
	return fmt.Errorf("NfqOpen was not called. No Socket open")

}

//CreateQueue -- Create a queue
//handle -- handle representing the opne netlink socket
//num -- queue number
//data -- private data associated with the queue
func (q *NfQueue) CreateQueue(num uint16, callback func(*NFPacket, interface{}), errorCallback func(err error, data interface{}), privateData interface{}) error {
	q.QueueNum = num
	q.callback = callback
	q.errorCallback = errorCallback
	q.privateData = privateData
	config := &NfqMsgConfigCommand{
		Command: NfqnlCfgCmdBind, //NFQNL_CFG_CMD_BIND,
		_pad:    0,
		pf:      syscall.AF_UNSPEC,
	}
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgConfig, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, num, hdr)
	attr := common.BuildNfAttrMsg(NfqaCfgCmd, hdr, config.Length())
	nfgenData := nfgen.ToWireFormat()
	nfgenData = append(nfgenData, attr.ToWireFormat()...)
	nfgenData = append(nfgenData, config.ToWireFormat()...)
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   nfgenData,
	}

	if q.queueHandle != nil {
		return q.queueHandle.query(netlinkMsg)
	}
	return fmt.Errorf("NfqOpen was not called. No Socket open")
}

//NfqSetMode -- Set queue mode copynone/copymeta/copypacket
//handle -- handle representing the opne netlink socket
//mode -- Copy mode for this queue
//packetSize -- The range of bytes from packets to copy
func (q *NfQueue) NfqSetMode(mode nfqConfigMode, packetSize uint32) error {
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgConfig, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, q.QueueNum, hdr)
	config := &NfqMsgConfigParams{
		copyMode:  uint8(mode),
		copyRange: packetSize,
	}
	attr := common.BuildNfAttrMsg(NfqaCfgParams, hdr, config.Length())
	nfgenData := nfgen.ToWireFormat()
	nfgenData = append(nfgenData, attr.ToWireFormat()...)
	nfgenData = append(nfgenData, config.ToWireFormat()...)
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   nfgenData,
	}

	if q.queueHandle != nil {
		return q.queueHandle.query(netlinkMsg)
	}
	return fmt.Errorf("NfqOpen was not called. No Socket open")
}

//NfqSetQueueMaxLen -- THe maximum number of packets in queue
//handle -- handle representing the opne netlink socket
//queuelen -- Length of queue
func (q *NfQueue) NfqSetQueueMaxLen(queuelen uint32) error {
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgConfig, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, q.QueueNum, hdr)
	config := &NfqMsgConfigQueueLen{
		queueLen: queuelen,
	}
	attr := common.BuildNfAttrMsg(NfqaCfgQueueMaxLen, hdr, config.Length())
	nfgenData := nfgen.ToWireFormat()
	nfgenData = append(nfgenData, attr.ToWireFormat()...)
	nfgenData = append(nfgenData, config.ToWireFormat()...)
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   nfgenData,
	}

	if q.queueHandle != nil {
		return q.queueHandle.query(netlinkMsg)
	}
	return fmt.Errorf("NfqOpen was not called. No Socket open")
}

//SetVerdict -- SetVerdict on the packet -- accept/drop
func (q *NfQueue) SetVerdict(queueNum uint32, verdict uint32, packetLen uint32, packetID uint32, packet []byte) {
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgVerdict, common.NlmFRequest, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, q.QueueNum, hdr)
	configVerdict := NfqMsgVerdictHdr{
		verdict: verdict,
		id:      packetID,
	}

	verdicthdr := common.BuildNfAttrMsg(NfqaVerdictHdr, hdr, configVerdict.Length())
	iovecLen := hdr.Len

	var payloadnfattr common.NfAttr

	payloadnfattr.SetNfaLen(common.NfaLength(uint16(packetLen)))
	payloadnfattr.SetNfaType(uint16(NfqaPayload))

	payloadnfattrbuf := payloadnfattr.ToWireFormat()
	hdr.Len += uint32(payloadnfattr.GetNfaLen())
	iovec := make([]syscall.Iovec, 3)
	hdrBuf := common.SerializeNlMsgHdr(hdr)
	hdrBuf = append(hdrBuf, nfgen.ToWireFormat()...)
	vedicthdrbuf := append(hdrBuf, verdicthdr.ToWireFormat()...)
	vedicthdrbuf = append(vedicthdrbuf, configVerdict.ToWireFormat()...)

	iovec[0].Base = &vedicthdrbuf[0]
	iovec[0].Len = uint64(iovecLen)

	iovec[1].Base = &payloadnfattrbuf[0]
	iovec[1].Len = uint64(len(payloadnfattrbuf))
	pad := make([]byte, common.NfaAlign(uint16(packetLen))-uint16(packetLen))
	if len(pad) > 0 {
		packet = append(packet, pad...)
	}
	iovec[2].Base = &packet[0]
	iovec[2].Len = uint64(common.NfaAlign(uint16(packetLen)))
	q.sendmsg(q.queueHandle.getFd(), iovec)
}

//SetVerdict2 -- SetVerdict on the packet -- accept/drop also mark
func (q *NfQueue) SetVerdict2(queueNum uint32, verdict uint32, mark uint32, packetLen uint32, packetID uint32, packet []byte) {
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgVerdict, common.NlmFRequest, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, q.QueueNum, hdr)

	configVerdict := NfqMsgVerdictHdr{
		verdict: verdict,
		id:      packetID,
	}
	configMark := NfqMsgMarkHdr{
		mark: mark,
	}

	verdicthdr := common.BuildNfAttrMsg(NfqaVerdictHdr, hdr, configVerdict.Length())
	markhdr := common.BuildNfAttrMsg(uint16(NfqaMark), hdr, configMark.Length())

	iovecLen := hdr.Len

	var payloadnfattr common.NfAttr

	//payloadnfattr.SetNfaLen(common.NfaLength(uint16(packetLen)))
	payloadnfattr.SetNfaType(uint16(NfqaPayload))

	payloadnfattr.SetNfaLen((uint16(packetLen)) + 4)
	// sliceLength := syscall.SizeofNlMsghdr + SizeofNfGenMsg + uint32(NfaLength(uint16(configVerdict.Length()))) + uint32(NfaLength(uint16(configMark.Length())))
	// hdrSlice := make([]byte, sliceLength)
	hdrSlice := q.hdrSlice
	payloadnfattrbuf := payloadnfattr.ToWireFormat()
	hdr.Len += uint32((payloadnfattr.GetNfaLen()))
	pad := make([]byte, common.NfaAlign(uint16(packetLen))-uint16(packetLen))
	iovec := make([]syscall.Iovec, 3)

	copyIndex := common.SerializeNlMsgHdrBuf(hdr, hdrSlice)
	copyIndex += nfgen.ToWireFormatBuf(hdrSlice[copyIndex:])
	copyIndex += verdicthdr.ToWireFormatBuf(hdrSlice[copyIndex:])
	copyIndex += configVerdict.ToWireFormatBuf(hdrSlice[copyIndex:])
	copyIndex += markhdr.ToWireFormatBuf(hdrSlice[copyIndex:])
	configMark.ToWireFormatBuf(hdrSlice[copyIndex:])

	iovec[0].Base = &hdrSlice[0]
	iovec[0].Len = uint64(iovecLen)

	iovec[1].Base = &payloadnfattrbuf[0]
	iovec[1].Len = uint64(len(payloadnfattrbuf))

	if len(pad) > 0 {
		packet = append(packet, pad...)
	}

	iovec[2].Base = &packet[0]
	iovec[2].Len = uint64((len(packet)))

	q.sendmsg(q.queueHandle.getFd(), iovec)

}

//Recv -- Recv packets from socket and parse them return nfgen and nfattr slices
func (q *NfQueue) Recv() (*common.NfqGenMsg, []*common.NfAttrResponsePayload, error) {
	buf := q.buf
	n, _, err := q.Syscalls.Recvfrom(q.queueHandle.getFd(), buf, syscall.MSG_WAITALL)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to read from socket %v", err)
	}
	hdr, payload, err := common.NetlinkMessageToStruct(buf[:n])

	if hdr.Type == common.NlMsgError {
		_, err := common.NetlinkErrMessagetoStruct(payload)
		if err.Error != 0 {
			return nil, nil, fmt.Errorf("Netlink Returned errror %d", err.Error)
		}
	}
	if err != nil {
		//fmt.Printf("HEader Type %v,Header Length %v Flags %x\n", hdr.Type, hdr.Len, hdr.Flags)
		return nil, nil, fmt.Errorf("Netlink message format invalid : %v", err)
	}
	nfgenmsg, payload, err := common.NetlinkMessageToNfGenStruct(payload)

	if err != nil {
		return nil, nil, fmt.Errorf("NfGen struct format invalid : %v", err)
	}

	nfattrmsg, _, err := common.NetlinkMessageToNfAttrStruct(payload, q.nfattrresponse)

	return nfgenmsg, nfattrmsg, err
}

//ProcessPackets -- Function to wait on socket to receive packets and post it back to channel
func (q *NfQueue) ProcessPackets() {
	for {
		nfgenmsg, attr, err := q.Recv()

		if err != nil {
			if q.errorCallback != nil {
				q.errorCallback(fmt.Errorf("Netlink error %v", err), nfgenmsg)
				continue
			} else {
				fmt.Println("Received Error from netlink", err)
				if nfgenmsg != nil {
					fmt.Println(nfgenmsg.GetNfgenFamily())
				}
			}
		}

		packetid, mark, packet := GetPacketInfo(attr)

		q.callback(&NFPacket{
			Buffer:      packet,
			Mark:        mark,
			QueueHandle: q,
			ID:          packetid,
		}, q.privateData)

	}

}

//BindPf -- Bind to a PF family
func (q *NfQueue) BindPf() error {
	config := &NfqMsgConfigCommand{
		Command: NfqnlCfgCmdPfBind,
		_pad:    0,
		pf:      syscall.AF_INET,
	}
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgConfig, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, 0, hdr)
	attr := common.BuildNfAttrMsg(NfqaCfgCmd, hdr, config.Length())
	data := nfgen.ToWireFormat()
	data = append(data, attr.ToWireFormat()...)
	data = append(data, config.ToWireFormat()...)
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   data,
	}

	if q.queueHandle != nil {
		return q.queueHandle.query(netlinkMsg)
	}
	return fmt.Errorf("NfqOpen was not called. No Socket open")
}

//GetNotificationChannel -- Return a handle to the notification channel
func (q *NfQueue) GetNotificationChannel() chan *NFPacket {
	return q.NotificationChannel
}

//sendmsg -- wrapper around syscall.SYS_SENDMSG. need to populate msgHdr struct
func (q *NfQueue) sendmsg(fd int, iovecs []syscall.Iovec) {
	msg := &syscall.Msghdr{}
	lsa := q.queueHandle.getLocalAddress()
	msg.Name = (*byte)(unsafe.Pointer(&lsa))
	msg.Control = nil
	msg.Controllen = 0
	msg.Namelen = syscall.SizeofSockaddrNetlink
	msg.Iov = &iovecs[0]
	msg.Iovlen = uint64(len(iovecs))
	msg.Flags = 0
	_, _, err := q.Syscalls.Syscall(syscall.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(0))

	if err != 0 {
		fmt.Println("Error", err)
	}
}

//NfqClose -- Close the netlink socket for this queue
func (q *NfQueue) NfqClose() {
	if q.queueHandle != nil {
		q.queueHandle.close()
	}

}

//StopQueue -- Destroy queue and close socket
func (q *NfQueue) StopQueue() error {
	if err := q.NfqDestroyQueue(); err != nil {
		return err
	}
	q.queueHandle.close()
	return nil
}

//NfqDestroyQueue -- unbind queue
func (q *NfQueue) NfqDestroyQueue() error {
	config := &NfqMsgConfigCommand{
		Command: NfqnlCfgCmdUnbind, //NFQNL_CFG_CMD_BIND,
		_pad:    0,
		pf:      syscall.AF_UNSPEC,
	}
	hdr := common.BuildNlMsgHeader(common.NfqnlMsgConfig, common.NlmFRequest|common.NlmFAck, 0)
	nfgen := common.BuildNfgenMsg(syscall.AF_UNSPEC, common.NFNetlinkV0, q.QueueNum, hdr)
	attr := common.BuildNfAttrMsg(NfqaCfgCmd, hdr, config.Length())
	nfgenData := nfgen.ToWireFormat()
	nfgenData = append(nfgenData, attr.ToWireFormat()...)
	nfgenData = append(nfgenData, config.ToWireFormat()...)
	netlinkMsg := &syscall.NetlinkMessage{
		Header: *hdr,
		Data:   nfgenData,
	}
	if q.queueHandle != nil {
		return q.queueHandle.query(netlinkMsg)
	}
	return fmt.Errorf("NfqOpen was not called. No Socket open")
}

func (q *NfQueue) setSockHandle(handle SockHandle) {
	q.queueHandle = handle
}

//nfqueueinit -- Init to discover endianess of the system we are on
func nfqueueinit() {
	if native != nil {
		return
	}
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		native = binary.BigEndian
	} else {
		native = binary.LittleEndian
	}
}
