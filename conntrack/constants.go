package conntrack

import (
	"syscall"
	"unsafe"
)

const (
	//NfDefaultPacketSize   the maximum size packet to expect on queue
	NfDefaultPacketSize = 0xffff
	//NFQUEUESUBSYSID The netlink subsystem id for nfqueue
	NFQUEUESUBSYSID = 0x3
	//SOCKFAMILY  constant for AF_NETLINK
	SOCKFAMILY = syscall.AF_NETLINK
	//SolNetlink  costant for SOL_NETLINK
	SolNetlink = 270 /* syscall.SOL_NETLINK not defined */

	//NFQNL - Netfilter Queue Netink message types

	//NfqnlMsgPacket  packet from kernel to userspace
	NfqnlMsgPacket msgTypes = 0x0
	//NfqnlMsgVerdict verdict from userspace to kernel
	NfqnlMsgVerdict msgTypes = 0x1
	//NfqnlMsgConfig connect to a particular queue
	NfqnlMsgConfig msgTypes = 0x2
	//NfqnlMsgVerdictBatch batch verdict from userspace to kernel
	NfqnlMsgVerdictBatch msgTypes = 0x3
	//unexported max
	//nfqnlMsgMax msgTypes = 0x4 //nodeadcode

	/* Flags values */
	/* from netlink.h*/

	/*NlmFRequest -- It is request message. 	*/
	NlmFRequest NlmFlags = 0x1
	/*NlmFMulti -- Multipart message, terminated by NlMsgDone */
	NlmFMulti NlmFlags = 0x2
	/*NlmFAck -- Reply with ack, with zero or error code */
	NlmFAck NlmFlags = 0x4
	/*NlmFEcho -- Echo this request 		*/
	NlmFEcho NlmFlags = 0x8
	/*NlmFDumpintr --  Dump was inconsistent due to sequence change */
	NlmFDumpintr NlmFlags = 0x10
	/*NlmFDumpFiltered -- Dump was filtered as requested */
	NlmFDumpFiltered NlmFlags = 0x20

	//NfnlBuffSize -- Buffer size of socket
	NfnlBuffSize uint32 = (75 * 1024)
	//NFNetlinkV0 - netlink v0
	NFNetlinkV0 uint8 = 0
	//SizeofMsgConfigCommand -- Sizeof config command struct
	SizeofconntrackMarkStruct = 0x4
	//SizeofNfGenMsg -- Sizeof nfgen msg struct
	SizeofNfGenMsg uint32 = 0x4
	//SizeofNfAttr -- Sizeof nfattr struct
	// This does not account for the size of the byte slice at the end
	SizeofNfAttr uint16 = 0x4

	//APUNSPEC -- PF_UNSPEC/AF_UNSPEC
	APUNSPEC uint8 = syscall.AF_UNSPEC

	//NfqaCfgUnspec -- Unspec
	NfqaCfgUnspec uint32 = 0x0
	//NfqaCfgCmd -- attr config command
	NfqaCfgCmd uint16 = 0x1 /* nfqnl_msg_config_cmd */
	//NfqaCfgParams -- config parameters
	NfqaCfgParams uint16 = 0x2 /* nfqnl_msg_config_params */
	//NfqaCfgQueueMaxLen -- MaxQueuelen
	NfqaCfgQueueMaxLen uint16 = 0x3 /* u_int32_t */
	//NfqaCfgMask -- Mask
	NfqaCfgMask uint32 = 0x4 /* identify which flags to change */
	//NfqaCfgFlags -- Config Flags
	NfqaCfgFlags uint32 = 0x5 /* value of these flags (__u32) */
	//nfqaCfgMax -- unexported max
	//nfqaCfgMax uint32 = 0x6 //nodeadcode

	//NlMsgNoop -- do nothing
	NlMsgNoop = 0x1 /* nothing.		*/
	//NlMsgError -- error message from netlink
	NlMsgError = 0x2 /* error		*/
	//NlMsgDone -- Multi part message done
	NlMsgDone = 0x3 /* end of a dump	*/
	//NlMsgOverrun -- Overrun of buffer
	NlMsgOverrun = 0x4 /* data lost		*/
	//unexported type
	//nlmsgMinType = 0x10 //nodeadcode /* < 0x10: reserved control messages */

	CTA_MARK = 8

	ATTR_MARK = 25

	SizeOfConntrackLength uint32 = uint32(unsafe.Sizeof(conntrackMarkHdr{}))

	SizeOfValue32 uint32 = uint32(unsafe.Sizeof(NfValue32{}))

	SizeOfValue8 uint8 = uint8(unsafe.Sizeof(NfValue8{}))

	SizeOfValue16 uint16 = uint16(unsafe.Sizeof(NfValue16{}))
)
const (
	// backward compatibility with golang 1.6 which does not have io.SeekCurrent
	seekCurrent = 1
)
