// +build linux !darwin
//nolint
package common

import (
	"syscall"
	"unsafe"
)

const (
	nlMsgAlignTo = 4
	nfaAlignTo   = 4
)
const (
	// ConntrackTable Conntrack table
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h -> #define NFNL_SUBSYS_CTNETLINK		 1
	ConntrackTable = 1
	// ConntrackExpectTable Conntrack expect table
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h -> #define NFNL_SUBSYS_CTNETLINK_EXP 2
	ConntrackExpectTable = 2
)
const (
	//NFQUEUESUBSYSID The netlink subsystem id for nfqueue
	NFQUEUESUBSYSID = 0x3
	//SOCKFAMILY  constant for AF_NETLINK
	SOCKFAMILY = syscall.AF_NETLINK
	//SolNetlink  costant for SOL_NETLINK
	SolNetlink = 270 /* syscall.SOL_NETLINK not defined */

	//NFQNL - Netfilter Queue Netink message types

	//NfqnlMsgPacket  packet from kernel to userspace
	NfqnlMsgPacket msgTypes = (NFQUEUESUBSYSID << 8) | 0
	//NfqnlMsgVerdict verdict from userspace to kernel
	NfqnlMsgVerdict msgTypes = (NFQUEUESUBSYSID << 8) | 1
	//NfqnlMsgConfig connect to a particular queue
	NfqnlMsgConfig msgTypes = (NFQUEUESUBSYSID << 8) | 2
	//NfqnlMsgVerdictBatch batch verdict from userspace to kernel
	NfqnlMsgVerdictBatch msgTypes = (NFQUEUESUBSYSID << 8) | 3

	//NFCTNL - Netfilter Conntrack Netink message types
	NfnlConntrackTable msgTypes = (ConntrackTable << 8) | IPCTNL_MSG_CT_NEW

	//NFLOG - Netfilter NFLog message types
	NfnlNFLog msgTypes = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG

	//unexported max
	nfqaMax nfqaAttr = 0xb

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
	SizeofMsgConfigCommand = 0x4
	//SizeofNfGenMsg -- Sizeof nfgen msg struct
	SizeofNfGenMsg uint32 = 0x4
	//SizeofNfAttr -- Sizeof nfattr struct
	// This does not account for the size of the byte slice at the end
	SizeofNfAttr uint16 = 0x4
	//SizeOfNfqMsgConfigParams -- Sizeof NfqMsgConfigParams
	SizeOfNfqMsgConfigParams uint32 = uint32(unsafe.Sizeof(NfqMsgConfigParams{}))
	//SizeOfNfqMsgConfigQueueLen -- Sizeof NfqMsgConfigQueueLen
	SizeOfNfqMsgConfigQueueLen uint32 = uint32(unsafe.Sizeof(NfqMsgConfigQueueLen{}))
	//SizeofNfqMsgVerdictHdr -- Sizeof verdict hdr struct
	SizeofNfqMsgVerdictHdr uint32 = 0x8
	//SizeofNfqMsgMarkHdr -- sizeof mark hdr
	SizeofNfqMsgMarkHdr = 0x4
	//APUNSPEC -- PF_UNSPEC/AF_UNSPEC
	APUNSPEC uint8 = syscall.AF_UNSPEC

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

	SizeOfValue8 uint8 = uint8(unsafe.Sizeof(NfValue8{}))

	SizeOfValue16 uint16 = uint16(unsafe.Sizeof(NfValue16{}))

	SizeOfValue32 uint32 = uint32(unsafe.Sizeof(NfValue32{}))
)

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	IPCTNL_MSG_CT_NEW    = 0
	IPCTNL_MSG_CT_GET    = 1
	IPCTNL_MSG_CT_DELETE = 2
)

// For generic use
const (
	TCP_PROTO = 6
	UDP_PROTO = 17
)

const (
	NFNL_SUBSYS_NONE = iota
	NFNL_SUBSYS_CTNETLINK
	NFNL_SUBSYS_CTNETLINK_EXP
	NFNL_SUBSYS_QUEUE
	NFNL_SUBSYS_ULOG
	NFNL_SUBSYS_OSF
	NFNL_SUBSYS_IPSET
	NFNL_SUBSYS_ACCT
	NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NFNL_SUBSYS_CTHELPER
	NFNL_SUBSYS_NFTABLES
	NFNL_SUBSYS_NFT_COMPAT
	NFNL_SUBSYS_COUNT
)

const (
	NFULNL_MSG_CONFIG = 1
)
