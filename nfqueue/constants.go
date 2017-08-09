//nolint
package nfqueue

import (
	"syscall"
	"unsafe"
)

const (
	//NfDefaultPacketSize   the maximum size packet to expect on queue
	NfDefaultPacketSize = 0xffff
	//NFQNL_ATTR = Netfilter Queue Netink atttributes

	//NfqaUnspec  unspecified
	NfqaUnspec nfqaAttr = 0x0
	//NfqaPacketHdr  Attr header for Packet payload
	NfqaPacketHdr nfqaAttr = 0x1
	//NfqaVerdictHdr  Attr header for verdict payload
	NfqaVerdictHdr uint16 = 0x2 /* nfqnlmsg_verdict_hrd */
	//NfqaMark  Attr Header for Mark Payload
	NfqaMark nfqaAttr = 0x3 /* u_int32_t nfmark */
	//NfqaTimestamp  header for timestamp payload
	NfqaTimestamp nfqaAttr = 0x4 /* nfqnl_msg_packet_timestamp */
	//NfqaIfindexIndev -- Ifindex for in device payload
	NfqaIfindexIndev nfqaAttr = 0x5 /* u_int32_t ifindex */
	//NfqaIfindexOutdev -- Ifindex for out device payload
	NfqaIfindexOutdev nfqaAttr = 0x6 /* u_int32_t ifindex */
	//NfqaIfindexPhysindev -- Physical Device
	NfqaIfindexPhysindev nfqaAttr = 0x7 /* u_int32_t ifindex */
	//NfqaIfindexPhysoutdev -- Physical Device
	NfqaIfindexPhysoutdev nfqaAttr = 0x8 /* u_int32_t ifindex */
	//NfqaHwaddr -- Hardware Address
	NfqaHwaddr nfqaAttr = 0x9 /* nfqnl_msg_packet_hw */
	//NfqaPayload -- Packet Payload
	NfqaPayload nfqaAttr = 0xa /* opaque data payload */
	//unexported max
	nfqaMax nfqaAttr = 0xb

	//NfqnlCfgCmdnone -- None
	NfqnlCfgCmdnone nfqConfigCommands = 0x0
	//NfqnlCfgCmdBind -- queue bind command
	NfqnlCfgCmdBind nfqConfigCommands = 0x1
	//NfqnlCfgCmdUnbind -- queue unbind command
	NfqnlCfgCmdUnbind nfqConfigCommands = 0x2
	//NfqnlCfgCmdPfBind -- bind family
	NfqnlCfgCmdPfBind nfqConfigCommands = 0x3
	//NfqnlCfgCmdPfUnbind -- unbind family
	NfqnlCfgCmdPfUnbind nfqConfigCommands = 0x4

	//NfqnlCopyNone -- Copy no packet bytes to userspace
	NfqnlCopyNone nfqConfigMode = 0x0
	//NfqnlCopyMeta -- Copy only metadata
	NfqnlCopyMeta nfqConfigMode = 0x1
	//NfqnlCopyPacket -- Copy packet bytes specified by Range
	NfqnlCopyPacket nfqConfigMode = 0x2

	SizeofMsgConfigCommand = 0x4

	SizeOfNfqMsgConfigParams uint32 = uint32(unsafe.Sizeof(NfqMsgConfigParams{}))
	//SizeOfNfqMsgConfigQueueLen -- Sizeof NfqMsgConfigQueueLen
	SizeOfNfqMsgConfigQueueLen uint32 = uint32(unsafe.Sizeof(NfqMsgConfigQueueLen{}))
	//SizeofNfqMsgVerdictHdr -- Sizeof verdict hdr struct
	SizeofNfqMsgVerdictHdr uint32 = 0x8
	//SizeofNfqMsgMarkHdr -- sizeof mark hdr
	SizeofNfqMsgMarkHdr = 0x4
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

)
