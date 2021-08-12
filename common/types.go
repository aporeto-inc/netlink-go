// +build linux !darwin

// nolint
package common

import (
	"syscall"

	"go.aporeto.io/netlink-go/common/syscallwrappers"
)

//Types for various enums needed by the nfqueue subsys in linux
type msgTypes int
type nfqaAttr int
type nfqConfigCommands uint8

//NlmFlags -- The flags passed to NlMsgHdr
type NlmFlags uint32

//We will write a method to serialize these messages into a byte slice. So so need to be packed

//NfqMsgPacketHdr PacketHdr
//packetID --  unique ID of packet in queue
//hwProtocol -- hw protocol (network order)
//hook -- netfilter hook
//lint complains -- uncomment when needed
// type NfqMsgPacketHdr struct {
// 	packetID   uint32
// 	hwProtocol uint16
// 	hook       uint8
// }

//Not needed for our usecase

//NfqMsgPacketHwAddress -- HwAddress
//lint complains -- uncomment when needed
// type NfqMsgPacketHwAddress struct { //nolint: structcheck
// 	hwAddrLen uint16
// 	_pad      uint16 //nolint
// 	hwaddr    [8]uint8
// }

//NfqMsgVerdictHdr -- Verdict Hdr struct
//verdict -- accept/drop
//id -- packetid
type NfqMsgVerdictHdr struct {
	verdict uint32
	id      uint32
}

//NfqMsgMarkHdr -- Mark Payload
//mark -- markval
type NfqMsgMarkHdr struct {
	mark uint32
}

//NfqMsgVerdictPayload -- unused
// type NfqMsgVerdictPayload struct { //nolint: structcheck
// 	iovecs []syscall.Iovec
// }

//NfqMsgConfigCommand -- config command
//Command -- the config command
//pf -- family
type NfqMsgConfigCommand struct {
	Command nfqConfigCommands
	_pad    uint8 //nolint
	pf      uint16
}

//NfqMsgConfigParams -- Config params
//copyRange -- Range of bytes to copy
//copyMode -- copyMode meta/none/packet
type NfqMsgConfigParams struct {
	copyRange uint32
	copyMode  uint8
}

//NfqMsgConfigQueueLen -- Queue length
//queueLen -- The length of queue
type NfqMsgConfigQueueLen struct {
	queueLen uint32
}

//SockHandles -- Sock handle of netlink socket
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

/*
struct inet_diag_req_v2 {
        __u8    sdiag_family;
        __u8    sdiag_protocol;
        __u8    idiag_ext;
        __u8    pad;
        __u32   idiag_states;
        struct inet_diag_sockid id;
};

*/

type be16 [2]byte
type be32 [4]byte

// InetDiagSockId is the inet_diag_sockid struct as defined in inet_diag.h
//
// struct inet_diag_sockid {
// 	__be16  idiag_sport;
// 	__be16  idiag_dport;
// 	__be32  idiag_src[4];
// 	__be32  idiag_dst[4];
// 	__u32   idiag_if;
// 	__u32   idiag_cookie[2];
// #define INET_DIAG_NOCOOKIE (~0U)
// };
//
type InetDiagSockId struct {
	IDiagSport  be16
	IDiagDport  be16
	IDiagSrc    [4]be32
	IDiagDst    [4]be32
	IDiagIf     uint32
	IDiagCookie [2]uint32
}

// InetDiagReqV2 is the inet_diag_req_v2 struct as defined in inet_diag.h
//
// struct inet_diag_req_v2 {
// 	__u8    sdiag_family;
// 	__u8    sdiag_protocol;
// 	__u8    idiag_ext;
// 	__u8    pad;
// 	__u32   idiag_states;
// 	struct inet_diag_sockid id;
// };
//
type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	Id            InetDiagSockId
}

// InetDiagMsg is the inet_diag_msg struct as defined in inet_diag.h
//
// struct inet_diag_msg {
// 	__u8    idiag_family;
// 	__u8    idiag_state;
// 	__u8    idiag_timer;
// 	__u8    idiag_retrans;

// 	struct inet_diag_sockid id;

// 	__u32   idiag_expires;
// 	__u32   idiag_rqueue;
// 	__u32   idiag_wqueue;
// 	__u32   idiag_uid;
// 	__u32   idiag_inode;
// };
//
type InetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	Id           InetDiagSockId
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUid     uint32
	IDiagInode   uint32
}

//NfqGenMsg -- the nfgen msg structure
//nfGenFamily -- Family
//version -- netlink version
//resId -- queueNum in big endian format
type NfqGenMsg struct {
	nfgenFamily uint8
	version     uint8
	resID       uint16
}

//NfAttr -- attr struct header
//nfaLen -- sizeof struct + payload
//nfaType --  nfaType
type NfAttr struct {
	nfaLen  uint16
	nfaType uint16
}

//NfValue8 -- uint8 type attribute structure
//value -- the value for a uint8 type attribute
type NfValue8 struct {
	value uint8
}

//NfValue16 -- uint16 type attribute structure
//value -- the value for a uint16 type attribute
type NfValue16 struct {
	value uint16
}

//NfValue32 -- uint32 type attribute structure
//value -- the value for a uint32 type attribute
type NfValue32 struct {
	value uint32
}

//NfAttrResponsePayload -- Response of attr from netlink
//attr -- NfAttr
//data -- payload for response
type NfAttrResponsePayload struct {
	//attr *NfAttr
	data []byte
}

// NfAttrSlice is an array of attributes
type NfAttrSlice [nfqaMax]NfAttrResponsePayload

//NfqNetlinkRequest -- netlink request to send
//NlMsgHdr fields
//serialized data of structure passed to netlink
type NfqNetlinkRequest struct {
	syscall.NlMsghdr
	Data []byte
}

// SelnlMsgSetenforce is the selnl_msg_setenforce struct
type SelnlMsgSetenforce struct {
	Val int32
}

// SelnlMsgPolicyload is the selnl_msg_policyload struct
type SelnlMsgPolicyload struct {
	Seqno uint32
}
