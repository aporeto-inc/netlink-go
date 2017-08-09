//nolint

package nflog

import "unsafe"

// See linux/netfilter/nfnetlink_log.h

// enum nfulnl_msg_types
const (
	NFULNL_MSG_PACKET = iota
	NFULNL_MSG_CONFIG
	NFULNL_MSG_MAX
)

// enum nfulnl_msg_config_cmds
const (
	NFULNL_CFG_CMD_NONE = iota
	NFULNL_CFG_CMD_BIND
	NFULNL_CFG_CMD_UNBIND
	NFULNL_CFG_CMD_PF_BIND
	NFULNL_CFG_CMD_PF_UNBIND
)

const (
	NFULNL_COPY_NONE = iota
	NFULNL_COPY_META
	NFULNL_COPY_PACKET
)

// enum nfulnl_attr_config
const (
	NFULA_CFG_UNSPEC   = iota
	NFULA_CFG_CMD      /* nfulnl_msg_config_cmd */
	NFULA_CFG_MODE     /* nfulnl_msg_config_mode */
	NFULA_CFG_NLBUFSIZ /* __u32 buffer size */
	NFULA_CFG_TIMEOUT  /* __u32 in 1/100 s */
	NFULA_CFG_QTHRESH  /* __u32 */
	NFULA_CFG_FLAGS    /* __u16 */
)

// enum nfulnl_attr_type
const (
	NFULA_UNSPEC = iota
	NFULA_PACKET_HDR
	NFULA_MARK               /* __u32 nfmark */
	NFULA_TIMESTAMP          /* nfulnl_msg_packet_timestamp */
	NFULA_IFINDEX_INDEV      /* __u32 ifindex */
	NFULA_IFINDEX_OUTDEV     /* __u32 ifindex */
	NFULA_IFINDEX_PHYSINDEV  /* __u32 ifindex */
	NFULA_IFINDEX_PHYSOUTDEV /* __u32 ifindex */
	NFULA_HWADDR             /* nfulnl_msg_packet_hw */
	NFULA_PAYLOAD            /* opaque data payload */
	NFULA_PREFIX             /* string prefix */
	NFULA_UID                /* user id of socket */
	NFULA_SEQ                /* instance-local sequence number */
	NFULA_SEQ_GLOBAL         /* global sequence number */
	NFULA_GID                /* group id of socket */
	NFULA_HWTYPE             /* hardware type */
	NFULA_HWHEADER           /* hardware header */
	NFULA_HWLEN              /* hardware header length */
	NFULA_CT                 /* nf_conntrack_netlink.h */
	NFULA_CT_INFO            /* enum ip_conntrack_info */
)
const (
	SizeofMsgConfigCommand = 0x4

	SizeofMsgConfigMode uint32 = uint32(unsafe.Sizeof(NflMsgConfigMode{}))
)
