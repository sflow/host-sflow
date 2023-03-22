/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */
/* Assign mappings from netlink trap-name to sFlow drop-reason (from sflow_drop.h)
   The order of precendence is:
   (1) == lookup on trap-name
   (3) *= lookup (case-insensitive glob-pattern) on trap-name

   If the lookup fails or maps to an empty drop-reason, the trap is disregarded, and will
   not be sent out with the sFlow feed. */

/* Drops are captured in the kfree_skbuf() kernel fn,  which is called from over 600 places,
   but starting in Linux Kernel 6.1 a drop enum can be supplied there too. It is defined in
   the kernel include file net/dropreason.h.
*/

/* TODO: confirm that NOT_DROPPED_YET and NOT_SPECIFIED appear like this */
HSP_DROPPOINT(==,NOT_DROPPED_YET,)
HSP_DROPPOINT(==,NOT_SPECIFIED,unknown)

/* TODO map these into sFlow drop enum */
HSP_DROPPOINT(==,NO_SOCKET,port_unreachable)
HSP_DROPPOINT(==,PKT_TOO_SMALL,unknown)
HSP_DROPPOINT(==,TCP_CSUM,unknown)
HSP_DROPPOINT(==,SOCKET_FILTER,unknown)
HSP_DROPPOINT(==,UDP_CSUM,unknown)
HSP_DROPPOINT(==,NETFILTER_DROP,unknown)
HSP_DROPPOINT(==,OTHERHOST,unknown)
HSP_DROPPOINT(==,IP_CSUM,unknown)
HSP_DROPPOINT(==,IP_INHDR,unknown)
HSP_DROPPOINT(==,IP_RPFILTER,unknown)
HSP_DROPPOINT(==,UNICAST_IN_L2_MULTICAST,unknown)
HSP_DROPPOINT(==,XFRM_POLICY,unknown)
HSP_DROPPOINT(==,IP_NOPROTO,unknown)
HSP_DROPPOINT(==,SOCKET_RCVBUFF,unknown)
HSP_DROPPOINT(==,PROTO_MEM,unknown)
HSP_DROPPOINT(==,TCP_MD5NOTFOUND,unknown)
HSP_DROPPOINT(==,TCP_MD5UNEXPECTED,unknown)
HSP_DROPPOINT(==,TCP_MD5FAILURE,unknown)
HSP_DROPPOINT(==,SOCKET_BACKLOG,unknown)
HSP_DROPPOINT(==,TCP_FLAGS,unknown)
HSP_DROPPOINT(==,TCP_ZEROWINDOW,unknown)
HSP_DROPPOINT(==,TCP_OLD_DATA,unknown)
HSP_DROPPOINT(==,TCP_OVERWINDOW,unknown)
HSP_DROPPOINT(==,TCP_OFOMERGE,unknown)
HSP_DROPPOINT(==,TCP_RFC7323_PAWS,unknown)
HSP_DROPPOINT(==,TCP_INVALID_SEQUENCE,unknown)
HSP_DROPPOINT(==,TCP_RESET,unknown)
HSP_DROPPOINT(==,TCP_INVALID_SYN,unknown)
HSP_DROPPOINT(==,TCP_CLOSE,unknown)
HSP_DROPPOINT(==,TCP_FASTOPEN,unknown)
HSP_DROPPOINT(==,TCP_OLD_ACK,unknown)
HSP_DROPPOINT(==,TCP_TOO_OLD_ACK,unknown)
HSP_DROPPOINT(==,TCP_ACK_UNSENT_DATA,unknown)
HSP_DROPPOINT(==,TCP_OFO_QUEUE_PRUNE,unknown)
HSP_DROPPOINT(==,TCP_OFO_DROP,unknown)
HSP_DROPPOINT(==,IP_OUTNOROUTES,unknown)
HSP_DROPPOINT(==,BPF_CGROUP_EGRESS,unknown)
HSP_DROPPOINT(==,IPV6DISABLED,unknown)
HSP_DROPPOINT(==,NEIGH_CREATEFAIL,unknown)
HSP_DROPPOINT(==,NEIGH_FAILED,unknown)
HSP_DROPPOINT(==,NEIGH_QUEUEFULL,unknown)
HSP_DROPPOINT(==,NEIGH_DEAD,unknown)
HSP_DROPPOINT(==,TC_EGRESS,unknown)
HSP_DROPPOINT(==,QDISC_DROP,unknown)
HSP_DROPPOINT(==,CPU_BACKLOG,unknown)
HSP_DROPPOINT(==,XDP,unknown)
HSP_DROPPOINT(==,TC_INGRESS,unknown)
HSP_DROPPOINT(==,UNHANDLED_PROTO,unknown)
HSP_DROPPOINT(==,SKB_CSUM,unknown)
HSP_DROPPOINT(==,SKB_GSO_SEG,unknown)
HSP_DROPPOINT(==,SKB_UCOPY_FAULT,unknown)
HSP_DROPPOINT(==,DEV_HDR,unknown)
HSP_DROPPOINT(==,DEV_READY,unknown)
HSP_DROPPOINT(==,FULL_RING,unknown)
HSP_DROPPOINT(==,NOMEM,unknown)
HSP_DROPPOINT(==,HDR_TRUNC,unknown)
HSP_DROPPOINT(==,TAP_FILTER,unknown)
HSP_DROPPOINT(==,TAP_TXFILTER,unknown)
HSP_DROPPOINT(==,ICMP_CSUM,unknown)
HSP_DROPPOINT(==,INVALID_PROTO,unknown)
HSP_DROPPOINT(==,IP_INADDRERRORS,unknown)
HSP_DROPPOINT(==,IP_INNOROUTES,unknown)
HSP_DROPPOINT(==,PKT_TOO_BIG,unknown)
HSP_DROPPOINT(==,DUP_FRAG,unknown)
HSP_DROPPOINT(==,FRAG_REASM_TIMEOUT,unknown)
HSP_DROPPOINT(==,FRAG_TOO_FAR,unknown)
HSP_DROPPOINT(==,TCP_MINTTL,unknown)
HSP_DROPPOINT(==,IPV6_BAD_EXTHDR,unknown)
HSP_DROPPOINT(==,IPV6_NDISC_FRAG,unknown)
HSP_DROPPOINT(==,IPV6_NDISC_HOP_LIMIT,unknown)
HSP_DROPPOINT(==,IPV6_NDISC_BAD_CODE,unknown)
HSP_DROPPOINT(==,IPV6_NDISC_BAD_OPTIONS,unknown)
HSP_DROPPOINT(==,IPV6_NDISC_NS_OTHERHOST,unknown)
// accept anything else as unknown
HSP_DROPPOINT(*=,*,unknown)
