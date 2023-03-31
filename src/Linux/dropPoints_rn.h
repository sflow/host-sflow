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
HSP_DROPPOINT(==,PKT_TOO_SMALL,pkt_too_small)
HSP_DROPPOINT(==,TCP_CSUM,tcp_parsing)
HSP_DROPPOINT(==,SOCKET_FILTER,socket_filter)
HSP_DROPPOINT(==,UDP_CSUM,udp_parsing)
HSP_DROPPOINT(==,NETFILTER_DROP,acl)
HSP_DROPPOINT(==,OTHERHOST,dst_host_unknown)
HSP_DROPPOINT(==,IP_CSUM,ip_1_parsing)
HSP_DROPPOINT(==,IP_INHDR,ip_1_parsing)
HSP_DROPPOINT(==,IP_RPFILTER,reverse_path_forwarding)
HSP_DROPPOINT(==,UNICAST_IN_L2_MULTICAST,uc_dip_over_mc_dmac)
HSP_DROPPOINT(==,XFRM_POLICY,xfrm_policy)
HSP_DROPPOINT(==,IP_NOPROTO,protocol_unreachable)
HSP_DROPPOINT(==,SOCKET_RCVBUFF,no_buffer_space)
HSP_DROPPOINT(==,PROTO_MEM,no_buffer_space)
HSP_DROPPOINT(==,TCP_MD5NOTFOUND,tcp_md5notfound)
HSP_DROPPOINT(==,TCP_MD5UNEXPECTED,tcp_md5unexpected)
HSP_DROPPOINT(==,TCP_MD5FAILURE,tcp_md5failure)
HSP_DROPPOINT(==,SOCKET_BACKLOG,no_buffer_space)
HSP_DROPPOINT(==,TCP_FLAGS,tcp_flags)
HSP_DROPPOINT(==,TCP_ZEROWINDOW,tcp_zerowindow)
HSP_DROPPOINT(==,TCP_OLD_DATA,tcp_old_data)
HSP_DROPPOINT(==,TCP_OVERWINDOW,tcp_overwindow)
HSP_DROPPOINT(==,TCP_OFOMERGE,tcp_ofomerge)
HSP_DROPPOINT(==,TCP_RFC7323_PAWS,tcp_rfc7323_paws)
HSP_DROPPOINT(==,TCP_INVALID_SEQUENCE,tcp_invalid_sequence)
HSP_DROPPOINT(==,TCP_RESET,tcp_reset)
HSP_DROPPOINT(==,TCP_INVALID_SYN,tcp_invalid_syn)
HSP_DROPPOINT(==,TCP_CLOSE,tcp_close)
HSP_DROPPOINT(==,TCP_FASTOPEN,tcp_fastopen)
HSP_DROPPOINT(==,TCP_OLD_ACK,tcp_old_ack)
HSP_DROPPOINT(==,TCP_TOO_OLD_ACK,tcp_too_old_ack)
HSP_DROPPOINT(==,TCP_ACK_UNSENT_DATA,tcp_ack_unsent_data)
HSP_DROPPOINT(==,TCP_OFO_QUEUE_PRUNE,tcp_ofo_queue_prune)
HSP_DROPPOINT(==,TCP_OFO_DROP,tcp_ofo_drop)
HSP_DROPPOINT(==,IP_OUTNOROUTES,dst_net_unknown)
HSP_DROPPOINT(==,BPF_CGROUP_EGRESS,bpf_cgroup_egress)
HSP_DROPPOINT(==,IPV6DISABLED,ipv6disabled)
HSP_DROPPOINT(==,NEIGH_CREATEFAIL,unresolved_neigh)
HSP_DROPPOINT(==,NEIGH_FAILED,unresolved_neigh)
HSP_DROPPOINT(==,NEIGH_QUEUEFULL,unresolved_neigh)
HSP_DROPPOINT(==,NEIGH_DEAD,unresolved_neigh)
HSP_DROPPOINT(==,TC_EGRESS,tc_egress)
HSP_DROPPOINT(==,QDISC_DROP,traffic_shaping)
HSP_DROPPOINT(==,CPU_BACKLOG,cpu_backlog)
HSP_DROPPOINT(==,XDP,xdp)
HSP_DROPPOINT(==,TC_INGRESS,tc_ingress)
HSP_DROPPOINT(==,UNHANDLED_PROTO,unhandled_proto)
HSP_DROPPOINT(==,SKB_CSUM,skb_csum)
HSP_DROPPOINT(==,SKB_GSO_SEG,skb_gso_seg)
HSP_DROPPOINT(==,SKB_UCOPY_FAULT,skb_ucopy_fault)
HSP_DROPPOINT(==,DEV_HDR,dev_hdr)
HSP_DROPPOINT(==,DEV_READY,dev_ready)
HSP_DROPPOINT(==,FULL_RING,no_buffer_space)
HSP_DROPPOINT(==,NOMEM,no_buffer_space)
HSP_DROPPOINT(==,HDR_TRUNC,pkt_too_small)
HSP_DROPPOINT(==,TAP_FILTER,tap_filter)
HSP_DROPPOINT(==,TAP_TXFILTER,tap_txfilter)
HSP_DROPPOINT(==,ICMP_CSUM,icmp_parsing)
HSP_DROPPOINT(==,INVALID_PROTO,invalid_proto)
HSP_DROPPOINT(==,IP_INADDRERRORS,host_unreachable)
HSP_DROPPOINT(==,IP_INNOROUTES,net_unreachable)
HSP_DROPPOINT(==,PKT_TOO_BIG,pkt_too_big)
HSP_DROPPOINT(==,DUP_FRAG,dup_frag)
HSP_DROPPOINT(==,FRAG_REASM_TIMEOUT,frag_needed)
HSP_DROPPOINT(==,FRAG_TOO_FAR,frag_needed)
HSP_DROPPOINT(==,TCP_MINTTL,tcp_minttl)
HSP_DROPPOINT(==,IPV6_BAD_EXTHDR,ipv6_bad_exthdr)
HSP_DROPPOINT(==,IPV6_NDISC_FRAG,ipv6_ndisc_frag)
HSP_DROPPOINT(==,IPV6_NDISC_HOP_LIMIT,ipv6_ndisc_hop_limit)
HSP_DROPPOINT(==,IPV6_NDISC_BAD_CODE,ipv6_ndisc_bad_code)
HSP_DROPPOINT(==,IPV6_NDISC_BAD_OPTIONS,ipv6_ndisc_bad_options)
HSP_DROPPOINT(==,IPV6_NDISC_NS_OTHERHOST,ipv6_ndisc_ns_otherhost)
// accept anything else as unknown
HSP_DROPPOINT(*=,*,unknown)
