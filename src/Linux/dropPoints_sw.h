/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */
/* Assign mappings from netlink trap-name to sFlow drop-reason (from sflow_drop.h)
   The order of precendence is:
   (1) == lookup on trap-name
   (3) *= lookup (case-insensitive glob-pattern) on trap-name

   If the lookup fails or maps to an empty drop-reason, the trap is disregarded, and will
   not be sent out with the sFlow feed. */

/* TODO: May have to look carefully to see which symbols
   represent real drops, and not just other kinds of
   packet trap. */
/* Drops are captured in the kfree_skbuf() kernel fn,
   which is called from over 600 places. We may need to go
   through them all. Protocols like rose, bluetooth,
   espintcp, hostap, ... */
HSP_DROPPOINT(*=,tcp_*,unknown_l4)
HSP_DROPPOINT(*=,udp_*,unknown_l4)
HSP_DROPPOINT(*=,__udp4_*,unknown_l4)
HSP_DROPPOINT(*=,__udp6_*,unknown_l4)
HSP_DROPPOINT(*=,icmp_*,unknown_l3)
HSP_DROPPOINT(*=,icmpv6_*,unknown_l3)
HSP_DROPPOINT(*=,ip_*,unknown_l3)
HSP_DROPPOINT(*=,ipv4_*,unknown_l3)
HSP_DROPPOINT(*=,ip6_*,unknown_l3)
HSP_DROPPOINT(*=,ipv6_*,unknown_l3)
HSP_DROPPOINT(*=,raw_*,unknown_l3)
HSP_DROPPOINT(*=,rawv6_*,unknown_l3)
HSP_DROPPOINT(*=,br_*,unknown_l2)
HSP_DROPPOINT(*=,__br_*,unknown_l2)
HSP_DROPPOINT(*=,sk_stream_kill_queues*,) /* see https://patchwork.ozlabs.org/project/netdev/patch/20141120185829.986CB290095D@tardy/ */
HSP_DROPPOINT(*=,skb_release_data*,) /* normal fragmentation/reassembly. See https://github.com/nhorman/dropwatch/issues/3 */
HSP_DROPPOINT(*=,skb_queue_purge*,) /* normal socket teardown */
HSP_DROPPOINT(*=,*,unknown)
