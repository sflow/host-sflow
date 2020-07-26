/* Map to general categories using glob patterns */
/* TODO: May have to look carefully to see which symbols
   represent real drops, and not just other kinds of
   packet trap. */
/* Drops are captured in the kfree_skbuf() kernel fn,
   which is called from ~600 places. We may need to go
   through them all. Protocols like rose, bluetooth,
   espintcp, hostap, ... */
HSP_DROPPOINT(*=,tcp_*,unknown_l4)
HSP_DROPPOINT(*=,udp_*,unknown_l4)
HSP_DROPPOINT(*=,__udp4_*,unknown_l4)
HSP_DROPPOINT(*=,__udp6_*,unknown_l4)
HSP_DROPPOINT(*=,icmp_*,unknown_l4)
HSP_DROPPOINT(*=,icmpv6_*,unknown_l4)
HSP_DROPPOINT(*=,ip_*,unknown_l3)
HSP_DROPPOINT(*=,ipv4_*,unknown_l3)
HSP_DROPPOINT(*=,ip6_*,unknown_l3)
HSP_DROPPOINT(*=,ipv6_*,unknown_l3)
HSP_DROPPOINT(*=,br_*,unknown_l2)
HSP_DROPPOINT(*=,__br_*,unknown_l2)

