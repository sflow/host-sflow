/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

/* See https://www.kernel.org/doc/html/latest/networking/devlink/devlink-trap.html */

/* Assign mappings from netlink trap-group or trap-name to sFlow drop-reason (from sflow_drop.h)
   The order of precendence is:
   (1) == lookup on trap-name
   (2) == lookup on trap-group
   (3) *= lookup (case-insensitive glob-pattern) on trap-name

   If the lookup fails or maps to an empty drop-reason, the trap is disregarded, and will
   not be sent out with the sFlow feed. */

/* fallback lookup is by group */
HSP_DROPPOINT(==,acl_drops,acl)
HSP_DROPPOINT(==,l2_drops,unknown_l2)
HSP_DROPPOINT(==,l3_drops,unknown_l3)
HSP_DROPPOINT(==,l3_exceptions,unknown_l3_exception)
HSP_DROPPOINT(==,tunnel_drops,unknown_tunnel)
HSP_DROPPOINT(==,buffer_drops,unknown_buffer)

/* Some groups are not considered drops. We
   can leave them out, or indicate they should
   be ignored by using a blank reason code name.*/
HSP_DROPPOINT(==,stp,)
HSP_DROPPOINT(==,lacp,)
HSP_DROPPOINT(==,lldp,)
HSP_DROPPOINT(==,mc_snooping,)
HSP_DROPPOINT(==,dhcp,)
HSP_DROPPOINT(==,neigh_discovery,)
HSP_DROPPOINT(==,bfd,)
HSP_DROPPOINT(==,ospf,)
HSP_DROPPOINT(==,bgp,)
HSP_DROPPOINT(==,vrrp,)
HSP_DROPPOINT(==,pim,)
HSP_DROPPOINT(==,uc_loopback,)
HSP_DROPPOINT(==,local_delivery,)
HSP_DROPPOINT(==,external_delivery,)
HSP_DROPPOINT(==,ipv6,)
HSP_DROPPOINT(==,ptp_event,)
HSP_DROPPOINT(==,ptp_general,)
HSP_DROPPOINT(==,acl_sample,)
HSP_DROPPOINT(==,acl_trap,)
HSP_DROPPOINT(==,parser_error_drops,)
HSP_DROPPOINT(==,eapol,)

/* known trap-names */
HSP_DROPPOINT(==,source_mac_is_multicast,src_mac_is_multicast)                        /* DROP: Traps incoming packets that the device decided to drop because
											 of a multicast source MAC */
HSP_DROPPOINT(==,vlan_tag_mismatch,vlan_tag_mismatch)                                 /* DROP: Traps incoming packets that the device decided to drop in case
											 of VLAN tag mismatch: The ingress bridge port is not configured with
											 a PVID and the packet is untagged or prio-tagged */
HSP_DROPPOINT(==,ingress_vlan_filter,ingress_vlan_filter)                             /* DROP: Traps incoming packets that the device decided to drop in case
											 they are tagged with a VLAN that is not configured on the ingress
											 bridge port */
HSP_DROPPOINT(==,ingress_spanning_tree_filter,ingress_spanning_tree_filter)           /* DROP: Traps incoming packets that the device decided to drop in case
											 the STP state of the ingress bridge port is not “forwarding” */
HSP_DROPPOINT(==,port_list_is_empty,port_list_is_empty)                               /* DROP: Traps packets that the device decided to drop in case they
											 need to be flooded (e.g., unknown unicast, unregistered multicast)
											 and there are no ports the packets should be flooded to */
HSP_DROPPOINT(==,port_loopback_filter,port_loopback_filter)                           /* DROP: Traps packets that the device decided to drop in case after
											 layer 2 forwarding the only port from which they should be
											 transmitted through is the port from which they were received */
HSP_DROPPOINT(==,blackhole_route,blackhole_route)                                     /* DROP: Traps packets that the device decided to drop in case they hit
											 a blackhole route */
HSP_DROPPOINT(==,ttl_value_is_too_small,ttl_exceeded)                                 /* EXCEPTION: Traps unicast packets that should be forwarded by the
											 device whose TTL was decremented to 0 or less */
HSP_DROPPOINT(==,tail_drop,no_buffer_space)                                           /* DROP: Traps packets that the device decided to drop because they
											 could not be enqueued to a transmission queue which is full */
HSP_DROPPOINT(==,non_ip,non_ip)                                                       /* DROP: Traps packets that the device decided to drop because they
											 need to undergo a layer 3 lookup, but are not IP or MPLS packets */
HSP_DROPPOINT(==,uc_dip_over_mc_dmac,uc_dip_over_mc_dmac)                             /* DROP: Traps packets that the device decided to drop because they
											 need to be routed and they have a unicast destination IP and a
											 multicast destination MAC */
HSP_DROPPOINT(==,dip_is_loopback_address,dip_is_loopback_address)                     /* DROP: Traps packets that the device decided to drop because they
											 need to be routed and their destination IP is the loopback address
											 (i.e., 127.0.0.0/8 and ::1/128) */
HSP_DROPPOINT(==,sip_is_mc,sip_is_mc)                                                 /* DROP: Traps packets that the device decided to drop because they
											 need to be routed and their source IP is multicast
											 (i.e., 224.0.0.0/8 and ff::/8) */
HSP_DROPPOINT(==,sip_is_loopback_address,sip_is_loopback_address)                     /* DROP: Traps packets that the device decided to drop because they
											 need to be routed and their source IP is the loopback address
											 (i.e., 127.0.0.0/8 and ::1/128) */
HSP_DROPPOINT(==,ip_header_corrupted,ip_header_corrupted)                             /* DROP: Traps packets that the device decided to drop because they
											 need to be routed and their IP header is corrupted: wrong checksum,
											 wrong IP version or too short Internet Header Length (IHL) */
HSP_DROPPOINT(==,ipv4_sip_is_limited_bc,ipv4_sip_is_limited_bc)                       /* DROP: Traps packets that the device decided to drop because they
											 need to be routed and their source IP is limited broadcast
											 (i.e., 255.255.255.255/32) */
HSP_DROPPOINT(==,ipv6_mc_dip_reserved_scope,ipv6_mc_dip_reserved_scope)               /* DROP: Traps IPv6 packets that the device decided to drop because
											 they need to be routed and their IPv6 multicast destination IP has
											 a reserved scope (i.e., ffx0::/16) */
HSP_DROPPOINT(==,ipv6_mc_dip_interface_local_scope,ipv6_mc_dip_interface_local_scope) /* DROP: Traps IPv6 packets that the device decided to drop because
											 they need to be routed and their IPv6 multicast destination IP has
											 an interface-local scope (i.e., ffx1::/16) */
HSP_DROPPOINT(==,mtu_value_is_too_small,pkt_too_big)                                  /* EXCEPTION: Traps packets that should have been routed by the device,
											 but were bigger than the MTU of the egress interface */
HSP_DROPPOINT(==,unresolved_neigh,unresolved_neigh)                                   /* EXCEPTION: Traps packets that did not have a matching IP neighbour
											 after routing */
HSP_DROPPOINT(==,mc_reverse_path_forwarding,mc_reverse_path_forwarding)               /* EXCEPTION: Traps multicast IP packets that failed reverse-path
											 forwarding (RPF) check during multicast routing */
HSP_DROPPOINT(==,reject_route,dst_net_prohibited)                                     /* EXCEPTION: Traps packets that hit reject routes
											 (i.e., “unreachable”, “prohibit”) */
HSP_DROPPOINT(==,ipv4_lpm_miss,dst_net_unknown)                                       /* EXCEPTION: Traps unicast IPv4 packets that did not match any route */
HSP_DROPPOINT(==,ipv6_lpm_miss,dst_net_unknown)                                       /* EXCEPTION: Traps unicast IPv6 packets that did not match any route */
HSP_DROPPOINT(==,non_routable_packet,non_routable_packet)                             /* DROP: Traps packets that the device decided to drop because they
											 are not supposed to be routed. For example, IGMP queries can be
											 flooded by the device in layer 2 and reach the router. Such packets
											 should not be routed and instead dropped */
HSP_DROPPOINT(==,decap_error,decap_error)                                             /* EXCEPTION: Traps NVE and IPinIP packets that the device decided to
											 drop because of failure during decapsulation (e.g., packet being
											 too short, reserved bits set in VXLAN header) */
HSP_DROPPOINT(==,overlay_smac_is_mc,overlay_smac_is_mc)                               /* DROP: Traps NVE packets that the device decided to drop because
											 their overlay source MAC is multicast */
HSP_DROPPOINT(==,ingress_flow_action_drop,acl)                                        /* DROP: Traps packets dropped during processing of ingress flow action
											 drop */
HSP_DROPPOINT(==,egress_flow_action_drop,acl)                                         /* DROP: Traps packets dropped during processing of egress flow action
											 drop */

HSP_DROPPOINT(==,sip_is_unspecified,sip_is_unspecified)          /* L3_DROPS: Source IP is unspecified */
HSP_DROPPOINT(==,mlag_port_isolation,mlag_port_isolation)        /* L2_DROPS: MLAG port isolation */
HSP_DROPPOINT(==,blackhole_arp_neigh,blackhole_arp_neigh)        /* L3_DROPS: Blackhole ARP/neighbor */
HSP_DROPPOINT(==,src_mac_is_dmac,src_mac_is_dmac)                /* L2_DROPS: Source MAC equals Destination MAC */
HSP_DROPPOINT(==,dmac_is_reserved,dmac_is_reserved)              /* L2_DROPS: Destination MAC is reserved (DNAC=01-80-C2-00-00-0x) */
HSP_DROPPOINT(==,sip_is_class_e,sip_is_class_e)                  /* L3_DROPS: Source IP is in class E */
HSP_DROPPOINT(==,mc_dmac_mismatch,mc_dmac_mismatch)              /* L3_DROPS: Multicast MAC mismatch */
HSP_DROPPOINT(==,sip_is_dip,sip_is_dip)                          /* L3_DROPS: Source IP equals Destination IP */
HSP_DROPPOINT(==,dip_is_local_network,dip_is_local_network)      /* L3_DROPS: Destination IP is local network (destination=0.0.0.0/8) */
HSP_DROPPOINT(==,dip_is_link_local,dip_is_link_local)            /* L3_DROPS: Destination IP is link local */
HSP_DROPPOINT(==,overlay_smac_is_dmac,overlay_smac_is_dmac)      /* TUNNEL_DROPS: Overlay switch - Source MAC equals Destination MAC */

/* CONTROL traps are not considered drops */

// key ignored at group level:
// HSP_DROPPOINT(==,stp,)                          /* CONTROL: Traps STP packets */
// HSP_DROPPOINT(==,lacp,)                         /* CONTROL: Traps LACP packets */
// HSP_DROPPOINT(==,lldp,)                         /* CONTROL: Traps LLDP packets */
HSP_DROPPOINT(==,igmp_query,)                   /* CONTROL: Traps IGMP Membership Query packets */
HSP_DROPPOINT(==,igmp_v1_report,)               /* CONTROL: Traps IGMP Version 1 Membership Report packets */
HSP_DROPPOINT(==,igmp_v2_report,)               /* CONTROL: Traps IGMP Version 2 Membership Report packets */
HSP_DROPPOINT(==,igmp_v3_report,)               /* CONTROL: Traps IGMP Version 3 Membership Report packets */
HSP_DROPPOINT(==,igmp_v2_leave,)                /* CONTROL: Traps IGMP Version 2 Leave Group packets */
HSP_DROPPOINT(==,mld_query,)                    /* CONTROL: Traps MLD Multicast Listener Query packets */
HSP_DROPPOINT(==,mld_v1_report,)                /* CONTROL: Traps MLD Version 1 Multicast Listener Report packets */
HSP_DROPPOINT(==,mld_v2_report,)                /* CONTROL: Traps MLD Version 2 Multicast Listener Report packets */
HSP_DROPPOINT(==,mld_v1_done,)                  /* CONTROL: Traps MLD Version 1 Multicast Listener Done packets */
HSP_DROPPOINT(==,ipv4_dhcp,)                    /* CONTROL: Traps IPv4 DHCP packets */
HSP_DROPPOINT(==,ipv6_dhcp,)                    /* CONTROL: Traps IPv6 DHCP packets */
HSP_DROPPOINT(==,arp_request,)                  /* CONTROL: Traps ARP request packets */
HSP_DROPPOINT(==,arp_response,)                 /* CONTROL: Traps ARP response packets */
HSP_DROPPOINT(==,arp_overlay,)                  /* CONTROL: Traps NVE-decapsulated ARP packets that reached the overlay network. This is required, for example,
						   when the address that needs to be resolved is a local address */
HSP_DROPPOINT(==,ipv6_neigh_solicit,)           /* CONTROL: Traps IPv6 Neighbour Solicitation packets */
HSP_DROPPOINT(==,ipv6_neigh_advert,)            /* CONTROL: Traps IPv6 Neighbour Advertisement packets */
HSP_DROPPOINT(==,ipv4_bfd,)                     /* CONTROL: Traps IPv4 BFD packets */
HSP_DROPPOINT(==,ipv6_bfd,)                     /* CONTROL: Traps IPv6 BFD packets */
HSP_DROPPOINT(==,ipv4_ospf,)                    /* CONTROL: Traps IPv4 OSPF packets */
HSP_DROPPOINT(==,ipv6_ospf,)                    /* CONTROL: Traps IPv6 OSPF packets */
HSP_DROPPOINT(==,ipv4_bgp,)                     /* CONTROL: Traps IPv4 BGP packets */
HSP_DROPPOINT(==,ipv6_bgp,)                     /* CONTROL: Traps IPv6 BGP packets */
HSP_DROPPOINT(==,ipv4_vrrp,)                    /* CONTROL: Traps IPv4 VRRP packets */
HSP_DROPPOINT(==,ipv6_vrrp,)                    /* CONTROL: Traps IPv6 VRRP packets */
HSP_DROPPOINT(==,ipv4_pim,)                     /* CONTROL: Traps IPv4 PIM packets */
HSP_DROPPOINT(==,ipv6_pim,)                     /* CONTROL: Traps IPv6 PIM packets */
/* HSP_DROPPOINT(==,uc_loopback,) */            /* CONTROL: Traps unicast packets that need to be routed through the same layer 3 interface from which they
						   were received. Such packets are routed by the kernel, but also cause it to potentially generate ICMP
						   redirect packets */
HSP_DROPPOINT(==,local_route,)                  /* CONTROL: Traps unicast packets that hit a local route and need to be locally delivered */
HSP_DROPPOINT(==,external_route,)               /* CONTROL: Traps packets that should be routed through an external interface (e.g., management interface)
						   that does not belong to the same device (e.g., switch ASIC) as the ingress interface */
HSP_DROPPOINT(==,ipv6_uc_dip_link_local_scope,) /* CONTROL: Traps unicast IPv6 packets that need to be routed and have a destination IP address with a
						   link-local scope (i.e., fe80::/10). The trap allows device drivers to avoid programming link-local routes,
						   but still receive packets for local delivery */
HSP_DROPPOINT(==,ipv6_dip_all_nodes,)           /* CONTROL: Traps IPv6 packets that their destination IP address is the “All Nodes Address” (i.e., ff02::1) */
HSP_DROPPOINT(==,ipv6_dip_all_routers,)         /* CONTROL: Traps IPv6 packets that their destination IP address is the “All Routers Address” (i.e., ff02::2) */
HSP_DROPPOINT(==,ipv6_router_solicit,)          /* CONTROL: Traps IPv6 Router Solicitation packets */
HSP_DROPPOINT(==,ipv6_router_advert,)           /* CONTROL: Traps IPv6 Router Advertisement packets */
HSP_DROPPOINT(==,ipv6_redirect,)                /* CONTROL: Traps IPv6 Redirect Message packets */
HSP_DROPPOINT(==,ipv4_router_alert,)            /* CONTROL: Traps IPv4 packets that need to be routed and include the Router Alert option. Such packets need
						  to be locally delivered to raw sockets that have the IP_ROUTER_ALERT socket option set */
HSP_DROPPOINT(==,ipv6_router_alert,)            /* CONTROL: Traps IPv6 packets that need to be routed and include the Router Alert option in their Hop-by-Hop
					 	  extension header. Such packets need to be locally delivered to raw sockets that have the IPV6_ROUTER_ALERT
						  socket option set */
// key ignored at group level:
// HSP_DROPPOINT(==,ptp_event,)                    /* CONTROL: Traps PTP time-critical event messages (Sync, Delay_req, Pdelay_Req and Pdelay_Resp) */
// HSP_DROPPOINT(==,ptp_general,)                  /* CONTROL: Traps PTP general messages (Announce, Follow_Up, Delay_Resp, Pdelay_Resp_Follow_Up, management
//						      and signaling) */
// HSP_DROPPOINT(==,eapol,)                        /* CONTROL: Traps “Extensible Authentication Protocol over LAN” (EAPOL) packets specified in IEEE 802.1X */

HSP_DROPPOINT(==,flow_action_sample,)           /* CONTROL: Traps packets sampled during processing of flow action sample (e.g., via tc’s sample action) */
HSP_DROPPOINT(==,flow_action_trap,)             /* CONTROL: Traps packets logged during processing of flow action trap (e.g., via tc’s trap action) */

HSP_DROPPOINT(==,early_drop,red)                      /* DROP: Traps packets dropped due to the RED (Random Early Detection) algorithm (i.e., early drops) */
HSP_DROPPOINT(==,vxlan_parsing,vxlan_parsing)         /* DROP: Traps packets dropped due to an error in the VXLAN header parsing which might be because of packet
							 truncation or the I flag is not set. */
HSP_DROPPOINT(==,llc_snap_parsing,llc_snap_parsing)   /* DROP: Traps packets dropped due to an error in the LLC+SNAP header parsing */
HSP_DROPPOINT(==,vlan_parsing,vlan_parsing)           /* DROP: Traps packets dropped due to an error in the VLAN header parsing. Could include unexpected
							 packet truncation. */
HSP_DROPPOINT(==,pppoe_ppp_parsing,pppoe_ppp_parsing) /* DROP: Traps packets dropped due to an error in the PPPoE+PPP header parsing. This could include
							 finding a session ID of 0xFFFF (which is reserved and not for use), a PPPoE length which is larger
							 than the frame received or any common error on this type of header */
HSP_DROPPOINT(==,mpls_parsing,mpls_parsing)           /* DROP: Traps packets dropped due to an error in the MPLS header parsing which could include unexpected
							 header truncation */
HSP_DROPPOINT(==,arp_parsing,arp_parsing)             /* DROP: Traps packets dropped due to an error in the ARP header parsing */
HSP_DROPPOINT(==,ip_1_parsing,ip_1_parsing)           /* DROP: Traps packets dropped due to an error in the first IP header parsing. This packet trap could
							 include packets which do not pass an IP checksum check, a header length check (a minimum of 20 bytes),
							 which might suffer from packet truncation thus the total length field exceeds the received packet
							 length etc. */
HSP_DROPPOINT(==,ip_n_parsing,ip_n_parsing)           /* DROP: Traps packets dropped due to an error in the parsing of the last IP header (the inner one in
							 case of an IP over IP tunnel). The same common error checking is performed here as for the
							 ip_1_parsing trap */
HSP_DROPPOINT(==,gre_parsing,gre_parsing)             /* DROP: Traps packets dropped due to an error in the GRE header parsing */
HSP_DROPPOINT(==,udp_parsing,udp_parsing)             /* DROP: Traps packets dropped due to an error in the UDP header parsing. This packet trap could
							 include checksum errors,an improper UDP length detected (smaller than 8 bytes) or detection of
							 header truncation. */
HSP_DROPPOINT(==,tcp_parsing,tcp_parsing)             /* DROP: Traps packets dropped due to an error in the TCP header parsing. This could include TCP
							 checksum errors, improper combination of SYN, FIN and/or RESET etc. */
HSP_DROPPOINT(==,ipsec_parsing,ipsec_parsing)         /* DROP: Traps packets dropped due to an error in the IPSEC header parsing */
HSP_DROPPOINT(==,sctp_parsing,sctp_parsing)           /* DROP: Traps packets dropped due to an error in the SCTP header parsing. This would mean that port
							 number 0 was used or that the header is truncated. */
HSP_DROPPOINT(==,dccp_parsing,dccp_parsing)           /* DROP: Traps packets dropped due to an error in the DCCP header parsing */
HSP_DROPPOINT(==,gtp_parsing,gtp_parsing)             /* DROP: Traps packets dropped due to an error in the GTP header parsing */
HSP_DROPPOINT(==,esp_parsing,esp_parsing)             /* DROP: Traps packets dropped due to an error in the ESP header parsing */
HSP_DROPPOINT(==,blackhole_nexthop,blackhole_nexthop) /* DROP: Traps packets that the device decided to drop in case they hit a blackhole nexthop */
HSP_DROPPOINT(==,dmac_filter,dmac_filter)             /* DROP: Traps incoming packets that the device decided to drop because the destination MAC is not
							 configured in the MAC table and the interface is not in promiscuous mode */
HSP_DROPPOINT(==,locked_port,locked_port)             /* DROP: Traps packets that the device decided to drop because they failed the locked bridge port
							 check. That is, packets that were received via a locked port and whose {SMAC, VID} does not
							 correspond to an FDB entry pointing to the port */

/* report anything else with reason "unknown" */
// HSP_DROPPOINT(*=,*,unknown)
