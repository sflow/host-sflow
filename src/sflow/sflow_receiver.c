/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include <assert.h>
#include "sflow_api.h"
#include "sflow_xdr.h"

/*_________________--------------------------__________________
  _________________    sfl_receiver_init     __________________
  -----------------__________________________------------------
*/

void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent) {
  /* first clear everything */
  memset(receiver, 0, sizeof(*receiver));

  /* now copy in the parameters */
  receiver->agent = agent;

  /* set defaults */
  receiver->sFlowRcvrMaximumDatagramSize = SFL_DEFAULT_DATAGRAM_SIZE;
  receiver->sFlowRcvrPort = SFL_DEFAULT_COLLECTOR_PORT;
}

/*_________________--------------------------__________________
  _________________   sfl_receiver_init_sfdg __________________
  -----------------__________________________------------------
*/

void sfl_receiver_init_sfdg(SFLReceiver *receiver)
{
  if(receiver->sfdg)
    SFDFree(receiver->sfdg);
  SFLAgent *agent = receiver->agent;
  receiver->sfdg = SFDNew(sfl_receiver_get_sFlowRcvrMaximumDatagramSize(receiver),
			  sfl_agent_get_address(agent),
			  agent->subId,
			  receiver,
			  agent->sfdg.allocFn,
			  agent->sfdg.freeFn,
			  agent->sfdg.nowFn,
			  agent->sfdg.sendFn,
			  agent->sfdg.errFn,
			  agent->sfdg.hookFn);
}

/*_________________---------------------------__________________
  _________________      reset                __________________
  -----------------___________________________------------------

  called on timeout, or when owner string is cleared
*/

static void reset(SFLReceiver *receiver) {
  // ask agent to tell samplers and pollers to stop sending samples
  sfl_agent_resetReceiver(receiver->agent, receiver);
  // reinitialize
  sfl_receiver_init(receiver, receiver->agent);
}

/*_________________----------------------------------------_____________
  _________________          MIB Vars                      _____________
  -----------------________________________________________-------------
*/

char * sfl_receiver_get_sFlowRcvrOwner(SFLReceiver *receiver) {
  return receiver->sFlowRcvrOwner;
}
void sfl_receiver_set_sFlowRcvrOwner(SFLReceiver *receiver, char *sFlowRcvrOwner) {
  receiver->sFlowRcvrOwner = sFlowRcvrOwner;
  if(sFlowRcvrOwner == NULL || sFlowRcvrOwner[0] == '\0') {
    // reset condition! owner string was cleared
    reset(receiver);
  }
}
time_t sfl_receiver_get_sFlowRcvrTimeout(SFLReceiver *receiver) {
  return receiver->sFlowRcvrTimeout;
}
void sfl_receiver_set_sFlowRcvrTimeout(SFLReceiver *receiver, time_t sFlowRcvrTimeout) {
  receiver->sFlowRcvrTimeout =sFlowRcvrTimeout;
} 
uint32_t sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver) {
  return receiver->sFlowRcvrMaximumDatagramSize;
}
void sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, uint32_t sFlowRcvrMaximumDatagramSize) {
  uint32_t mdz = sFlowRcvrMaximumDatagramSize;
  if(mdz < SFL_MIN_DATAGRAM_SIZE) mdz = SFL_MIN_DATAGRAM_SIZE;
  if(mdz > SFL_MAX_DATAGRAM_SIZE) mdz = SFL_MAX_DATAGRAM_SIZE;
  receiver->sFlowRcvrMaximumDatagramSize = mdz;
}
SFLAddress *sfl_receiver_get_sFlowRcvrAddress(SFLReceiver *receiver) {
  return &receiver->sFlowRcvrAddress;
}
void sfl_receiver_set_sFlowRcvrAddress(SFLReceiver *receiver, SFLAddress *sFlowRcvrAddress) {
  if(sFlowRcvrAddress) receiver->sFlowRcvrAddress = *sFlowRcvrAddress; // structure copy
}
uint32_t sfl_receiver_get_sFlowRcvrPort(SFLReceiver *receiver) {
  return receiver->sFlowRcvrPort;
}
void sfl_receiver_set_sFlowRcvrPort(SFLReceiver *receiver, uint32_t sFlowRcvrPort) {
  receiver->sFlowRcvrPort = sFlowRcvrPort;
}

/*_________________---------------------------__________________
  _________________   sfl_receiver_flush      __________________
  -----------------___________________________------------------
*/

void sfl_receiver_flush(SFLReceiver *receiver)
{
  if(receiver->sfdg)
    SFDSend(receiver->sfdg);
}

/*_________________---------------------------__________________
  _________________   sfl_receiver_tick       __________________
  -----------------___________________________------------------
*/

void sfl_receiver_tick(SFLReceiver *receiver, time_t now)
{
  sfl_receiver_flush(receiver);
  // check the timeout
  if(receiver->sFlowRcvrTimeout && (uint32_t)receiver->sFlowRcvrTimeout != 0xFFFFFFFF) {
    // count down one tick and reset if we reach 0
    if(--receiver->sFlowRcvrTimeout == 0) reset(receiver);
  }
}

/*_________________-------------------------------__________________
  _________________    extra xdr encoding utils   __________________
  -----------------_______________________________------------------
*/

static void xdr_enc_sflstring(SFDBuf *dbuf, SFLString *str) {
  sfd_xdr_enc_str(dbuf, str->str, str->len);
}

/*_________________-------------------------------__________________
  _________________   flow sample elements        __________________
  -----------------_______________________________------------------
*/

static void xdr_enc_hdr(SFDBuf *pktsmp, SFLSampled_header *hdr) {
  sfd_xdr_enc_int32(pktsmp, hdr->header_protocol);
  sfd_xdr_enc_int32(pktsmp, hdr->frame_length);
  sfd_xdr_enc_int32(pktsmp, hdr->stripped);
  sfd_xdr_enc_int32(pktsmp, hdr->header_length);
  sfd_xdr_enc_bytes(pktsmp, hdr->header_bytes, hdr->header_length);
}

static void xdr_enc_ethernet(SFDBuf *pktsmp, SFLSampled_ethernet *eth) {
  sfd_xdr_enc_int32(pktsmp, eth->eth_len);
  sfd_xdr_enc_mac(pktsmp, eth->src_mac);
  sfd_xdr_enc_mac(pktsmp, eth->dst_mac);
  sfd_xdr_enc_int32(pktsmp, eth->eth_type);
}

static void xdr_enc_ipv4(SFDBuf *pktsmp, SFLSampled_ipv4 *ipv4) {
  sfd_xdr_enc_int32(pktsmp, ipv4->length);
  sfd_xdr_enc_int32(pktsmp, ipv4->protocol);
  sfd_xdr_enc_ip4(pktsmp, ipv4->src_ip.addr);
  sfd_xdr_enc_ip4(pktsmp, ipv4->dst_ip.addr);
  sfd_xdr_enc_int32(pktsmp, ipv4->src_port);
  sfd_xdr_enc_int32(pktsmp, ipv4->dst_port);
  sfd_xdr_enc_int32(pktsmp, ipv4->tcp_flags);
  sfd_xdr_enc_int32(pktsmp, ipv4->tos);
}

static void xdr_enc_ipv6(SFDBuf *pktsmp, SFLSampled_ipv6 *ipv6) {
  sfd_xdr_enc_int32(pktsmp, ipv6->length);
  sfd_xdr_enc_int32(pktsmp, ipv6->protocol);
  sfd_xdr_enc_ip6(pktsmp, ipv6->src_ip.addr);
  sfd_xdr_enc_ip6(pktsmp, ipv6->dst_ip.addr);
  sfd_xdr_enc_int32(pktsmp, ipv6->src_port);
  sfd_xdr_enc_int32(pktsmp, ipv6->dst_port);
  sfd_xdr_enc_int32(pktsmp, ipv6->tcp_flags);
  sfd_xdr_enc_int32(pktsmp, ipv6->priority);
}

static void xdr_enc_switch(SFDBuf *pktsmp, SFLExtended_switch *sw) {
  sfd_xdr_enc_int32(pktsmp, sw->src_vlan);
  sfd_xdr_enc_int32(pktsmp, sw->src_priority);
  sfd_xdr_enc_int32(pktsmp, sw->dst_vlan);
  sfd_xdr_enc_int32(pktsmp, sw->dst_priority);
}

static void xdr_enc_router(SFDBuf *pktsmp, SFLExtended_router *rtr) {
  sfd_xdr_enc_ip(pktsmp, &rtr->nexthop);
  sfd_xdr_enc_int32(pktsmp, rtr->src_mask);
  sfd_xdr_enc_int32(pktsmp, rtr->dst_mask);
}

static void xdr_enc_gateway(SFDBuf *pktsmp, SFLExtended_gateway *gw) {
  sfd_xdr_enc_ip(pktsmp, &gw->nexthop);
  sfd_xdr_enc_int32(pktsmp, gw->as);
  sfd_xdr_enc_int32(pktsmp, gw->src_as);
  sfd_xdr_enc_int32(pktsmp, gw->src_peer_as);
  sfd_xdr_enc_int32(pktsmp, gw->dst_as_path_segments);
  for(uint32_t seg = 0; seg < gw->dst_as_path_segments; seg++) {
    uint32_t segType = gw->dst_as_path[seg].type;
    uint32_t segLen = gw->dst_as_path[seg].length;
    sfd_xdr_enc_int32(pktsmp, segType);
    sfd_xdr_enc_int32(pktsmp, segLen);
    sfd_xdr_enc_quads(pktsmp, gw->dst_as_path[seg].as.seq, segLen);
  }
  sfd_xdr_enc_int32(pktsmp, gw->communities_length);
  sfd_xdr_enc_quads(pktsmp, gw->communities, gw->communities_length);
  sfd_xdr_enc_int32(pktsmp, gw->localpref);
}

static void xdr_enc_user(SFDBuf *pktsmp, SFLExtended_user *user) {
  sfd_xdr_enc_int32(pktsmp, user->src_charset);
  xdr_enc_sflstring(pktsmp, &user->src_user);
  sfd_xdr_enc_int32(pktsmp, user->dst_charset);
  xdr_enc_sflstring(pktsmp, &user->dst_user);
}

static void xdr_enc_url(SFDBuf *pktsmp, SFLExtended_url *url) {
  sfd_xdr_enc_int32(pktsmp, url->direction);
  xdr_enc_sflstring(pktsmp, &url->url);
  xdr_enc_sflstring(pktsmp, &url->host);
}

static void xdr_enc_mpls(SFDBuf *pktsmp, SFLExtended_mpls *mpls) {
  sfd_xdr_enc_ip(pktsmp, &mpls->nextHop);
  sfd_xdr_enc_int32(pktsmp, mpls->in_stack.depth);
  sfd_xdr_enc_quads(pktsmp, mpls->in_stack.stack, mpls->in_stack.depth);
  sfd_xdr_enc_int32(pktsmp, mpls->out_stack.depth);
  sfd_xdr_enc_quads(pktsmp, mpls->out_stack.stack, mpls->out_stack.depth);
}

static void xdr_enc_nat(SFDBuf *pktsmp, SFLExtended_nat *nat) {
  sfd_xdr_enc_ip(pktsmp, &nat->src);
  sfd_xdr_enc_ip(pktsmp, &nat->dst);
}

static void xdr_enc_mpls_tunnel(SFDBuf *pktsmp, SFLExtended_mpls_tunnel *tun) {
  xdr_enc_sflstring(pktsmp, &tun->tunnel_lsp_name);
  sfd_xdr_enc_int32(pktsmp, tun->tunnel_id);
  sfd_xdr_enc_int32(pktsmp, tun->tunnel_cos);
}

static void xdr_enc_mpls_vc(SFDBuf *pktsmp, SFLExtended_mpls_vc *vc) {
  xdr_enc_sflstring(pktsmp, &vc->vc_instance_name);
  sfd_xdr_enc_int32(pktsmp, vc->vll_vc_id);
  sfd_xdr_enc_int32(pktsmp, vc->vc_label_cos);
}

static void xdr_enc_mpls_ftn(SFDBuf *pktsmp, SFLExtended_mpls_FTN *ftn) {
  xdr_enc_sflstring(pktsmp, &ftn->mplsFTNDescr);
  sfd_xdr_enc_int32(pktsmp, ftn->mplsFTNMask);
}

static void xdr_enc_mpls_ldp_fec(SFDBuf *pktsmp, SFLExtended_mpls_LDP_FEC *fec) {
  sfd_xdr_enc_int32(pktsmp, fec->mplsFecAddrPrefixLength);
}

static void xdr_enc_vlan_tunnel(SFDBuf *pktsmp, SFLExtended_vlan_tunnel *tun) {
  sfd_xdr_enc_int32(pktsmp, tun->stack.depth);
  sfd_xdr_enc_quads(pktsmp, tun->stack.stack, tun->stack.depth);
}

static void xdr_enc_app_ctxt(SFDBuf *pktsmp, SFLSampled_APP_CTXT *ctxt) {
  xdr_enc_sflstring(pktsmp, &ctxt->application);
  xdr_enc_sflstring(pktsmp, &ctxt->operation);
  xdr_enc_sflstring(pktsmp, &ctxt->attributes);
}

static void xdr_enc_app(SFDBuf *pktsmp, SFLSampled_APP *app) {
  xdr_enc_app_ctxt(pktsmp, &app->context);
  xdr_enc_sflstring(pktsmp, &app->status_descr);
  sfd_xdr_enc_int64(pktsmp, app->req_bytes);
  sfd_xdr_enc_int64(pktsmp, app->resp_bytes);
  sfd_xdr_enc_int32(pktsmp, app->duration_uS);
  sfd_xdr_enc_int32(pktsmp, app->status);
}

static void xdr_enc_socket4(SFDBuf *pktsmp, SFLExtended_socket_ipv4 *soc4) {
  sfd_xdr_enc_int32(pktsmp, soc4->protocol);
  sfd_xdr_enc_ip4(pktsmp, soc4->local_ip.addr);
  sfd_xdr_enc_ip4(pktsmp, soc4->remote_ip.addr);
  sfd_xdr_enc_int32(pktsmp, soc4->local_port);
  sfd_xdr_enc_int32(pktsmp, soc4->remote_port);
}

static void xdr_enc_socket6(SFDBuf *pktsmp, SFLExtended_socket_ipv6 *soc6) {
  sfd_xdr_enc_int32(pktsmp, soc6->protocol);
  sfd_xdr_enc_ip6(pktsmp, soc6->local_ip.addr);
  sfd_xdr_enc_ip6(pktsmp, soc6->remote_ip.addr);
  sfd_xdr_enc_int32(pktsmp, soc6->local_port);
  sfd_xdr_enc_int32(pktsmp, soc6->remote_port);
}

static void xdr_enc_tcp_info(SFDBuf *pktsmp, SFLExtended_TCP_info *tcpi) {
  sfd_xdr_enc_int32(pktsmp, tcpi->dirn);
  sfd_xdr_enc_int32(pktsmp, tcpi->snd_mss);
  sfd_xdr_enc_int32(pktsmp, tcpi->rcv_mss);
  sfd_xdr_enc_int32(pktsmp, tcpi->unacked);
  sfd_xdr_enc_int32(pktsmp, tcpi->lost);
  sfd_xdr_enc_int32(pktsmp, tcpi->retrans);
  sfd_xdr_enc_int32(pktsmp, tcpi->pmtu);
  sfd_xdr_enc_int32(pktsmp, tcpi->rtt);
  sfd_xdr_enc_int32(pktsmp, tcpi->rttvar);
  sfd_xdr_enc_int32(pktsmp, tcpi->snd_cwnd);
  sfd_xdr_enc_int32(pktsmp, tcpi->reordering);
  sfd_xdr_enc_int32(pktsmp, tcpi->min_rtt);
}

static void xdr_enc_entities(SFDBuf *pktsmp, SFLExtended_entities *ent) {
  sfd_xdr_enc_int32(pktsmp, ent->src_dsClass);
  sfd_xdr_enc_int32(pktsmp, ent->src_dsIndex);
  sfd_xdr_enc_int32(pktsmp, ent->dst_dsClass);
  sfd_xdr_enc_int32(pktsmp, ent->dst_dsIndex);
}

static void xdr_enc_hw_trap(SFDBuf *pktsmp, SFLExtended_hw_trap *trp) {
  xdr_enc_sflstring(pktsmp, &trp->group);
  xdr_enc_sflstring(pktsmp, &trp->trap);
}

static int xdr_enc_flow_sample_elements(SFDBuf *pktsmp, SFLFlow_sample_element *elements) {
  int nFound = 0;
  for(SFLFlow_sample_element *elem = elements; elem != NULL; elem = elem->nxt) {
    nFound++;
    sfd_xdr_start_tlv(pktsmp, elem->tag); // start element
    switch(elem->tag) {
    case SFLFLOW_HEADER: xdr_enc_hdr(pktsmp, &elem->flowType.header); break;
    case SFLFLOW_ETHERNET: xdr_enc_ethernet(pktsmp, &elem->flowType.ethernet); break;
    case SFLFLOW_IPV4: xdr_enc_ipv4(pktsmp, &elem->flowType.ipv4); break;
    case SFLFLOW_IPV6: xdr_enc_ipv6(pktsmp, &elem->flowType.ipv6); break;
    case SFLFLOW_EX_SWITCH: xdr_enc_switch(pktsmp, &elem->flowType.sw); break;
    case SFLFLOW_EX_ROUTER: xdr_enc_router(pktsmp, &elem->flowType.router); break;
    case SFLFLOW_EX_GATEWAY: xdr_enc_gateway(pktsmp, &elem->flowType.gateway); break;
    case SFLFLOW_EX_USER: xdr_enc_user(pktsmp, &elem->flowType.user); break;
    case SFLFLOW_EX_URL: xdr_enc_url(pktsmp, &elem->flowType.url); break;
    case SFLFLOW_EX_MPLS: xdr_enc_mpls(pktsmp, &elem->flowType.mpls); break;
    case SFLFLOW_EX_NAT: xdr_enc_nat(pktsmp, &elem->flowType.nat); break;	
    case SFLFLOW_EX_MPLS_TUNNEL: xdr_enc_mpls_tunnel(pktsmp, &elem->flowType.mpls_tunnel); break;
    case SFLFLOW_EX_MPLS_VC: xdr_enc_mpls_vc(pktsmp, &elem->flowType.mpls_vc); break;
    case SFLFLOW_EX_MPLS_FTN: xdr_enc_mpls_ftn(pktsmp, &elem->flowType.mpls_ftn); break;
    case SFLFLOW_EX_MPLS_LDP_FEC: xdr_enc_mpls_ldp_fec(pktsmp, &elem->flowType.mpls_ldp_fec); break;
    case SFLFLOW_EX_VLAN_TUNNEL: xdr_enc_vlan_tunnel(pktsmp, &elem->flowType.vlan_tunnel); break;
    case SFLFLOW_EX_L2_TUNNEL_EGRESS: xdr_enc_ethernet(pktsmp, &elem->flowType.tunnel_l2.header); break;
    case SFLFLOW_EX_L2_TUNNEL_INGRESS: xdr_enc_ethernet(pktsmp, &elem->flowType.tunnel_l2.header); break;
    case SFLFLOW_EX_IPV4_TUNNEL_EGRESS: xdr_enc_ipv4(pktsmp, &elem->flowType.tunnel_ipv4.header); break;
    case SFLFLOW_EX_IPV4_TUNNEL_INGRESS: xdr_enc_ipv4(pktsmp, &elem->flowType.tunnel_ipv4.header); break;
    case SFLFLOW_EX_IPV6_TUNNEL_EGRESS: xdr_enc_ipv6(pktsmp, &elem->flowType.tunnel_ipv6.header); break;
    case SFLFLOW_EX_IPV6_TUNNEL_INGRESS: xdr_enc_ipv6(pktsmp, &elem->flowType.tunnel_ipv6.header); break;
    case SFLFLOW_EX_DECAP_EGRESS: sfd_xdr_enc_int32(pktsmp, elem->flowType.tunnel_decap.inner_header_offset); break;
    case SFLFLOW_EX_DECAP_INGRESS: sfd_xdr_enc_int32(pktsmp, elem->flowType.tunnel_decap.inner_header_offset); break;
    case SFLFLOW_EX_VNI_EGRESS: sfd_xdr_enc_int32(pktsmp, elem->flowType.tunnel_vni.vni); break;
    case SFLFLOW_EX_VNI_INGRESS: sfd_xdr_enc_int32(pktsmp, elem->flowType.tunnel_vni.vni); break;
    case SFLFLOW_APP: xdr_enc_app(pktsmp, &elem->flowType.app); break;
    case SFLFLOW_APP_CTXT: xdr_enc_app_ctxt(pktsmp, &elem->flowType.context); break;
    case SFLFLOW_APP_ACTOR_INIT: xdr_enc_sflstring(pktsmp, &elem->flowType.actor.actor); break;
    case SFLFLOW_APP_ACTOR_TGT: xdr_enc_sflstring(pktsmp, &elem->flowType.actor.actor); break;
    case SFLFLOW_EX_PROXY_SOCKET4: xdr_enc_socket4(pktsmp, &elem->flowType.socket4); break;
    case SFLFLOW_EX_SOCKET4: xdr_enc_socket4(pktsmp, &elem->flowType.socket4); break;
    case SFLFLOW_EX_PROXY_SOCKET6: xdr_enc_socket6(pktsmp, &elem->flowType.socket6); break;
    case SFLFLOW_EX_SOCKET6: xdr_enc_socket6(pktsmp, &elem->flowType.socket6); break;
    case SFLFLOW_EX_TCP_INFO: xdr_enc_tcp_info(pktsmp, &elem->flowType.tcp_info); break;
    case SFLFLOW_EX_ENTITIES: xdr_enc_entities(pktsmp, &elem->flowType.entities); break;
    case SFLFLOW_EX_EGRESS_Q: sfd_xdr_enc_int32(pktsmp, elem->flowType.egress_queue.queue); break;
    case SFLFLOW_EX_FUNCTION: xdr_enc_sflstring(pktsmp, &elem->flowType.function.symbol); break;
    case SFLFLOW_EX_TRANSIT: sfd_xdr_enc_int32(pktsmp, elem->flowType.transit_delay.delay); break;
    case SFLFLOW_EX_Q_DEPTH: sfd_xdr_enc_int32(pktsmp, elem->flowType.queue_depth.depth); break;
    case SFLFLOW_EX_HW_TRAP: xdr_enc_hw_trap(pktsmp, &elem->flowType.hw_trap); break;
    case SFLFLOW_EX_LINUX_REASON: xdr_enc_sflstring(pktsmp, &elem->flowType.linux_reason.reason); break;
    default:
      return -1;
    }
    sfd_xdr_end_tlv(pktsmp); // end element
  }
  return nFound;
}

/*_________________-------------------------------__________________
  _________________ sfl_receiver_writeFlowSample  __________________
  -----------------_______________________________------------------
*/

int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
  SFDDgram *sfdg = receiver->sfdg;
  SFDBuf *pktsmp = SFDSampleNew(sfdg);
  
#ifdef SFL_USE_32BIT_INDEX
  sfd_xdr_start_tlv(pktsmp, SFLFLOW_SAMPLE_EXPANDED);
#else
  sfd_xdr_start_tlv(pktsmp, SFLFLOW_SAMPLE);
#endif
  
  sfd_xdr_enc_int32(pktsmp, fs->sequence_number);
  
#ifdef SFL_USE_32BIT_INDEX
  sfd_xdr_enc_int32(pktsmp, fs->ds_class);
  sfd_xdr_enc_int32(pktsmp, fs->ds_index);
#else
  sfd_xdr_enc_int32(pktsmp, fs->source_id);
#endif
  
  sfd_xdr_enc_int32(pktsmp, fs->sampling_rate);
  sfd_xdr_enc_int32(pktsmp, fs->sample_pool);
  sfd_xdr_enc_int32(pktsmp, fs->drops);
  
#ifdef SFL_USE_32BIT_INDEX
  sfd_xdr_enc_int32(pktsmp, fs->inputFormat);
  sfd_xdr_enc_int32(pktsmp, fs->input);
  sfd_xdr_enc_int32(pktsmp, fs->outputFormat);
  sfd_xdr_enc_int32(pktsmp, fs->output);
#else
  sfd_xdr_enc_int32(pktsmp, fs->input);
  sfd_xdr_enc_int32(pktsmp, fs->output);
#endif
  
  sfd_xdr_enc_int32(pktsmp, fs->num_elements);
  if(xdr_enc_flow_sample_elements(pktsmp, fs->elements) < 0) {
    sfdg->f_err(sfdg->magic, "unexpected flow-sample element");
    return -1; // element-encoding problem - junk whole sample
  }
  sfd_xdr_end_tlv(pktsmp); // end flow sample
  SFDAddSample(sfdg, pktsmp);
  return 0; // TODO: do we need to return the size of the buffer?
}

/*_________________-------------------------------__________________
  _________________ sfl_receiver_writeEventSample __________________
  -----------------_______________________________------------------
*/

int sfl_receiver_writeEventSample(SFLReceiver *receiver, SFLEvent_discarded_packet *es)
{
  SFDDgram *sfdg = receiver->sfdg;
  SFDBuf *evtsmp = SFDSampleNew(sfdg);

  sfd_xdr_start_tlv(evtsmp, SFLEVENT_DISCARDED_PACKET);
  sfd_xdr_enc_int32(evtsmp, es->sequence_number);
  sfd_xdr_enc_int32(evtsmp, es->ds_class);
  sfd_xdr_enc_int32(evtsmp, es->ds_index);
  sfd_xdr_enc_int32(evtsmp, es->drops);
  sfd_xdr_enc_int32(evtsmp, es->input);
  sfd_xdr_enc_int32(evtsmp, es->output);
  sfd_xdr_enc_int32(evtsmp, es->reason);
  sfd_xdr_enc_int32(evtsmp, es->num_elements);
  if(xdr_enc_flow_sample_elements(evtsmp, es->elements) < 0) {
    sfdg->f_err(sfdg->magic, "unexpected event-sample element");
    return -1; // element-encoding problem - junk whole sample
  }
  sfd_xdr_end_tlv(evtsmp); // end flow sample
  SFDAddSample(sfdg, evtsmp);
  return 0; // TODO: return size?
}

/*_________________-------------------------------__________________
  _________________   counter sample elements     __________________
  -----------------_______________________________------------------
*/

static void xdr_enc_generic(SFDBuf *ctrsmp, SFLIf_counters *gen) {
  sfd_xdr_enc_int32(ctrsmp, gen->ifIndex);
  sfd_xdr_enc_int32(ctrsmp, gen->ifType);
  sfd_xdr_enc_int64(ctrsmp, gen->ifSpeed);
  sfd_xdr_enc_int32(ctrsmp, gen->ifDirection);
  sfd_xdr_enc_int32(ctrsmp, gen->ifStatus);
  sfd_xdr_enc_int64(ctrsmp, gen->ifInOctets);
  sfd_xdr_enc_int32(ctrsmp, gen->ifInUcastPkts);
  sfd_xdr_enc_int32(ctrsmp, gen->ifInMulticastPkts);
  sfd_xdr_enc_int32(ctrsmp, gen->ifInBroadcastPkts);
  sfd_xdr_enc_int32(ctrsmp, gen->ifInDiscards);
  sfd_xdr_enc_int32(ctrsmp, gen->ifInErrors);
  sfd_xdr_enc_int32(ctrsmp, gen->ifInUnknownProtos);
  sfd_xdr_enc_int64(ctrsmp, gen->ifOutOctets);
  sfd_xdr_enc_int32(ctrsmp, gen->ifOutUcastPkts);
  sfd_xdr_enc_int32(ctrsmp, gen->ifOutMulticastPkts);
  sfd_xdr_enc_int32(ctrsmp, gen->ifOutBroadcastPkts);
  sfd_xdr_enc_int32(ctrsmp, gen->ifOutDiscards);
  sfd_xdr_enc_int32(ctrsmp, gen->ifOutErrors);
  sfd_xdr_enc_int32(ctrsmp, gen->ifPromiscuousMode);
}

static void xdr_enc_ethernet_counters(SFDBuf *ctrsmp, SFLEthernet_counters *eth) {
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsAlignmentErrors);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsFCSErrors);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsSingleCollisionFrames);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsMultipleCollisionFrames);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsSQETestErrors);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsDeferredTransmissions);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsLateCollisions);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsExcessiveCollisions);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsInternalMacTransmitErrors);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsCarrierSenseErrors);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsFrameTooLongs);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsInternalMacReceiveErrors);
  sfd_xdr_enc_int32(ctrsmp, eth->dot3StatsSymbolErrors);
}

static void xdr_enc_tokenring(SFDBuf *ctrsmp, SFLTokenring_counters *tr) {
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsLineErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsBurstErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsACErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsAbortTransErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsInternalErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsLostFrameErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsReceiveCongestions);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsFrameCopiedErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsTokenErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsSoftErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsHardErrors);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsSignalLoss);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsTransmitBeacons);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsRecoverys);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsLobeWires);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsRemoves);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsSingles);
  sfd_xdr_enc_int32(ctrsmp, tr->dot5StatsFreqErrors);
}

static void xdr_enc_vg(SFDBuf *ctrsmp, SFLVg_counters *vg) {
  sfd_xdr_enc_int32(ctrsmp, vg->dot12InHighPriorityFrames);
  sfd_xdr_enc_int64(ctrsmp, vg->dot12InHighPriorityOctets);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12InNormPriorityFrames);
  sfd_xdr_enc_int64(ctrsmp, vg->dot12InNormPriorityOctets);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12InIPMErrors);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12InOversizeFrameErrors);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12InDataErrors);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12InNullAddressedFrames);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12OutHighPriorityFrames);
  sfd_xdr_enc_int64(ctrsmp, vg->dot12OutHighPriorityOctets);
  sfd_xdr_enc_int32(ctrsmp, vg->dot12TransitionIntoTrainings);
  sfd_xdr_enc_int64(ctrsmp, vg->dot12HCInHighPriorityOctets);
  sfd_xdr_enc_int64(ctrsmp, vg->dot12HCInNormPriorityOctets);
  sfd_xdr_enc_int64(ctrsmp, vg->dot12HCOutHighPriorityOctets);
}

static void xdr_enc_vlan(SFDBuf *ctrsmp, SFLVlan_counters *vl) {
  sfd_xdr_enc_int32(ctrsmp, vl->vlan_id);
  sfd_xdr_enc_int64(ctrsmp, vl->octets);
  sfd_xdr_enc_int32(ctrsmp, vl->ucastPkts);
  sfd_xdr_enc_int32(ctrsmp, vl->multicastPkts);
  sfd_xdr_enc_int32(ctrsmp, vl->broadcastPkts);
  sfd_xdr_enc_int32(ctrsmp, vl->discards);
}

static void xdr_enc_lacp(SFDBuf *ctrsmp, SFLLACP_counters *lacp) {
  sfd_xdr_enc_mac(ctrsmp, lacp->actorSystemID);
  sfd_xdr_enc_mac(ctrsmp, lacp->partnerSystemID);
  sfd_xdr_enc_int32(ctrsmp, lacp->attachedAggID);
  sfd_xdr_enc_int32(ctrsmp, lacp->portState.all);
  sfd_xdr_enc_int32(ctrsmp, lacp->LACPDUsRx);
  sfd_xdr_enc_int32(ctrsmp, lacp->markerPDUsRx);
  sfd_xdr_enc_int32(ctrsmp, lacp->markerResponsePDUsRx);
  sfd_xdr_enc_int32(ctrsmp, lacp->unknownRx);
  sfd_xdr_enc_int32(ctrsmp, lacp->illegalRx);
  sfd_xdr_enc_int32(ctrsmp, lacp->LACPDUsTx);
  sfd_xdr_enc_int32(ctrsmp, lacp->markerPDUsTx);
  sfd_xdr_enc_int32(ctrsmp, lacp->markerResponsePDUsTx);
}

static void xdr_enc_sfp(SFDBuf *ctrsmp, SFLSFP_counters *sfp) {
  sfd_xdr_enc_int32(ctrsmp, sfp->module_id);
  sfd_xdr_enc_int32(ctrsmp, sfp->module_total_lanes);
  sfd_xdr_enc_int32(ctrsmp, sfp->module_supply_voltage);
  sfd_xdr_enc_int32(ctrsmp, sfp->module_temperature);
  sfd_xdr_enc_int32(ctrsmp, sfp->num_lanes);
  for(uint32_t ii = 0; ii < sfp->num_lanes; ii++) {
    SFLLane *lane = &(sfp->lanes[ii]);
    sfd_xdr_enc_int32(ctrsmp, lane->lane_index);
    sfd_xdr_enc_int32(ctrsmp, lane->tx_bias_current);
    sfd_xdr_enc_int32(ctrsmp, lane->tx_power);
    sfd_xdr_enc_int32(ctrsmp, lane->tx_power_min);
    sfd_xdr_enc_int32(ctrsmp, lane->tx_power_max);
    sfd_xdr_enc_int32(ctrsmp, lane->tx_wavelength);
    sfd_xdr_enc_int32(ctrsmp, lane->rx_power);
    sfd_xdr_enc_int32(ctrsmp, lane->rx_power_min);
    sfd_xdr_enc_int32(ctrsmp, lane->rx_power_max);
    sfd_xdr_enc_int32(ctrsmp, lane->rx_wavelength);
  }
}

static void xdr_enc_processor(SFDBuf *ctrsmp, SFLProcessor_counters *pr) {
  sfd_xdr_enc_int32(ctrsmp, pr->five_sec_cpu);
  sfd_xdr_enc_int32(ctrsmp, pr->one_min_cpu);
  sfd_xdr_enc_int32(ctrsmp, pr->five_min_cpu);
  sfd_xdr_enc_int64(ctrsmp, pr->total_memory);
  sfd_xdr_enc_int64(ctrsmp, pr->free_memory);
}

static void xdr_enc_host_hid(SFDBuf *ctrsmp, SFLHost_hid_counters *hid) {
  xdr_enc_sflstring(ctrsmp, &hid->hostname);
  sfd_xdr_enc_bytes(ctrsmp, hid->uuid, 16);
  sfd_xdr_enc_int32(ctrsmp, hid->machine_type);
  sfd_xdr_enc_int32(ctrsmp, hid->os_name);
  xdr_enc_sflstring(ctrsmp, &hid->os_release);
}

static void xdr_enc_host_par(SFDBuf *ctrsmp, SFLHost_par_counters *par) {
  sfd_xdr_enc_int32(ctrsmp, par->dsClass);
  sfd_xdr_enc_int32(ctrsmp, par->dsIndex);
}

static void xdr_enc_adaptors(SFDBuf *ctrsmp, SFLAdaptorList *adaptorList) {
  sfd_xdr_enc_int32(ctrsmp, adaptorList->num_adaptors);
  for(uint32_t i = 0; i < adaptorList->num_adaptors; i++) {
    SFLAdaptor *adaptor = adaptorList->adaptors[i];
    sfd_xdr_enc_int32(ctrsmp, adaptor->ifIndex);
    sfd_xdr_enc_int32(ctrsmp, adaptor->num_macs);
    for(uint32_t j = 0; j < adaptor->num_macs; j++) {
      sfd_xdr_enc_mac(ctrsmp, adaptor->macs[j].mac);
    }
  }
}

static void xdr_enc_host_cpu(SFDBuf *ctrsmp, SFLHost_cpu_counters *cpu) {
  sfd_xdr_enc_float(ctrsmp, cpu->load_one);
  sfd_xdr_enc_float(ctrsmp, cpu->load_five);
  sfd_xdr_enc_float(ctrsmp, cpu->load_fifteen);
  sfd_xdr_enc_int32(ctrsmp, cpu->proc_run);
  sfd_xdr_enc_int32(ctrsmp, cpu->proc_total);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_num);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_speed);
  sfd_xdr_enc_int32(ctrsmp, cpu->uptime);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_user);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_nice);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_system);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_idle);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_wio);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_intr);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_sintr);
  sfd_xdr_enc_int32(ctrsmp, cpu->interrupts);
  sfd_xdr_enc_int32(ctrsmp, cpu->contexts);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_steal);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_guest);
  sfd_xdr_enc_int32(ctrsmp, cpu->cpu_guest_nice);
}

static void xdr_enc_host_mem(SFDBuf *ctrsmp, SFLHost_mem_counters *mem) {
  sfd_xdr_enc_int64(ctrsmp, mem->mem_total);
  sfd_xdr_enc_int64(ctrsmp, mem->mem_free);
  sfd_xdr_enc_int64(ctrsmp, mem->mem_shared);
  sfd_xdr_enc_int64(ctrsmp, mem->mem_buffers);
  sfd_xdr_enc_int64(ctrsmp, mem->mem_cached);
  sfd_xdr_enc_int64(ctrsmp, mem->swap_total);
  sfd_xdr_enc_int64(ctrsmp, mem->swap_free);
  sfd_xdr_enc_int32(ctrsmp, mem->page_in);
  sfd_xdr_enc_int32(ctrsmp, mem->page_out);
  sfd_xdr_enc_int32(ctrsmp, mem->swap_in);
  sfd_xdr_enc_int32(ctrsmp, mem->swap_out);
}

static void xdr_enc_host_dsk(SFDBuf *ctrsmp, SFLHost_dsk_counters *dsk) {
  sfd_xdr_enc_int64(ctrsmp, dsk->disk_total);
  sfd_xdr_enc_int64(ctrsmp, dsk->disk_free);
  sfd_xdr_enc_int32(ctrsmp, dsk->part_max_used);
  sfd_xdr_enc_int32(ctrsmp, dsk->reads);
  sfd_xdr_enc_int64(ctrsmp, dsk->bytes_read);
  sfd_xdr_enc_int32(ctrsmp, dsk->read_time);
  sfd_xdr_enc_int32(ctrsmp, dsk->writes);
  sfd_xdr_enc_int64(ctrsmp, dsk->bytes_written);
  sfd_xdr_enc_int32(ctrsmp, dsk->write_time);
}

static void xdr_enc_host_nio(SFDBuf *ctrsmp, SFLHost_nio_counters *nio) {
  sfd_xdr_enc_int64(ctrsmp, nio->bytes_in);
  sfd_xdr_enc_int32(ctrsmp, nio->pkts_in);
  sfd_xdr_enc_int32(ctrsmp, nio->errs_in);
  sfd_xdr_enc_int32(ctrsmp, nio->drops_in);
  sfd_xdr_enc_int64(ctrsmp, nio->bytes_out);
  sfd_xdr_enc_int32(ctrsmp, nio->pkts_out);
  sfd_xdr_enc_int32(ctrsmp, nio->errs_out);
  sfd_xdr_enc_int32(ctrsmp, nio->drops_out);
}

static void xdr_enc_host_vrt_node(SFDBuf *ctrsmp, SFLHost_vrt_node_counters *vrt) {
  sfd_xdr_enc_int32(ctrsmp, vrt->mhz);
  sfd_xdr_enc_int32(ctrsmp, vrt->cpus);
  sfd_xdr_enc_int64(ctrsmp, vrt->memory);
  sfd_xdr_enc_int64(ctrsmp, vrt->memory_free);
  sfd_xdr_enc_int32(ctrsmp, vrt->num_domains);
}

static void xdr_enc_host_vrt_cpu(SFDBuf *ctrsmp, SFLHost_vrt_cpu_counters *vcpu) {
  sfd_xdr_enc_int32(ctrsmp, vcpu->state);
  sfd_xdr_enc_int32(ctrsmp, vcpu->cpuTime);
  sfd_xdr_enc_int32(ctrsmp, vcpu->nrVirtCpu);
}

static void xdr_enc_host_vrt_mem(SFDBuf *ctrsmp, SFLHost_vrt_mem_counters *vmem) {
  sfd_xdr_enc_int64(ctrsmp, vmem->memory);
  sfd_xdr_enc_int64(ctrsmp, vmem->maxMemory);
}

static void xdr_enc_host_vrt_dsk(SFDBuf *ctrsmp, SFLHost_vrt_dsk_counters *vdsk) {
  sfd_xdr_enc_int64(ctrsmp, vdsk->capacity);
  sfd_xdr_enc_int64(ctrsmp, vdsk->allocation);
  sfd_xdr_enc_int64(ctrsmp, vdsk->available);
  sfd_xdr_enc_int32(ctrsmp, vdsk->rd_req);
  sfd_xdr_enc_int64(ctrsmp, vdsk->rd_bytes);
  sfd_xdr_enc_int32(ctrsmp, vdsk->wr_req);
  sfd_xdr_enc_int64(ctrsmp, vdsk->wr_bytes);
  sfd_xdr_enc_int32(ctrsmp, vdsk->errs);
}

static void xdr_enc_host_vrt_nio(SFDBuf *ctrsmp, SFLHost_vrt_nio_counters *vnio) {
  sfd_xdr_enc_int64(ctrsmp, vnio->bytes_in);
  sfd_xdr_enc_int32(ctrsmp, vnio->pkts_in);
  sfd_xdr_enc_int32(ctrsmp, vnio->errs_in);
  sfd_xdr_enc_int32(ctrsmp, vnio->drops_in);
  sfd_xdr_enc_int64(ctrsmp, vnio->bytes_out);
  sfd_xdr_enc_int32(ctrsmp, vnio->pkts_out);
  sfd_xdr_enc_int32(ctrsmp, vnio->errs_out);
  sfd_xdr_enc_int32(ctrsmp, vnio->drops_out);
}

static void xdr_enc_host_gpu_nvml(SFDBuf *ctrsmp, SFLHost_gpu_nvml *nvml) {
  sfd_xdr_enc_int32(ctrsmp, nvml->device_count);
  sfd_xdr_enc_int32(ctrsmp, nvml->processes);
  sfd_xdr_enc_int32(ctrsmp, nvml->gpu_time);
  sfd_xdr_enc_int32(ctrsmp, nvml->mem_time);
  sfd_xdr_enc_int64(ctrsmp, nvml->mem_total);
  sfd_xdr_enc_int64(ctrsmp, nvml->mem_free);
  sfd_xdr_enc_int32(ctrsmp, nvml->ecc_errors);
  sfd_xdr_enc_int32(ctrsmp, nvml->energy);
  sfd_xdr_enc_int32(ctrsmp, nvml->temperature);
  sfd_xdr_enc_int32(ctrsmp, nvml->fan_speed);
}

static void xdr_enc_host_ip(SFDBuf *ctrsmp, SFLHost_ip_counters *ip) {
  sfd_xdr_enc_int32(ctrsmp, ip->ipForwarding);
  sfd_xdr_enc_int32(ctrsmp, ip->ipDefaultTTL);
  sfd_xdr_enc_int32(ctrsmp, ip->ipInReceives);
  sfd_xdr_enc_int32(ctrsmp, ip->ipInHdrErrors);
  sfd_xdr_enc_int32(ctrsmp, ip->ipInAddrErrors);
  sfd_xdr_enc_int32(ctrsmp, ip->ipForwDatagrams);
  sfd_xdr_enc_int32(ctrsmp, ip->ipInUnknownProtos);
  sfd_xdr_enc_int32(ctrsmp, ip->ipInDiscards);
  sfd_xdr_enc_int32(ctrsmp, ip->ipInDelivers);
  sfd_xdr_enc_int32(ctrsmp, ip->ipOutRequests);
  sfd_xdr_enc_int32(ctrsmp, ip->ipOutDiscards);
  sfd_xdr_enc_int32(ctrsmp, ip->ipOutNoRoutes);
  sfd_xdr_enc_int32(ctrsmp, ip->ipReasmTimeout);
  sfd_xdr_enc_int32(ctrsmp, ip->ipReasmReqds);
  sfd_xdr_enc_int32(ctrsmp, ip->ipReasmOKs);
  sfd_xdr_enc_int32(ctrsmp, ip->ipReasmFails);
  sfd_xdr_enc_int32(ctrsmp, ip->ipFragOKs);
  sfd_xdr_enc_int32(ctrsmp, ip->ipFragFails);
  sfd_xdr_enc_int32(ctrsmp, ip->ipFragCreates);
}

static void xdr_enc_host_icmp(SFDBuf *ctrsmp, SFLHost_icmp_counters *icmp) {
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInMsgs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInErrors);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInDestUnreachs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInTimeExcds);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInParamProbs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInSrcQuenchs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInRedirects);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInEchos);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInEchoReps);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInTimestamps);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInAddrMasks);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpInAddrMaskReps);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutMsgs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutErrors);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutDestUnreachs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutTimeExcds);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutParamProbs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutSrcQuenchs);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutRedirects);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutEchos);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutEchoReps);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutTimestamps);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutTimestampReps);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutAddrMasks);
  sfd_xdr_enc_int32(ctrsmp, icmp->icmpOutAddrMaskReps);
}

static void xdr_enc_host_tcp(SFDBuf *ctrsmp, SFLHost_tcp_counters *tcp) {
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpRtoAlgorithm);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpRtoMin);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpRtoMax);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpMaxConn);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpActiveOpens);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpPassiveOpens);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpAttemptFails);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpEstabResets);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpCurrEstab);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpInSegs);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpOutSegs);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpRetransSegs);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpInErrs);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpOutRsts);
  sfd_xdr_enc_int32(ctrsmp, tcp->tcpInCsumErrors);
}

static void xdr_enc_host_udp(SFDBuf *ctrsmp, SFLHost_udp_counters *udp) {
  sfd_xdr_enc_int32(ctrsmp, udp->udpInDatagrams);
  sfd_xdr_enc_int32(ctrsmp, udp->udpNoPorts);
  sfd_xdr_enc_int32(ctrsmp, udp->udpInErrors);
  sfd_xdr_enc_int32(ctrsmp, udp->udpOutDatagrams);
  sfd_xdr_enc_int32(ctrsmp, udp->udpRcvbufErrors);
  sfd_xdr_enc_int32(ctrsmp, udp->udpSndbufErrors);
  sfd_xdr_enc_int32(ctrsmp, udp->udpInCsumErrors);
}

static void xdr_enc_app_counters(SFDBuf *ctrsmp, SFLAPPCounters *app) {
  xdr_enc_sflstring(ctrsmp, &app->application);
  sfd_xdr_enc_int32(ctrsmp, app->status_OK);
  sfd_xdr_enc_int32(ctrsmp, app->errors_OTHER);
  sfd_xdr_enc_int32(ctrsmp, app->errors_TIMEOUT);
  sfd_xdr_enc_int32(ctrsmp, app->errors_INTERNAL_ERROR);
  sfd_xdr_enc_int32(ctrsmp, app->errors_BAD_REQUEST);
  sfd_xdr_enc_int32(ctrsmp, app->errors_FORBIDDEN);
  sfd_xdr_enc_int32(ctrsmp, app->errors_TOO_LARGE);
  sfd_xdr_enc_int32(ctrsmp, app->errors_NOT_IMPLEMENTED);
  sfd_xdr_enc_int32(ctrsmp, app->errors_NOT_FOUND);
  sfd_xdr_enc_int32(ctrsmp, app->errors_UNAVAILABLE);
  sfd_xdr_enc_int32(ctrsmp, app->errors_UNAUTHORIZED);
}

static void xdr_enc_app_resources(SFDBuf *ctrsmp, SFLAPPResources *apr) {
  sfd_xdr_enc_int32(ctrsmp, apr->user_time);
  sfd_xdr_enc_int32(ctrsmp, apr->system_time);
  sfd_xdr_enc_int64(ctrsmp, apr->mem_used);
  sfd_xdr_enc_int64(ctrsmp, apr->mem_max);
  sfd_xdr_enc_int32(ctrsmp, apr->fd_open);
  sfd_xdr_enc_int32(ctrsmp, apr->fd_max);
  sfd_xdr_enc_int32(ctrsmp, apr->conn_open);
  sfd_xdr_enc_int32(ctrsmp, apr->conn_max);
}

static void xdr_enc_app_workers(SFDBuf *ctrsmp, SFLAPPWorkers *apw) {
  sfd_xdr_enc_int32(ctrsmp, apw->workers_active);
  sfd_xdr_enc_int32(ctrsmp, apw->workers_idle);
  sfd_xdr_enc_int32(ctrsmp, apw->workers_max);
  sfd_xdr_enc_int32(ctrsmp, apw->req_delayed);
  sfd_xdr_enc_int32(ctrsmp, apw->req_dropped);
}

static void xdr_enc_port_name(SFDBuf *ctrsmp, SFLPortName *pnm) {
  xdr_enc_sflstring(ctrsmp, &pnm->portName);
}

static void xdr_enc_bcm(SFDBuf *ctrsmp, SFLBCM_tables *bcm) {
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_host_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_host_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv4_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv4_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv6_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv6_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv4_ipv6_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv4_ipv6_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_long_ipv6_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_long_ipv6_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_total_routes);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_total_routes_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ecmp_nexthops);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ecmp_nexthops_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_mac_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_mac_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv4_neighbors);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv6_neighbors);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv4_routes);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_ipv6_routes);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_counters);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_counters_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_meters);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_meters_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_slices);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_ingress_slices_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_entries);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_entries_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_counters);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_counters_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_meters);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_meters_max);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_slices);
  sfd_xdr_enc_int32(ctrsmp, bcm->bcm_acl_egress_slices_max);
}

static int xdr_enc_counter_sample_elements(SFDBuf *ctrsmp, SFLCounters_sample_element *elements) {
  int nFound = 0;
  for(SFLCounters_sample_element *elem = elements; elem != NULL; elem = elem->nxt) {
    nFound++;
    sfd_xdr_start_tlv(ctrsmp, elem->tag); // start element
    switch(elem->tag) {
    case SFLCOUNTERS_GENERIC: xdr_enc_generic(ctrsmp, &elem->counterBlock.generic); break;
    case SFLCOUNTERS_ETHERNET: xdr_enc_ethernet_counters(ctrsmp, &elem->counterBlock.ethernet); break;
    case SFLCOUNTERS_TOKENRING: xdr_enc_tokenring(ctrsmp, &elem->counterBlock.tokenring); break;
    case SFLCOUNTERS_VG: xdr_enc_vg(ctrsmp, &elem->counterBlock.vg); break;
    case SFLCOUNTERS_VLAN: xdr_enc_vlan(ctrsmp, &elem->counterBlock.vlan); break;
    case SFLCOUNTERS_LACP: xdr_enc_lacp(ctrsmp, &elem->counterBlock.lacp); break;
    case SFLCOUNTERS_SFP: xdr_enc_sfp(ctrsmp, &elem->counterBlock.sfp); break;
    case SFLCOUNTERS_PROCESSOR: xdr_enc_processor(ctrsmp, &elem->counterBlock.processor); break;
    case SFLCOUNTERS_HOST_HID: xdr_enc_host_hid(ctrsmp, &elem->counterBlock.host_hid); break;
    case SFLCOUNTERS_HOST_PAR: xdr_enc_host_par(ctrsmp, &elem->counterBlock.host_par); break;
    case SFLCOUNTERS_ADAPTORS: xdr_enc_adaptors(ctrsmp, elem->counterBlock.adaptors); break;
    case SFLCOUNTERS_HOST_CPU: xdr_enc_host_cpu(ctrsmp, &elem->counterBlock.host_cpu); break;
    case SFLCOUNTERS_HOST_MEM: xdr_enc_host_mem(ctrsmp, &elem->counterBlock.host_mem); break;
    case SFLCOUNTERS_HOST_DSK: xdr_enc_host_dsk(ctrsmp, &elem->counterBlock.host_dsk); break;
    case SFLCOUNTERS_HOST_NIO: xdr_enc_host_nio(ctrsmp, &elem->counterBlock.host_nio); break;
    case SFLCOUNTERS_HOST_VRT_NODE: xdr_enc_host_vrt_node(ctrsmp, &elem->counterBlock.host_vrt_node); break;
    case SFLCOUNTERS_HOST_VRT_CPU: xdr_enc_host_vrt_cpu(ctrsmp, &elem->counterBlock.host_vrt_cpu); break;
    case SFLCOUNTERS_HOST_VRT_MEM: xdr_enc_host_vrt_mem(ctrsmp, &elem->counterBlock.host_vrt_mem); break;
    case SFLCOUNTERS_HOST_VRT_DSK: xdr_enc_host_vrt_dsk(ctrsmp, &elem->counterBlock.host_vrt_dsk); break;
    case SFLCOUNTERS_HOST_VRT_NIO: xdr_enc_host_vrt_nio(ctrsmp, &elem->counterBlock.host_vrt_nio); break;
    case SFLCOUNTERS_HOST_GPU_NVML: xdr_enc_host_gpu_nvml(ctrsmp, &elem->counterBlock.host_gpu_nvml); break;
    case SFLCOUNTERS_HOST_IP: xdr_enc_host_ip(ctrsmp, &elem->counterBlock.host_ip); break;
    case SFLCOUNTERS_HOST_ICMP: xdr_enc_host_icmp(ctrsmp, &elem->counterBlock.host_icmp); break;
    case SFLCOUNTERS_HOST_TCP: xdr_enc_host_tcp(ctrsmp, &elem->counterBlock.host_tcp); break;
    case SFLCOUNTERS_HOST_UDP: xdr_enc_host_udp(ctrsmp, &elem->counterBlock.host_udp); break;
    case SFLCOUNTERS_APP: xdr_enc_app_counters(ctrsmp, &elem->counterBlock.app); break;
    case SFLCOUNTERS_APP_RESOURCES: xdr_enc_app_resources(ctrsmp, &elem->counterBlock.appResources); break;
    case SFLCOUNTERS_APP_WORKERS: xdr_enc_app_workers(ctrsmp, &elem->counterBlock.appWorkers); break;
    case SFLCOUNTERS_PORTNAME: xdr_enc_port_name(ctrsmp, &elem->counterBlock.portName); break;
    case SFLCOUNTERS_BCM_TABLES: xdr_enc_bcm(ctrsmp, &elem->counterBlock.bcm_tables); break;
    default:
      return -1;
    }
    sfd_xdr_end_tlv(ctrsmp); // end element
  }
  return nFound;
}

/*_________________----------------------------------__________________
  _________________ sfl_receiver_writeCountersSample __________________
  -----------------__________________________________------------------
*/

int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
  SFDDgram *sfdg = receiver->sfdg;
  SFDBuf *ctrsmp = SFDSampleNew(sfdg);
  
#ifdef SFL_USE_32BIT_INDEX
  sfd_xdr_start_tlv(ctrsmp, SFLCOUNTERS_SAMPLE_EXPANDED);
#else
  sfd_xdr_start_tlv(ctrsmp, SFLCOUNTERS_SAMPLE);
#endif
  
  sfd_xdr_enc_int32(ctrsmp, cs->sequence_number);
  
#ifdef SFL_USE_32BIT_INDEX
  sfd_xdr_enc_int32(ctrsmp, cs->ds_class);
  sfd_xdr_enc_int32(ctrsmp, cs->ds_index);
#else
  sfd_xdr_enc_int32(ctrsmp, cs->source_id);
#endif
  
  sfd_xdr_enc_int32(ctrsmp, cs->num_elements);
  if(xdr_enc_counter_sample_elements(ctrsmp, cs->elements) < 0) {
    sfdg->f_err(sfdg->magic, "unexpected counter-sample element");
    return -1;
  }
  sfd_xdr_end_tlv(ctrsmp); // end counter sample
  SFDAddSample(sfdg, ctrsmp);
  return 0; // TODO: return size?
}

/*_________________-------------------------------__________________
  _________________ sfl_receiver_writeEncoded     __________________
  -----------------_______________________________------------------
  write a pre-encoded block of XDR
  TODO: allow client to request an SFDBuf, then submit it back for inclusion
  (e.g. by mod_json.c, which uses this to pass in rtmetric and rtflow data as
  pre-encoded XDR buffers).
*/

int sfl_receiver_writeEncoded(SFLReceiver *receiver, uint32_t samples, uint32_t *xdr, int packedSize) {
  SFDDgram *sfdg = receiver->sfdg;
  SFDBuf *dbuf = SFDSampleNew(sfdg);
  sfd_xdr_enc_bytes(dbuf, (u_char *)xdr, packedSize);
  SFDAddSample(sfdg, dbuf);
  return packedSize;
}

/*_________________-------------------------------__________________
  _________________     sfl_receiver_getSFDBuf    __________________
  -----------------_______________________________------------------
*/

SFDBuf *sfl_receiver_get_SFDBuf(SFLReceiver *receiver) {
  SFDDgram *sfdg = receiver->sfdg;
  return sfdg ? SFDSampleNew(sfdg) : NULL;
}

int sfl_receiver_free_SFDBuf(SFLReceiver *receiver, SFDBuf *dbuf) {
  SFDDgram *sfdg = receiver->sfdg;
  return sfdg ? SFDSampleFree(sfdg, dbuf) : 0;
}

int sfl_receiver_write_SFDBuf(SFLReceiver *receiver, SFDBuf *dbuf) {
  SFDDgram *sfdg = receiver->sfdg;
  if(sfdg) {
    SFDAddSample(sfdg, dbuf);
    return 1;
  }
  return 0;
}

/*_________________---------------------------------__________________
  _________________ sfl_receiver_samplePacketsSent  __________________
  -----------------_________________________________------------------
*/

uint32_t sfl_receiver_samplePacketsSent(SFLReceiver *receiver) {
  return receiver->sfdg->dgramSeqNo;
}


#if defined(__cplusplus)
} /* extern "C" */
#endif
