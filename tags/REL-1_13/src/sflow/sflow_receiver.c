/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include <assert.h>
#include "sflow_api.h"

static void resetSampleCollector(SFLReceiver *receiver);
static void sendSample(SFLReceiver *receiver);
static void sflError(SFLReceiver *receiver, char *errm);
static void putNet32(SFLReceiver *receiver, uint32_t val);
static void putAddress(SFLReceiver *receiver, SFLAddress *addr);
#ifdef SFLOW_DO_SOCKET
static void initSocket(SFLReceiver *receiver);
#endif

/*_________________--------------------------__________________
  _________________    sfl_receiver_init     __________________
  -----------------__________________________------------------
*/

void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent)
{
  /* first clear everything */
  memset(receiver, 0, sizeof(*receiver));

  /* now copy in the parameters */
  receiver->agent = agent;

  /* set defaults */
  receiver->sFlowRcvrMaximumDatagramSize = SFL_DEFAULT_DATAGRAM_SIZE;
  receiver->sFlowRcvrPort = SFL_DEFAULT_COLLECTOR_PORT;

#ifdef SFLOW_DO_SOCKET
  /* initialize the socket address */
  initSocket(receiver);
#endif

  /* prepare to receive the first sample */
  resetSampleCollector(receiver);
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

#ifdef SFLOW_DO_SOCKET
/*_________________---------------------------__________________
  _________________      initSocket           __________________
  -----------------___________________________------------------
*/

static void initSocket(SFLReceiver *receiver) {
  if(receiver->sFlowRcvrAddress.type == SFLADDRESSTYPE_IP_V6) {
    struct sockaddr_in6 *sa6 = &receiver->receiver6;
    sa6->sin6_port = htons((uint16_t)receiver->sFlowRcvrPort);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_addr = receiver->sFlowRcvrAddress.address.ip_v6;
  }
  else {
    struct sockaddr_in *sa4 = &receiver->receiver4;
    sa4->sin_port = htons((uint16_t)receiver->sFlowRcvrPort);
    sa4->sin_family = AF_INET;
    sa4->sin_addr = receiver->sFlowRcvrAddress.address.ip_v4;
  }
}
#endif

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
  receiver->sFlowRcvrMaximumDatagramSize = mdz;
}
SFLAddress *sfl_receiver_get_sFlowRcvrAddress(SFLReceiver *receiver) {
  return &receiver->sFlowRcvrAddress;
}
void sfl_receiver_set_sFlowRcvrAddress(SFLReceiver *receiver, SFLAddress *sFlowRcvrAddress) {
  if(sFlowRcvrAddress) receiver->sFlowRcvrAddress = *sFlowRcvrAddress; // structure copy
#ifdef SFLOW_DO_SOCKET
  initSocket(receiver);
#endif
}
uint32_t sfl_receiver_get_sFlowRcvrPort(SFLReceiver *receiver) {
  return receiver->sFlowRcvrPort;
}
void sfl_receiver_set_sFlowRcvrPort(SFLReceiver *receiver, uint32_t sFlowRcvrPort) {
  receiver->sFlowRcvrPort = sFlowRcvrPort;
  // update the socket structure
#ifdef SFLOW_DO_SOCKET
  initSocket(receiver);
#endif
}

/*_________________---------------------------__________________
  _________________   sfl_receiver_tick       __________________
  -----------------___________________________------------------
*/

void sfl_receiver_tick(SFLReceiver *receiver, time_t now)
{
  // if there are any samples to send, flush them now
  if(receiver->sampleCollector.numSamples > 0) sendSample(receiver);
  // check the timeout
  if(receiver->sFlowRcvrTimeout && (uint32_t)receiver->sFlowRcvrTimeout != 0xFFFFFFFF) {
    // count down one tick and reset if we reach 0
    if(--receiver->sFlowRcvrTimeout == 0) reset(receiver);
  }
}

/*_________________-----------------------------__________________
  _________________   receiver write utilities  __________________
  -----------------_____________________________------------------
*/
 
static void put32(SFLReceiver *receiver, uint32_t val)
{
  *receiver->sampleCollector.datap++ = val;
}

static void putNet32(SFLReceiver *receiver, uint32_t val)
{
  *receiver->sampleCollector.datap++ = htonl(val);
}

static void putNetFloat(SFLReceiver *receiver, float val)
{
  // not sure how to byte-swap a float - just alias it to an int32
  uint32_t reg32;
  memcpy(&reg32, &val, 4);
  putNet32(receiver, reg32);
}

static void putNet32_run(SFLReceiver *receiver, void *obj, size_t quads)
{
  uint32_t *from = (uint32_t *)obj;
  while(quads--) putNet32(receiver, *from++);
}

static void putNet64(SFLReceiver *receiver, uint64_t val64)
{
  uint32_t *firstQuadPtr = receiver->sampleCollector.datap;
  // first copy the bytes in
  memcpy((u_char *)firstQuadPtr, &val64, 8);
  if(htonl(1) != 1) {
    // swap the bytes, and reverse the quads too
    uint32_t tmp = *receiver->sampleCollector.datap++;
    *firstQuadPtr = htonl(*receiver->sampleCollector.datap);
    *receiver->sampleCollector.datap++ = htonl(tmp);
  }
  else receiver->sampleCollector.datap += 2;
}

static void put128(SFLReceiver *receiver, u_char *val)
{
  memcpy(receiver->sampleCollector.datap, val, 16);
  receiver->sampleCollector.datap += 4;
}

static void putString(SFLReceiver *receiver, SFLString *s)
{
  putNet32(receiver, s->len);
  memcpy(receiver->sampleCollector.datap, s->str, s->len);
  receiver->sampleCollector.datap += (s->len + 3) / 4; /* pad to 4-byte boundary */
}

static uint32_t stringEncodingLength(SFLString *s) {
  // answer in bytes,  so remember to mulitply by 4 after rounding up to nearest 4-byte boundary
  return 4 + (((s->len + 3) / 4) * 4);
}

static void putAddress(SFLReceiver *receiver, SFLAddress *addr)
{
  // encode unspecified addresses as IPV4:0.0.0.0 - or should we flag this as an error?
  if(addr->type == 0) {
    putNet32(receiver, SFLADDRESSTYPE_IP_V4);
    put32(receiver, 0);
  }
  else {
    putNet32(receiver, addr->type);
    if(addr->type == SFLADDRESSTYPE_IP_V4) put32(receiver, addr->address.ip_v4.addr);
    else put128(receiver, addr->address.ip_v6.addr);
  }
}

static uint32_t addressEncodingLength(SFLAddress *addr) {
  return (addr->type == SFLADDRESSTYPE_IP_V6) ? 20 : 8;  // type + address (unspecified == IPV4)
}

static void putMACAddress(SFLReceiver *receiver, uint8_t *mac)
{
  memcpy(receiver->sampleCollector.datap, mac, 6);
  receiver->sampleCollector.datap += 2;
}

static void putSwitch(SFLReceiver *receiver, SFLExtended_switch *sw)
{
  putNet32(receiver, sw->src_vlan);
  putNet32(receiver, sw->src_priority);
  putNet32(receiver, sw->dst_vlan);
  putNet32(receiver, sw->dst_priority);
}

static void putRouter(SFLReceiver *receiver, SFLExtended_router *router)
{
  putAddress(receiver, &router->nexthop);
  putNet32(receiver, router->src_mask);
  putNet32(receiver, router->dst_mask);
}

static uint32_t routerEncodingLength(SFLExtended_router *router) {
  return addressEncodingLength(&router->nexthop) + 8;
}

static void putGateway(SFLReceiver *receiver, SFLExtended_gateway *gw)
{
  uint32_t seg;

  putAddress(receiver, &gw->nexthop);
  putNet32(receiver, gw->as);
  putNet32(receiver, gw->src_as);
  putNet32(receiver, gw->src_peer_as);
  putNet32(receiver, gw->dst_as_path_segments);
  for(seg = 0; seg < gw->dst_as_path_segments; seg++) {
    putNet32(receiver, gw->dst_as_path[seg].type);
    putNet32(receiver, gw->dst_as_path[seg].length);
    putNet32_run(receiver, gw->dst_as_path[seg].as.seq, gw->dst_as_path[seg].length);
  }
  putNet32(receiver, gw->communities_length);
  putNet32_run(receiver, gw->communities, gw->communities_length);
  putNet32(receiver, gw->localpref);
}

static uint32_t gatewayEncodingLength(SFLExtended_gateway *gw) {
  uint32_t seg, elemSiz;

  elemSiz = addressEncodingLength(&gw->nexthop);
  elemSiz += 16; // as, src_as, src_peer_as, dst_as_path_segments 
  for(seg = 0; seg < gw->dst_as_path_segments; seg++) {
    elemSiz += 8; // type, length 
    elemSiz += 4 * gw->dst_as_path[seg].length; // set/seq bytes
  }
  elemSiz += 4; // communities_length
  elemSiz += 4 * gw->communities_length; // communities
  elemSiz += 4; // localpref
  return elemSiz;
}

static uint32_t hostIdEncodingLength(SFLHost_hid_counters *hid) {
  uint32_t elemSiz = stringEncodingLength(&hid->hostname);
  elemSiz += 16; // uuid
  elemSiz += 4; // machine
  elemSiz += 4; // os
  elemSiz += stringEncodingLength(&hid->os_release);
  return elemSiz;
}

static void putUser(SFLReceiver *receiver, SFLExtended_user *user)
{
  putNet32(receiver, user->src_charset);
  putString(receiver, &user->src_user);
  putNet32(receiver, user->dst_charset);
  putString(receiver, &user->dst_user);
}

static uint32_t userEncodingLength(SFLExtended_user *user) {
  return 4
    + stringEncodingLength(&user->src_user)
    + 4
    + stringEncodingLength(&user->dst_user);
}

static void putUrl(SFLReceiver *receiver, SFLExtended_url *url)
{
  putNet32(receiver, url->direction);
  putString(receiver, &url->url);
  putString(receiver, &url->host);
}

static uint32_t urlEncodingLength(SFLExtended_url *url) {
  return 4
    + stringEncodingLength(&url->url)
    + stringEncodingLength(&url->host);
}

static void putLabelStack(SFLReceiver *receiver, SFLLabelStack *labelStack)
{
  putNet32(receiver, labelStack->depth);
  putNet32_run(receiver, labelStack->stack, labelStack->depth);
}

static uint32_t labelStackEncodingLength(SFLLabelStack *labelStack) {
  return 4 + (4 * labelStack->depth);
}

static void putMpls(SFLReceiver *receiver, SFLExtended_mpls *mpls)
{
  putAddress(receiver, &mpls->nextHop);
  putLabelStack(receiver, &mpls->in_stack);
  putLabelStack(receiver, &mpls->out_stack);
}

static uint32_t mplsEncodingLength(SFLExtended_mpls *mpls) {
  return addressEncodingLength(&mpls->nextHop)
    + labelStackEncodingLength(&mpls->in_stack)
    + labelStackEncodingLength(&mpls->out_stack);
}

static void putNat(SFLReceiver *receiver, SFLExtended_nat *nat)
{
  putAddress(receiver, &nat->src);
  putAddress(receiver, &nat->dst);
}

static uint32_t natEncodingLength(SFLExtended_nat *nat) {
  return addressEncodingLength(&nat->src)
    + addressEncodingLength(&nat->dst);
}

static void putMplsTunnel(SFLReceiver *receiver, SFLExtended_mpls_tunnel *tunnel)
{
  putString(receiver, &tunnel->tunnel_lsp_name);
  putNet32(receiver, tunnel->tunnel_id);
  putNet32(receiver, tunnel->tunnel_cos);
}

static uint32_t mplsTunnelEncodingLength(SFLExtended_mpls_tunnel *tunnel) {
  return stringEncodingLength(&tunnel->tunnel_lsp_name) + 8;
}

static void putMplsVc(SFLReceiver *receiver, SFLExtended_mpls_vc *vc)
{
  putString(receiver, &vc->vc_instance_name);
  putNet32(receiver, vc->vll_vc_id);
  putNet32(receiver, vc->vc_label_cos);
}

static uint32_t mplsVcEncodingLength(SFLExtended_mpls_vc *vc) {
  return stringEncodingLength( &vc->vc_instance_name) + 8;
}

static void putMplsFtn(SFLReceiver *receiver, SFLExtended_mpls_FTN *ftn)
{
  putString(receiver, &ftn->mplsFTNDescr);
  putNet32(receiver, ftn->mplsFTNMask);
}

static uint32_t mplsFtnEncodingLength(SFLExtended_mpls_FTN *ftn) {
  return stringEncodingLength( &ftn->mplsFTNDescr) + 4;
}

static void putMplsLdpFec(SFLReceiver *receiver, SFLExtended_mpls_LDP_FEC *ldpfec)
{
  putNet32(receiver, ldpfec->mplsFecAddrPrefixLength);
}

static uint32_t mplsLdpFecEncodingLength(SFLExtended_mpls_LDP_FEC *ldpfec) {
  return 4;
}

static void putVlanTunnel(SFLReceiver *receiver, SFLExtended_vlan_tunnel *vlanTunnel)
{
  putLabelStack(receiver, &vlanTunnel->stack);
}

static uint32_t vlanTunnelEncodingLength(SFLExtended_vlan_tunnel *vlanTunnel) {
  return labelStackEncodingLength(&vlanTunnel->stack);
}

static void putAdaptorList(SFLReceiver *receiver, SFLAdaptorList *adaptorList)
{
  uint32_t i, j;

  putNet32(receiver, adaptorList->num_adaptors);
  for(i = 0; i < adaptorList->num_adaptors; i++) {
    SFLAdaptor *adaptor = adaptorList->adaptors[i];
    putNet32(receiver, adaptor->ifIndex);
    putNet32(receiver, adaptor->num_macs);
    for(j = 0; j < adaptor->num_macs; j++) {
      putMACAddress(receiver, adaptor->macs[j].mac);
    }
  }
}

static uint32_t adaptorListEncodingLength(SFLAdaptorList *adaptorList)
{
  uint32_t i;
  uint32_t len = 4; // number of adaptors

  for(i = 0; i < adaptorList->num_adaptors; i++) {
    SFLAdaptor *adaptor = adaptorList->adaptors[i];
    len += 4; // ifIndex
    len += 4; // number of MACs
    len += (adaptor->num_macs * 8); // mac bytes
  }
  return len;
}

static void putGenericCounters(SFLReceiver *receiver, SFLIf_counters *counters)
{
  putNet32(receiver, counters->ifIndex);
  putNet32(receiver, counters->ifType);
  putNet64(receiver, counters->ifSpeed);
  putNet32(receiver, counters->ifDirection);
  putNet32(receiver, counters->ifStatus);
  putNet64(receiver, counters->ifInOctets);
  putNet32(receiver, counters->ifInUcastPkts);
  putNet32(receiver, counters->ifInMulticastPkts);
  putNet32(receiver, counters->ifInBroadcastPkts);
  putNet32(receiver, counters->ifInDiscards);
  putNet32(receiver, counters->ifInErrors);
  putNet32(receiver, counters->ifInUnknownProtos);
  putNet64(receiver, counters->ifOutOctets);
  putNet32(receiver, counters->ifOutUcastPkts);
  putNet32(receiver, counters->ifOutMulticastPkts);
  putNet32(receiver, counters->ifOutBroadcastPkts);
  putNet32(receiver, counters->ifOutDiscards);
  putNet32(receiver, counters->ifOutErrors);
  putNet32(receiver, counters->ifPromiscuousMode);
}


/*_________________-----------------------------__________________
  _________________      computeFlowSampleSize  __________________
  -----------------_____________________________------------------
*/

static int computeFlowSampleSize(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
  SFLFlow_sample_element *elem;
  uint32_t elemSiz;
#ifdef SFL_USE_32BIT_INDEX
  uint siz = 52; /* tag, length, sequence_number, ds_class, ds_index, sampling_rate,
		     sample_pool, drops, inputFormat, input, outputFormat, output, number of elements */
#else
  uint32_t siz = 40; /* tag, length, sequence_number, source_id, sampling_rate,
		     sample_pool, drops, input, output, number of elements */
#endif

  fs->num_elements = 0; /* we're going to count them again even if this was set by the client */
  for(elem = fs->elements; elem != NULL; elem = elem->nxt) {
    fs->num_elements++;
    siz += 8; /* tag, length */
    elemSiz = 0;
    switch(elem->tag) {
    case SFLFLOW_HEADER:
      elemSiz = 16; /* header_protocol, frame_length, stripped, header_length */
      elemSiz += ((elem->flowType.header.header_length + 3) / 4) * 4; /* header, rounded up to nearest 4 bytes */
      break;
    case SFLFLOW_ETHERNET: elemSiz = sizeof(SFLSampled_ethernet); break;
    case SFLFLOW_IPV4: elemSiz = sizeof(SFLSampled_ipv4); break;
    case SFLFLOW_IPV6: elemSiz = sizeof(SFLSampled_ipv6); break;
    case SFLFLOW_EX_SWITCH: elemSiz = sizeof(SFLExtended_switch); break;
    case SFLFLOW_EX_ROUTER: elemSiz = routerEncodingLength(&elem->flowType.router); break;
    case SFLFLOW_EX_GATEWAY: elemSiz = gatewayEncodingLength(&elem->flowType.gateway); break;
    case SFLFLOW_EX_USER: elemSiz = userEncodingLength(&elem->flowType.user); break;
    case SFLFLOW_EX_URL: elemSiz = urlEncodingLength(&elem->flowType.url); break;
    case SFLFLOW_EX_MPLS: elemSiz = mplsEncodingLength(&elem->flowType.mpls); break;
    case SFLFLOW_EX_NAT: elemSiz = natEncodingLength(&elem->flowType.nat); break;
    case SFLFLOW_EX_MPLS_TUNNEL: elemSiz = mplsTunnelEncodingLength(&elem->flowType.mpls_tunnel); break;
    case SFLFLOW_EX_MPLS_VC: elemSiz = mplsVcEncodingLength(&elem->flowType.mpls_vc); break;
    case SFLFLOW_EX_MPLS_FTN: elemSiz = mplsFtnEncodingLength(&elem->flowType.mpls_ftn); break;
    case SFLFLOW_EX_MPLS_LDP_FEC: elemSiz = mplsLdpFecEncodingLength(&elem->flowType.mpls_ldp_fec); break;
    case SFLFLOW_EX_VLAN_TUNNEL: elemSiz = vlanTunnelEncodingLength(&elem->flowType.vlan_tunnel); break;
    default:
      sflError(receiver, "unexpected packet_data_tag");
      return -1;
      break;
    }
    // cache the element size, and accumulate it into the overall FlowSample size
    elem->length = elemSiz;
    siz += elemSiz;
  }

  return siz;
}

/*_________________-------------------------------__________________
  _________________ sfl_receiver_writeFlowSample  __________________
  -----------------_______________________________------------------
*/

int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
  int packedSize;
  SFLFlow_sample_element *elem;

  if(fs == NULL) return -1;
  if((packedSize = computeFlowSampleSize(receiver, fs)) == -1) return -1;

  // check in case this one sample alone is too big for the datagram
  // in fact - if it is even half as big then we should ditch it. Very
  // important to avoid overruning the packet buffer.
  if(packedSize > (int)(receiver->sFlowRcvrMaximumDatagramSize)) {
    sflError(receiver, "flow sample too big for datagram");
    return -1;
  }

  // if the sample pkt is full enough so that this sample might put
  // it over the limit, then we should send it now before going on.
  if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
    sendSample(receiver);
    
  receiver->sampleCollector.numSamples++;

#ifdef SFL_USE_32BIT_INDEX
  putNet32(receiver, SFLFLOW_SAMPLE_EXPANDED);
#else
  putNet32(receiver, SFLFLOW_SAMPLE);
#endif

  putNet32(receiver, packedSize - 8); // don't include tag and len
  putNet32(receiver, fs->sequence_number);

#ifdef SFL_USE_32BIT_INDEX
  putNet32(receiver, fs->ds_class);
  putNet32(receiver, fs->ds_index);
#else
  putNet32(receiver, fs->source_id);
#endif

  putNet32(receiver, fs->sampling_rate);
  putNet32(receiver, fs->sample_pool);
  putNet32(receiver, fs->drops);

#ifdef SFL_USE_32BIT_INDEX
  putNet32(receiver, fs->inputFormat);
  putNet32(receiver, fs->input);
  putNet32(receiver, fs->outputFormat);
  putNet32(receiver, fs->output);
#else
  putNet32(receiver, fs->input);
  putNet32(receiver, fs->output);
#endif

  putNet32(receiver, fs->num_elements);

  for(elem = fs->elements; elem != NULL; elem = elem->nxt) {

    putNet32(receiver, elem->tag);
    putNet32(receiver, elem->length); // length cached in computeFlowSampleSize()

    switch(elem->tag) {
    case SFLFLOW_HEADER:
    putNet32(receiver, elem->flowType.header.header_protocol);
    putNet32(receiver, elem->flowType.header.frame_length);
    putNet32(receiver, elem->flowType.header.stripped);
    putNet32(receiver, elem->flowType.header.header_length);
    /* the header */
    memcpy(receiver->sampleCollector.datap, elem->flowType.header.header_bytes, elem->flowType.header.header_length);
    /* round up to multiple of 4 to preserve alignment */
    receiver->sampleCollector.datap += ((elem->flowType.header.header_length + 3) / 4);
      break;
    case SFLFLOW_ETHERNET:
      putNet32(receiver, elem->flowType.ethernet.eth_len);
      putMACAddress(receiver, elem->flowType.ethernet.src_mac);
      putMACAddress(receiver, elem->flowType.ethernet.dst_mac);
      putNet32(receiver, elem->flowType.ethernet.eth_type);
      break;
    case SFLFLOW_IPV4:
      putNet32(receiver, elem->flowType.ipv4.length);
      putNet32(receiver, elem->flowType.ipv4.protocol);
      put32(receiver, elem->flowType.ipv4.src_ip.addr);
      put32(receiver, elem->flowType.ipv4.dst_ip.addr);
      putNet32(receiver, elem->flowType.ipv4.src_port);
      putNet32(receiver, elem->flowType.ipv4.dst_port);
      putNet32(receiver, elem->flowType.ipv4.tcp_flags);
      putNet32(receiver, elem->flowType.ipv4.tos);
      break;
    case SFLFLOW_IPV6:
      putNet32(receiver, elem->flowType.ipv6.length);
      putNet32(receiver, elem->flowType.ipv6.protocol);
      put128(receiver, elem->flowType.ipv6.src_ip.addr);
      put128(receiver, elem->flowType.ipv6.dst_ip.addr);
      putNet32(receiver, elem->flowType.ipv6.src_port);
      putNet32(receiver, elem->flowType.ipv6.dst_port);
      putNet32(receiver, elem->flowType.ipv6.tcp_flags);
      putNet32(receiver, elem->flowType.ipv6.priority);
      break;
    case SFLFLOW_EX_SWITCH: putSwitch(receiver, &elem->flowType.sw); break;
    case SFLFLOW_EX_ROUTER: putRouter(receiver, &elem->flowType.router); break;
    case SFLFLOW_EX_GATEWAY: putGateway(receiver, &elem->flowType.gateway); break;
    case SFLFLOW_EX_USER: putUser(receiver, &elem->flowType.user); break;
    case SFLFLOW_EX_URL: putUrl(receiver, &elem->flowType.url); break;
    case SFLFLOW_EX_MPLS: putMpls(receiver, &elem->flowType.mpls); break;
    case SFLFLOW_EX_NAT: putNat(receiver, &elem->flowType.nat); break;
    case SFLFLOW_EX_MPLS_TUNNEL: putMplsTunnel(receiver, &elem->flowType.mpls_tunnel); break;
    case SFLFLOW_EX_MPLS_VC: putMplsVc(receiver, &elem->flowType.mpls_vc); break;
    case SFLFLOW_EX_MPLS_FTN: putMplsFtn(receiver, &elem->flowType.mpls_ftn); break;
    case SFLFLOW_EX_MPLS_LDP_FEC: putMplsLdpFec(receiver, &elem->flowType.mpls_ldp_fec); break;
    case SFLFLOW_EX_VLAN_TUNNEL: putVlanTunnel(receiver, &elem->flowType.vlan_tunnel); break;
    default:
      sflError(receiver, "unexpected packet_data_tag");
      return -1;
      break;
    }
  }

  // sanity check
  assert(((u_char *)receiver->sampleCollector.datap
	  - (u_char *)receiver->sampleCollector.data
	  - receiver->sampleCollector.pktlen)  == (uint32_t)packedSize);

  // update the pktlen
  receiver->sampleCollector.pktlen = (u_char *)receiver->sampleCollector.datap - (u_char *)receiver->sampleCollector.data;
  return packedSize;
}

/*_________________-----------------------------__________________
  _________________ computeCountersSampleSize   __________________
  -----------------_____________________________------------------
*/

static int computeCountersSampleSize(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
  SFLCounters_sample_element *elem;
  uint32_t elemSiz;

#ifdef SFL_USE_32BIT_INDEX
  uint siz = 24; /* tag, length, sequence_number, ds_class, ds_index, number of elements */
#else
  uint32_t siz = 20; /* tag, length, sequence_number, source_id, number of elements */
#endif

  cs->num_elements = 0; /* we're going to count them again even if this was set by the client */
  for( elem = cs->elements; elem != NULL; elem = elem->nxt) {
    cs->num_elements++;
    siz += 8; /* tag, length */
    elemSiz = 0;
    /* here we are assuming that the structure fields are not expanded to be 64-bit aligned,
       because then the sizeof(struct) would be larger than the wire-encoding. */

    switch(elem->tag) {
    case SFLCOUNTERS_GENERIC:  elemSiz = sizeof(elem->counterBlock.generic); break;
    case SFLCOUNTERS_ETHERNET: elemSiz = sizeof(elem->counterBlock.ethernet); break;
    case SFLCOUNTERS_TOKENRING: elemSiz = sizeof(elem->counterBlock.tokenring); break;
    case SFLCOUNTERS_VG: elemSiz = sizeof(elem->counterBlock.vg); break;
    case SFLCOUNTERS_VLAN: elemSiz = sizeof(elem->counterBlock.vlan); break;
    case SFLCOUNTERS_PROCESSOR: elemSiz = sizeof(elem->counterBlock.processor);  break;
    case SFLCOUNTERS_HOST_HID: elemSiz = hostIdEncodingLength(&elem->counterBlock.host_hid);  break;
    case SFLCOUNTERS_HOST_PAR: elemSiz = 8 /*sizeof(elem->counterBlock.host_par)*/;  break;
    case SFLCOUNTERS_ADAPTORS: elemSiz = adaptorListEncodingLength(elem->counterBlock.adaptors);  break;
    case SFLCOUNTERS_HOST_CPU: elemSiz = 68 /*sizeof(elem->counterBlock.host_cpu)*/;  break;
    case SFLCOUNTERS_HOST_MEM: elemSiz = 72 /*sizeof(elem->counterBlock.host_mem)*/ ;  break;
    case SFLCOUNTERS_HOST_DSK: elemSiz = 52 /*sizeof(elem->counterBlock.host_dsk)*/;  break;
    case SFLCOUNTERS_HOST_NIO: elemSiz = 40 /*sizeof(elem->counterBlock.host_nio)*/;  break;
    case SFLCOUNTERS_HOST_VRT_NODE: elemSiz = 28 /*sizeof(elem->counterBlock.host_vrt_node)*/;  break;
    case SFLCOUNTERS_HOST_VRT_CPU: elemSiz = 12 /*sizeof(elem->counterBlock.host_vrt_cpu)*/;  break;
    case SFLCOUNTERS_HOST_VRT_MEM: elemSiz = 16 /*sizeof(elem->counterBlock.host_vrt_mem)*/;  break;
    case SFLCOUNTERS_HOST_VRT_DSK: elemSiz = 52 /*sizeof(elem->counterBlock.host_vrt_dsk)*/;  break;
    case SFLCOUNTERS_HOST_VRT_NIO: elemSiz = 40 /*sizeof(elem->counterBlock.host_vrt_nio)*/;  break;
    default:
      {
	char errm[128];
	sprintf(errm, "computeCounterSampleSize(): unexpected counters tag (%u)", elem->tag);
	sflError(receiver, errm);
	return -1;
      }
      break;
    }
    // cache the element size, and accumulate it into the overall FlowSample size
    elem->length = elemSiz;
    siz += elemSiz;
  }
  return siz;
}

/*_________________----------------------------------__________________
  _________________ sfl_receiver_writeCountersSample __________________
  -----------------__________________________________------------------
*/

int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
  int packedSize;
  SFLCounters_sample_element *elem;

  if(cs == NULL) return -1;
  // if the sample pkt is full enough so that this sample might put
  // it over the limit, then we should send it now.
  if((packedSize = computeCountersSampleSize(receiver, cs)) == -1) return -1;
  
  // check in case this one sample alone is too big for the datagram
  // in fact - if it is even half as big then we should ditch it. Very
  // important to avoid overruning the packet buffer.
  if(packedSize > (int)(receiver->sFlowRcvrMaximumDatagramSize)) {
    sflError(receiver, "counters sample too big for datagram");
    return -1;
  }
  
  if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
    sendSample(receiver);
  
  receiver->sampleCollector.numSamples++;
  
#ifdef SFL_USE_32BIT_INDEX
  putNet32(receiver, SFLCOUNTERS_SAMPLE_EXPANDED);
#else
  putNet32(receiver, SFLCOUNTERS_SAMPLE);
#endif

  putNet32(receiver, packedSize - 8); // tag and length not included
  putNet32(receiver, cs->sequence_number);

#ifdef SFL_USE_32BIT_INDEX
  putNet32(receiver, cs->ds_class);
  putNet32(receiver, cs->ds_index);
#else
  putNet32(receiver, cs->source_id);
#endif

  putNet32(receiver, cs->num_elements);
  
  for(elem = cs->elements; elem != NULL; elem = elem->nxt) {
    
    putNet32(receiver, elem->tag);
    putNet32(receiver, elem->length); // length cached in computeCountersSampleSize()
    
    switch(elem->tag) {
    case SFLCOUNTERS_GENERIC:
      putGenericCounters(receiver, &(elem->counterBlock.generic));
      break;
    case SFLCOUNTERS_ETHERNET:
      // all these counters are 32-bit
      putNet32_run(receiver, &elem->counterBlock.ethernet, sizeof(elem->counterBlock.ethernet) / 4);
      break;
    case SFLCOUNTERS_TOKENRING:
      // all these counters are 32-bit
      putNet32_run(receiver, &elem->counterBlock.tokenring, sizeof(elem->counterBlock.tokenring) / 4);
      break;
    case SFLCOUNTERS_VG:
      putNet32(receiver, elem->counterBlock.vg.dot12InHighPriorityFrames);
      putNet64(receiver, elem->counterBlock.vg.dot12InHighPriorityOctets);
      putNet32(receiver, elem->counterBlock.vg.dot12InNormPriorityFrames);
      putNet64(receiver, elem->counterBlock.vg.dot12InNormPriorityOctets);
      putNet32(receiver, elem->counterBlock.vg.dot12InIPMErrors);
      putNet32(receiver, elem->counterBlock.vg.dot12InOversizeFrameErrors);
      putNet32(receiver, elem->counterBlock.vg.dot12InDataErrors);
      putNet32(receiver, elem->counterBlock.vg.dot12InNullAddressedFrames);
      putNet32(receiver, elem->counterBlock.vg.dot12OutHighPriorityFrames);
      putNet64(receiver, elem->counterBlock.vg.dot12OutHighPriorityOctets);
      putNet32(receiver, elem->counterBlock.vg.dot12TransitionIntoTrainings);
      putNet64(receiver, elem->counterBlock.vg.dot12HCInHighPriorityOctets);
      putNet64(receiver, elem->counterBlock.vg.dot12HCInNormPriorityOctets);
      putNet64(receiver, elem->counterBlock.vg.dot12HCOutHighPriorityOctets);
      break;
    case SFLCOUNTERS_VLAN:
      putNet32(receiver, elem->counterBlock.vlan.vlan_id);
      putNet64(receiver, elem->counterBlock.vlan.octets);
      putNet32(receiver, elem->counterBlock.vlan.ucastPkts);
      putNet32(receiver, elem->counterBlock.vlan.multicastPkts);
      putNet32(receiver, elem->counterBlock.vlan.broadcastPkts);
      putNet32(receiver, elem->counterBlock.vlan.discards);
      break;
    case SFLCOUNTERS_PROCESSOR:
      putNet32(receiver, elem->counterBlock.processor.five_sec_cpu);
      putNet32(receiver, elem->counterBlock.processor.one_min_cpu);
      putNet32(receiver, elem->counterBlock.processor.five_min_cpu);
      putNet64(receiver, elem->counterBlock.processor.total_memory);
      putNet64(receiver, elem->counterBlock.processor.free_memory);
      break;
    case SFLCOUNTERS_HOST_HID:
      putString(receiver, &elem->counterBlock.host_hid.hostname);
      put128(receiver, elem->counterBlock.host_hid.uuid);
      putNet32(receiver, elem->counterBlock.host_hid.machine_type);
      putNet32(receiver, elem->counterBlock.host_hid.os_name);
      putString(receiver, &elem->counterBlock.host_hid.os_release);
      break;
    case SFLCOUNTERS_HOST_PAR:
      putNet32(receiver, elem->counterBlock.host_par.dsClass);
      putNet32(receiver, elem->counterBlock.host_par.dsIndex);
      break;
    case SFLCOUNTERS_ADAPTORS:
      putAdaptorList(receiver, elem->counterBlock.adaptors);
      break;
    case SFLCOUNTERS_HOST_CPU:
      putNetFloat(receiver, elem->counterBlock.host_cpu.load_one);
      putNetFloat(receiver, elem->counterBlock.host_cpu.load_five);
      putNetFloat(receiver, elem->counterBlock.host_cpu.load_fifteen);
      putNet32(receiver, elem->counterBlock.host_cpu.proc_run);
      putNet32(receiver, elem->counterBlock.host_cpu.proc_total);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_num);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_speed);
      putNet32(receiver, elem->counterBlock.host_cpu.uptime);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_user);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_nice);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_system);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_idle);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_wio);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_intr);
      putNet32(receiver, elem->counterBlock.host_cpu.cpu_sintr);
      putNet32(receiver, elem->counterBlock.host_cpu.interrupts);
      putNet32(receiver, elem->counterBlock.host_cpu.contexts);
      break;
    case SFLCOUNTERS_HOST_MEM:
      putNet64(receiver, elem->counterBlock.host_mem.mem_total);
      putNet64(receiver, elem->counterBlock.host_mem.mem_free);
      putNet64(receiver, elem->counterBlock.host_mem.mem_shared);
      putNet64(receiver, elem->counterBlock.host_mem.mem_buffers);
      putNet64(receiver, elem->counterBlock.host_mem.mem_cached);
      putNet64(receiver, elem->counterBlock.host_mem.swap_total);
      putNet64(receiver, elem->counterBlock.host_mem.swap_free);
      putNet32(receiver, elem->counterBlock.host_mem.page_in);
      putNet32(receiver, elem->counterBlock.host_mem.page_out);
      putNet32(receiver, elem->counterBlock.host_mem.swap_in);
      putNet32(receiver, elem->counterBlock.host_mem.swap_out);
      break;
    case SFLCOUNTERS_HOST_DSK:
      putNet64(receiver, elem->counterBlock.host_dsk.disk_total);
      putNet64(receiver, elem->counterBlock.host_dsk.disk_free);
      putNet32(receiver, elem->counterBlock.host_dsk.part_max_used);
      putNet32(receiver, elem->counterBlock.host_dsk.reads);
      putNet64(receiver, elem->counterBlock.host_dsk.bytes_read);
      putNet32(receiver, elem->counterBlock.host_dsk.read_time);
      putNet32(receiver, elem->counterBlock.host_dsk.writes);
      putNet64(receiver, elem->counterBlock.host_dsk.bytes_written);
      putNet32(receiver, elem->counterBlock.host_dsk.write_time);
      break;
    case SFLCOUNTERS_HOST_NIO:
      putNet64(receiver, elem->counterBlock.host_nio.bytes_in);
      putNet32(receiver, elem->counterBlock.host_nio.pkts_in);
      putNet32(receiver, elem->counterBlock.host_nio.errs_in);
      putNet32(receiver, elem->counterBlock.host_nio.drops_in);
      putNet64(receiver, elem->counterBlock.host_nio.bytes_out);
      putNet32(receiver, elem->counterBlock.host_nio.pkts_out);
      putNet32(receiver, elem->counterBlock.host_nio.errs_out);
      putNet32(receiver, elem->counterBlock.host_nio.drops_out);
      break;
    case SFLCOUNTERS_HOST_VRT_NODE:
      putNet32(receiver, elem->counterBlock.host_vrt_node.mhz);
      putNet32(receiver, elem->counterBlock.host_vrt_node.cpus);
      putNet64(receiver, elem->counterBlock.host_vrt_node.memory);
      putNet64(receiver, elem->counterBlock.host_vrt_node.memory_free);
      putNet32(receiver, elem->counterBlock.host_vrt_node.num_domains);
      break;
    case SFLCOUNTERS_HOST_VRT_CPU:
      putNet32(receiver, elem->counterBlock.host_vrt_cpu.state);
      putNet32(receiver, elem->counterBlock.host_vrt_cpu.cpuTime);
      putNet32(receiver, elem->counterBlock.host_vrt_cpu.nrVirtCpu);
      break;
    case SFLCOUNTERS_HOST_VRT_MEM:
      putNet64(receiver, elem->counterBlock.host_vrt_mem.memory);
      putNet64(receiver, elem->counterBlock.host_vrt_mem.maxMemory);
      break;
    case SFLCOUNTERS_HOST_VRT_DSK:
      putNet64(receiver, elem->counterBlock.host_vrt_dsk.capacity);
      putNet64(receiver, elem->counterBlock.host_vrt_dsk.allocation);
      putNet64(receiver, elem->counterBlock.host_vrt_dsk.available);
      putNet32(receiver, elem->counterBlock.host_vrt_dsk.rd_req);
      putNet64(receiver, elem->counterBlock.host_vrt_dsk.rd_bytes);
      putNet32(receiver, elem->counterBlock.host_vrt_dsk.wr_req);
      putNet64(receiver, elem->counterBlock.host_vrt_dsk.wr_bytes);
      putNet32(receiver, elem->counterBlock.host_vrt_dsk.errs);
      break;
    case SFLCOUNTERS_HOST_VRT_NIO:
      putNet64(receiver, elem->counterBlock.host_vrt_nio.bytes_in);
      putNet32(receiver, elem->counterBlock.host_vrt_nio.pkts_in);
      putNet32(receiver, elem->counterBlock.host_vrt_nio.errs_in);
      putNet32(receiver, elem->counterBlock.host_vrt_nio.drops_in);
      putNet64(receiver, elem->counterBlock.host_vrt_nio.bytes_out);
      putNet32(receiver, elem->counterBlock.host_vrt_nio.pkts_out);
      putNet32(receiver, elem->counterBlock.host_vrt_nio.errs_out);
      putNet32(receiver, elem->counterBlock.host_vrt_nio.drops_out);
      break;
    default:
      {
	char errm[128];
	sprintf(errm, "unexpected counters tag (%u)", elem->tag);
	sflError(receiver, errm);
	return -1;
      }
      break;
    }
  }
  // sanity check
  assert(((u_char *)receiver->sampleCollector.datap
	  - (u_char *)receiver->sampleCollector.data
	  - receiver->sampleCollector.pktlen)  == (uint32_t)packedSize);

  // update the pktlen
  receiver->sampleCollector.pktlen = (u_char *)receiver->sampleCollector.datap - (u_char *)receiver->sampleCollector.data;
  return packedSize;
}

/*_________________---------------------------------__________________
  _________________ sfl_receiver_samplePacketsSent  __________________
  -----------------_________________________________------------------
*/

uint32_t sfl_receiver_samplePacketsSent(SFLReceiver *receiver)
{
  return receiver->sampleCollector.packetSeqNo;
}

/*_________________---------------------------__________________
  _________________     sendSample            __________________
  -----------------___________________________------------------
*/

static void sendSample(SFLReceiver *receiver)
{  
  /* construct and send out the sample, then reset for the next one... */
  SFLAgent *agent = receiver->agent;
  
  /* go back and fill in the header */
  receiver->sampleCollector.datap = receiver->sampleCollector.data;
  putNet32(receiver, SFLDATAGRAM_VERSION5);
  putAddress(receiver, &agent->myIP);
  putNet32(receiver, agent->subId);
  putNet32(receiver, ++receiver->sampleCollector.packetSeqNo);
  putNet32(receiver,  (uint32_t)((agent->now - agent->bootTime) * 1000));
  putNet32(receiver, receiver->sampleCollector.numSamples);
  
  /* send */
  if(agent->sendFn) (*agent->sendFn)(agent->magic,
				     agent,
				     receiver,
				     (u_char *)receiver->sampleCollector.data, 
				     receiver->sampleCollector.pktlen);
  else {
#ifdef SFLOW_DO_SOCKET
    /* send it myself */
    if (receiver->sFlowRcvrAddress.type == SFLADDRESSTYPE_IP_V6) {
      uint32_t soclen = sizeof(struct sockaddr_in6);
      int result = sendto(agent->receiverSocket6,
			  receiver->sampleCollector.data,
			  receiver->sampleCollector.pktlen,
			  0,
			  (struct sockaddr *)&receiver->receiver6,
			  soclen);
      if(result == -1 && errno != EINTR) sfl_agent_sysError(agent, "receiver", "IPv6 socket sendto error");
      if(result == 0) sfl_agent_error(agent, "receiver", "IPv6 socket sendto returned 0");
    }
    else {
      uint32_t soclen = sizeof(struct sockaddr_in);
      int result = sendto(agent->receiverSocket4,
			  receiver->sampleCollector.data,
			  receiver->sampleCollector.pktlen,
			  0,
			  (struct sockaddr *)&receiver->receiver4,
			  soclen);
      if(result == -1 && errno != EINTR) sfl_agent_sysError(agent, "receiver", "socket sendto error");
      if(result == 0) sfl_agent_error(agent, "receiver", "socket sendto returned 0");
    }
#endif
  }

  /* reset for the next time */
  resetSampleCollector(receiver);
}

/*_________________---------------------------__________________
  _________________   resetSampleCollector    __________________
  -----------------___________________________------------------
*/

static void resetSampleCollector(SFLReceiver *receiver)
{
  receiver->sampleCollector.pktlen = 0;
  receiver->sampleCollector.numSamples = 0;

  /* clear the buffer completely (ensures that pad bytes will always be zeros - thank you CW) */
  memset((u_char *)receiver->sampleCollector.data, 0, (SFL_SAMPLECOLLECTOR_DATA_QUADS * 4));

  /* point the datap to just after the header */
  receiver->sampleCollector.datap = (receiver->agent->myIP.type == SFLADDRESSTYPE_IP_V6) ?
    (receiver->sampleCollector.data + 10) :
    (receiver->sampleCollector.data + 7);

  /* start pktlen with the right value */
  receiver->sampleCollector.pktlen = (u_char *)receiver->sampleCollector.datap - (u_char *)receiver->sampleCollector.data;
}

/*_________________---------------------------__________________
  _________________         sflError          __________________
  -----------------___________________________------------------
*/

static void sflError(SFLReceiver *receiver, char *msg)
{
  sfl_agent_error(receiver->agent, "receiver", msg);
  resetSampleCollector(receiver);
}


#if defined(__cplusplus)
} /* extern "C" */
#endif
