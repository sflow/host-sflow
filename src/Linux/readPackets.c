/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>


  /*_________________---------------------------__________________
    _________________       getPoller           __________________
    -----------------___________________________------------------
  */

  static void getPoller(HSP *sp, SFLAdaptor *adaptor)
  {
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    if(adaptorNIO->poller == NULL) {
      // Make sure we don't queue a flurry of requests by limiting to one per second
      time_t now_mono_S = EVCurrentBus()->now.tv_sec;
      if(adaptorNIO->poller_requested != now_mono_S) {
	adaptorNIO->poller_requested = now_mono_S;
	// message this request to the pollBus
	EVEvent *req_poller = EVGetEvent(sp->pollBus, HSPEVENT_REQUEST_POLLER);
	EVEventTx(sp->rootModule, req_poller, &adaptor->ifIndex, sizeof(adaptor->ifIndex));
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   forceCounterPolling     __________________
    -----------------___________________________------------------
  */

  void forceCounterPolling(HSP *sp, SFLAdaptor *adaptor) {
    getPoller(sp, adaptor);
  }

  /*_________________---------------------------__________________
    _________________       getSampler          __________________
    -----------------___________________________------------------
  */

  static SFLSampler *getSampler(HSP *sp, SFLAdaptor *adaptor)
  {
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    if(adaptorNIO->sampler == NULL) {
      SFLDataSource_instance dsi;
      SFL_DS_SET(dsi, 0, adaptor->ifIndex, 0); // ds_class,ds_index,ds_instance
      // add sampler to packet-bus agent
      adaptorNIO->sampler = sfl_agent_addSampler(sp->agent, &dsi);
      sfl_sampler_set_sFlowFsReceiver(adaptorNIO->sampler, HSP_SFLOW_RECEIVER_INDEX);
      // TODO: adapt if headerBytes changes dynamically in config settings - broadcast event?
      // same as for changes in polling interval or datagram size?
      sfl_sampler_set_sFlowFsMaximumHeaderSize(adaptorNIO->sampler, sp->sFlowSettings->headerBytes);
    }
    return adaptorNIO->sampler;
  }


  /*_________________---------------------------__________________
    _________________     pendingSample         __________________
    -----------------___________________________------------------
  */

  static HSPPendingSample *pendingSampleNew(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs)  {
    HSPPendingSample *ps = (HSPPendingSample *)my_calloc(sizeof(HSPPendingSample));
    ps->fs = fs;
    ps->sampler = sampler;
    ps->refCount = 1;
    ps->ptrsToFree = UTArrayNew(UTARRAY_DFLT);
    return ps;
  }

  static void pendingSample_addHeapPtr(HSPPendingSample *ps, void *ptr) {
    UTArrayAdd(ps->ptrsToFree, ptr);
  }

  void *pendingSample_calloc(HSPPendingSample *ps, size_t len) {
    void *ptr = my_calloc(len);
    pendingSample_addHeapPtr(ps, ptr);
    return ptr;
  }

  void holdPendingSample(HSPPendingSample *ps) {
    ps->refCount++;
  }

  void releasePendingSample(HSP *sp, HSPPendingSample *ps)
  {
    if(--ps->refCount == 0) {
      EVBus *bus = EVCurrentBus();

      // some consumers of packet-samples will want to wait until everyone has
      // looked at it and released it before they process it. For example, mod_k8s
      // wants the sample after any netlink DIAG lookup has been performed on it.
      if(sp->evt_flow_sample_released == NULL)
	sp->evt_flow_sample_released = EVGetEvent(bus, HSPEVENT_FLOW_SAMPLE_RELEASED);
      EVEventTx(sp->rootModule, sp->evt_flow_sample_released, ps, sizeof(*ps));
      
      if(ps->suppress) {
	sp->telemetry[HSP_TELEMETRY_FLOW_SAMPLES_SUPPRESSED]++;
      }
      else {
	sfl_agent_set_now(ps->sampler->agent, bus->now.tv_sec, bus->now.tv_nsec);
	sfl_sampler_writeFlowSample(ps->sampler, ps->fs);
	sp->telemetry[HSP_TELEMETRY_FLOW_SAMPLES]++;
      }
      void *ptr;
      UTARRAY_WALK(ps->ptrsToFree, ptr)
	my_free(ptr);
      UTArrayFree(ps->ptrsToFree);
      my_free(ps->fs);
      my_free(ps);
    }
  }

  /*_________________---------------------------__________________
    _________________    takeSample             __________________
    -----------------___________________________------------------
    TODO: if we split takeSample() into buildSample()
    and submitSample() then we could attach extensions
    more naturally in between, and make their lifecycle
    more explicit.  Could probably also streamline the
    more common paths (from mod_psample and mod_pcap) and
    corral legacy features like mod_ulog's disjoint mac-header.
  */

  void takeSample(HSP *sp, SFLAdaptor *ad_in, SFLAdaptor *ad_out, SFLAdaptor *ad_tap, uint32_t options, uint32_t hook, const u_char *mac_hdr, uint32_t mac_len, const u_char *cap_hdr, uint32_t cap_len, uint32_t pkt_len, uint32_t drops, uint32_t sampling_n, SFLFlow_sample_element *extended_elements)
  {
    EVMod *mod = sp->rootModule;
    if(EVDebug(mod, 2, NULL)) {
      u_char macdst[13], macsrc[13];
      macdst[0]='\0';
      macsrc[0]='\0';
      uint16_t ethtype = 0;
      if(mac_hdr
	 && mac_len == 14) {
	printHex(mac_hdr+6,6,macsrc,12,NO);
	macsrc[12] = '\0';
	printHex(mac_hdr+0,6,macdst,12,NO);
	macdst[12] = '\0';
	ethtype = (mac_hdr[12] << 8) + mac_hdr[13];
      }
      EVDebug(mod, 1, "takeSample: hook=%u tap=%s in=%s out=%s pkt_len=%u cap_len=%u mac_len=%u (%s -> %s et=0x%04X)",
	    hook,
	    ad_tap ? ad_tap->deviceName : "<no tap>",
	    ad_in ? ad_in->deviceName : "<not found>",
	    ad_out ? ad_out->deviceName : "<not found>",
	    pkt_len,
	    cap_len,
	    mac_len,
	    macsrc,
	    macdst,
	    ethtype);
    }
    
    uint32_t dsopts = options;

    if(dsopts & HSP_SAMPLEOPT_DIRN_HOOK) {
      // On Cumulus Linux the sampling direction is indicated in the low
      // bit of the pkt->hook field: 0==ingress,1==egress
      if(hook & 1) dsopts |= HSP_SAMPLEOPT_EGRESS;
      else dsopts |= HSP_SAMPLEOPT_INGRESS;
    }
      
    bool bridgeModel = (dsopts & HSP_SAMPLEOPT_BRIDGE) ? YES : NO;

    // If it is the container-end of a veth pair, then we want to
    // map it back to the other end that is in the global-namespace,
    // Since those are the bridge ports.
    if(ad_in) {
      if(ADAPTOR_NIO(ad_in)->vm_or_container)
	bridgeModel = YES;
      SFLAdaptor *ad_in_global = adaptorByPeerIndex(sp, ad_in->ifIndex);
      if(ad_in_global) {
	EVDebug(mod, 1, "GlobalNS veth peer ad_in=%s(%u)",
		ad_in_global->deviceName,
		ad_in_global->ifIndex);
	bridgeModel = YES;
	ad_in = ad_in_global;
      }
    }
    if(ad_out) {
      if(ADAPTOR_NIO(ad_out)->vm_or_container)
	bridgeModel = YES;
      SFLAdaptor *ad_out_global = adaptorByPeerIndex(sp, ad_out->ifIndex);
      if(ad_out_global) {
	EVDebug(mod, 1, "GlobalNS veth peer ad_out=%s(%u)",
		ad_out_global->deviceName,
		ad_out_global->ifIndex);
	bridgeModel = YES;
	ad_out = ad_out_global;
      }
    }

    int internal_in = NO;
    int internal_out = NO;
    
    if(bridgeModel == NO) {
      // model this as a standalone host, so that
      // packets go to and from the "internal" interface.
      if(ad_in) {
	internal_in = YES;
	ad_out = ad_in;
	ad_in = NULL;
      }
      else if(ad_out) {
	internal_out = YES;
	ad_in = ad_out;
	ad_out = NULL;
      }
    }

    SFL_FLOW_SAMPLE_TYPE *fs = my_calloc(sizeof(SFL_FLOW_SAMPLE_TYPE));

    // set the ingress and egress ifIndex numbers.
    // Can be "INTERNAL" (0x3FFFFFFF) or "UNKNOWN" (0).
    fs->input = ad_in ? ad_in->ifIndex : (internal_in ? SFL_INTERNAL_INTERFACE : 0);
    fs->output = ad_out ? ad_out->ifIndex : (internal_out ? SFL_INTERNAL_INTERFACE : 0);

    SFLAdaptor *sampler_dev = ad_tap;
    if(ad_tap
       && (dsopts & HSP_SAMPLEOPT_DEV_SAMPLER)) {
      // For pcap device tap monitoring there may be no useful sense of 'in'
      // or 'out' on this adaptor, but we can still set the sampler_dev.
      // This can also be forced with a flag,  which helps if there are
      // MACs showing up that do not map to ports (e.g. Docker swarm VIP MACs)
      sampler_dev = ad_tap;
      if(dsopts & HSP_SAMPLEOPT_DEV_POLLER)
	getPoller(sp, ad_tap);
    }
    else if(ad_out
	    && (dsopts & HSP_SAMPLEOPT_EGRESS))
      sampler_dev = ad_out;
    else if(ad_in
	    && (dsopts & HSP_SAMPLEOPT_INGRESS))
      sampler_dev = ad_in;
    else {
      // We have to infer ingress/egress.
      // If the ingress was a loopback and the egress is not -- and the
      // egress has an ifIndex,  then switch this over to indicate egress
      // sampling.  In a typical host scenario most samples will be
      // "lo" -> "eth0" or "eth0" -> "lo", so this ensures that
      // that we present it as bidirectional sampling on eth0.
      sampler_dev = ad_in ?: ad_out;
      if(ad_in
	 && ad_out
	 && ADAPTOR_NIO(ad_in)->loopback
	 && !ADAPTOR_NIO(ad_out)->loopback
	 && ad_out->ifIndex)
	sampler_dev = ad_out;
    }

    // must have a sampler_dev with an ifIndex
    if(sampler_dev == NULL
       || sampler_dev->ifIndex == 0) {
      EVDebug(mod, 1, "warning: takeSample found no sampler_dev with ifIndex");
      return;
    }
    EVDebug(mod, 2, "selected sampler %s ifIndex=%u",
	    sampler_dev->deviceName,
	    sampler_dev->ifIndex);
    
    SFLSampler *sampler = getSampler(sp, sampler_dev);
    assert(sampler != NULL);

    // may want to kick off an interface poller too,
    // even if it has no corresponding sampler
    if(dsopts & HSP_SAMPLEOPT_IF_POLLER) {
      if(ad_in
	 && ad_in->ifIndex
	 && !ADAPTOR_NIO(ad_in)->loopback)
	getPoller(sp, ad_in);
      if(ad_out
	 && ad_out->ifIndex
	 && !ADAPTOR_NIO(ad_out)->loopback)
	getPoller(sp, ad_out);
    }

    // build the sampled header structure
    HSPPendingSample *ps = pendingSampleNew(sampler, fs);
    bool sendPS = YES;
    SFLFlow_sample_element *hdrElem = pendingSample_calloc(ps, sizeof(SFLFlow_sample_element));
    hdrElem->tag = SFLFLOW_HEADER;
    uint32_t FCS_bytes = 4;
    uint32_t maxHdrLen = sampler->sFlowFsMaximumHeaderSize;
    hdrElem->flowType.header.header_bytes = (u_char *)pendingSample_calloc(ps, maxHdrLen);
    hdrElem->flowType.header.frame_length = pkt_len + FCS_bytes;
    hdrElem->flowType.header.stripped = FCS_bytes;
    
    uint64_t mac_hdr_test=0;
    if(mac_hdr && mac_len > 8) {
      memcpy(&mac_hdr_test, mac_hdr, 8);
    }
    
    if(mac_len == 14
       && mac_hdr_test != 0) {
      // set the header_protocol to ethernet and
      // reunite the mac header and payload in one buffer
      hdrElem->flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
      memcpy(hdrElem->flowType.header.header_bytes, mac_hdr, mac_len);
      maxHdrLen -= mac_len;
      uint32_t payloadBytes = (cap_len < maxHdrLen) ? cap_len : maxHdrLen;
      memcpy(hdrElem->flowType.header.header_bytes + mac_len, cap_hdr, payloadBytes);
      hdrElem->flowType.header.header_length = payloadBytes + mac_len;
      hdrElem->flowType.header.frame_length += mac_len;
    }
    else {
      u_char ipversion = cap_hdr[0] >> 4;
      if(ipversion != 4 && ipversion != 6) {
	EVDebug(mod, 1, "received non-IP packet. Encapsulation is unknown");
	// still go through the motions so that everything is freed properly, but
	// don't actually send out the sample.
	sendPS = NO;
	sp->telemetry[HSP_TELEMETRY_FLOW_SAMPLES_UNKNOWN]++;
      }
      else {
	if(mac_len == 0) {
	  // assume ethernet was (or will be) the framing
	  mac_len = 14;
	}
	hdrElem->flowType.header.header_protocol = (ipversion == 4) ? SFLHEADER_IPv4 : SFLHEADER_IPv6;
	hdrElem->flowType.header.stripped += mac_len;
	hdrElem->flowType.header.header_length = (cap_len < maxHdrLen) ? cap_len : maxHdrLen;
	memcpy(hdrElem->flowType.header.header_bytes, cap_hdr, hdrElem->flowType.header.header_length);
	hdrElem->flowType.header.frame_length += mac_len;
      }
    }
    // add to flow sample
    SFLADD_ELEMENT(fs, hdrElem);

    // submit the actual sampling rate so it goes out with the sFlow feed
    // otherwise the sampler object would fill in his own (sub-sampling) rate.
    // If it's a switch port then samplerNIO->sampling_n may be set, so that
    // takes precendence (allows different ports to have different sampling
    // settings).
    uint32_t actualSamplingRate = sampling_n;
    HSPAdaptorNIO *samplerNIO = ADAPTOR_NIO(sampler_dev);
    if(samplerNIO->sampling_n_set && samplerNIO->sampling_n) {
      actualSamplingRate = samplerNIO->sampling_n;
    }
    fs->sampling_rate = actualSamplingRate;
    
    // estimate the sample pool from the samples.  Could maybe do this
    // above with the (possibly more granular) ulogSamplingRate, but then
    // we would have to look up the sampler object every time, which
    // might be too expensive in the case where ulogSamplingRate==1.
    sampler->samplePool += actualSamplingRate;
    
    // accumulate total drops
    sp->telemetry[HSP_TELEMETRY_DROPPED_SAMPLES] += drops;

    // also accumulate dropped-samples we detected against whichever sampler
    // sends the next sample. This is not perfect,  but is likely to accrue
    // drops against the point whose sampling-rate needs to be adjusted.
    samplerNIO->netlink_drops += drops;
    fs->drops = samplerNIO->netlink_drops;

    // Attach linked list of extension structures if supplied, and
    // take over responsibility for freeing them when the sample is
    // released (it might get queued and released later if
    // another module wants to annotate it further after looking
    // something up).
    for(SFLFlow_sample_element *elem = extended_elements; elem; ) {
      SFLFlow_sample_element *next_elem = elem->nxt;
      SFLADD_ELEMENT(fs, elem);
      pendingSample_addHeapPtr(ps, elem);
      elem = next_elem;
    }
      
    // wrap it and send it out in case someone else wants to annotate it
    if(sp->evt_flow_sample == NULL)
      sp->evt_flow_sample = EVGetEvent(EVCurrentBus(), HSPEVENT_FLOW_SAMPLE);
    if(sendPS)
      EVEventTx(sp->rootModule, sp->evt_flow_sample, ps, sizeof(*ps));
    releasePendingSample(sp, ps);
  }

  /*_________________---------------------------__________________
    _________________   configSwitchPorts       __________________
    -----------------___________________________------------------
    Make sure the switch port interfaces are set up for regular
    polling even if they are not sampling any packets (yet).  This
    will be called whenever the interfaces list is refreshed.
  */

  int configSwitchPorts(HSP *sp)
  {
    // could do a mark-and-sweep here in case some ports have been
    // removed,  but that seems very unlikely to happen.  Just
    // make sure we have a poller for every interface that matched
    // the switchPort regex, and that has an ifIndex.  Note that
    // bonding-relationships may cause other interfaces to be
    // marked as switchPorts too, and this is where they are
    // configured to export individual counters.

    // calling readBondState() here is necesary to trigger the
    // discovery of bond interfaces and learn their relationship
    // to their components.  If neither the bond nor
    // a component have been flagged as a switchPorts,
    // however (currently by regex),  then individual
    // polling will not be enabled for them below.
    readBondState(sp);

    int count = 0;
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      if(ADAPTOR_NIO(adaptor)->switchPort) {
	count++;
	getPoller(sp, adaptor);
      }
    }

    // because we are on pollBus here, we know that
    // the above getPoller() requests will all have
    // completed, so we can go ahead with planning the
    // counter-polling batches here.

    // may want to cluster switch port polling into
    // batches that will go out together -- mostly
    // used when reading counters means reading all
    // counters and it's expensive to do it.
    if(sp->syncPollingInterval)
      syncPolling(sp);

    // make sure slave ports are on the same
    // polling schedule as their bond master.
    syncBondPolling(sp);

    return count;
  }

  /*_________________---------------------------__________________
    _________________     decodePacketHeader    __________________
    -----------------___________________________------------------
  */

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct iphdr))

  static int decodePacketHeader(SFLSampled_header *header, uint8_t *ipproto, int *l3_offset, int *l4_offset)
  {
    uint8_t *start = header->header_bytes;
    uint8_t *end = start + header->header_length;
    uint8_t *ptr = start;
    uint16_t type_len = 0;
    
    switch(header->header_protocol) {

    case SFLHEADER_IPv4:
      type_len = 0x0800;
      break;

    case SFLHEADER_IPv6:
      type_len = 0x86DD;
      break;

    case SFLHEADER_ETHERNET_ISO8023:
      // ethernet
      if((end - ptr) < NFT_ETHHDR_SIZ)
	return -1; // not enough for an Ethernet header
      ptr += 6;
      ptr += 6;
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
      
      while(type_len == 0x8100
	    || type_len == 0x88A8
	    || type_len == 0x9100
	    || type_len == 0x9200
	    || type_len == 0x9300) {
	// 802.1Q
	if((end - ptr) < 4)
	  return -1; // not enough for an 802.1Q header
	// VLAN  - next two bytes
	// uint32_t vlanData = (ptr[0] << 8) + ptr[1];
	// uint32_t vlan = vlanData & 0x0fff;
	// uint32_t priority = vlanData >> 13;
	ptr += 2;
	//  _____________________________________ 
	// |   pri  | c |         vlan-id        | 
	//  ------------------------------------- 
	// [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] 
	// now get the type_len again (next two bytes) 
	type_len = (ptr[0] << 8) + ptr[1];
	ptr += 2;
      }

      // now we're just looking for IP or IP6
      if((end - start) < sizeof(struct iphdr))
	return -1; // not enough for an IPv4 header (or IPX, or SNAP) 
      
      if(type_len <= NFT_MAX_8023_LEN) {
	// assume 802.3+802.2 header 
	// check for SNAP 
	if(ptr[0] == 0xAA &&
	   ptr[1] == 0xAA &&
	   ptr[2] == 0x03) {
	  ptr += 3;
	  if(ptr[0] != 0 ||
	     ptr[1] != 0 ||
	     ptr[2] != 0) {
	    return -1; // no further decode for vendor-specific protocol 
	  }
	  ptr += 3;
	  // OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) 
	  type_len = (ptr[0] << 8) + ptr[1];
	  ptr += 2;
	}
	else {
	  if (ptr[0] == 0x06 &&
	      ptr[1] == 0x06 &&
	      (ptr[2] & 0x01)) {
	    // IP over 8022 
	    ptr += 3;
	    // force the type_len to be IP so we can inline the IP decode below 
	    type_len = 0x0800;
	  }
	  else
	    return -1;
	}
      }
    }
    
    // type_len should be ethernet-type now
    switch(type_len) {
    case 0x0800:
      // IPV4 - check again that we have enough header bytes 
      if((end - ptr) < sizeof(struct iphdr))
	return -1;
      // look at first byte of header.... 
      //  ___________________________ 
      // |   version   |    hdrlen   | 
      //  --------------------------- 
      if((*ptr >> 4) != 4)
	return -1; // not version 4 
      if((*ptr & 15) < 5)
	return -1; // not IP (hdr len must be 5 quads or more) 
      // survived all the tests - store the offset to the start of the ip header 
      *l3_offset = (ptr - start);
      *l4_offset = (*l3_offset) + ((*ptr & 15) * 4);
      *ipproto = ptr[9];
      return 4; // IPv4
      
    case 0x86DD:
      // IPV6 
      // look at first byte of header.... 
      if((*ptr >> 4) != 6)
	return -1; // not version 6 
      // survived all the tests - store the offset to the start of the ip6 header 
      *l3_offset = (ptr - start);
      *ipproto = ptr[6];
      ptr += sizeof(struct ip6_hdr);
      bool decodingOptions = YES;
      while(decodingOptions
	    && ptr < end) {
	switch(*ipproto) {
	  // these we can skip
	case 0:  // hop
	case 43: // routing
	case 51: // auth
	case 60: // dest options
	  *ipproto = ptr[0];
	  // second byte gives option len in units of 8, not counting first 8
	  ptr += 8 * (ptr[1] + 1);
	  break;
	  // the rest we cannot skip (or don't want to)
	  // case 1: // ICMP6
	  // case 6: // TCP
	  // case 17: // UDP
	  // case 44: // fragment
	  // case 50: // encyption
	default:
	  decodingOptions = NO;
	  break;
	}
      }
      *l4_offset = (ptr - start);
      return 6; // IPv6
    }

    // type_len did not match
    return -2;
  }

  /*_________________---------------------------__________________
    _________________   decodePendingSample     __________________
    -----------------___________________________------------------
  */

  static void decodePendingSample_ipip(HSPPendingSample *ps) {
    if(ps->ipproto == IPPROTO_IPIP
       && ps->hdr_len >= (ps->l4_offset + 20 /* IPv4 */)) {
      u_char *innerIP = ps->hdr + ps->l4_offset;
      if(innerIP[0] == 0x45 /* version 4, header-length 20 */) {
	ps->src_1.type = SFLADDRESSTYPE_IP_V4;
	memcpy(&ps->src_1.address.ip_v4.addr, innerIP + 12, 4);
	ps->dst_1.type = SFLADDRESSTYPE_IP_V4;
	memcpy(&ps->dst_1.address.ip_v4.addr, innerIP + 16, 4);
	ps->ipproto_1 = innerIP[9];
	ps->gotInnerIP = YES;
	ps->l4_offset += 20;
	if(ps->ipproto_1 == 6
	   || ps->ipproto_1 == 17) {
	  u_char *ptr = ps->hdr + ps->l4_offset;
	  ps->l4_sport_1 = (ptr[0] << 8) + ptr[1];
	  ps->l4_dport_1 = (ptr[2] << 8) + ptr[3];
	}
      }
    }
  }
  
  static void decodePendingSample_vxlan(HSPPendingSample *ps) {
    int ip_offset_1 = ps->l4_offset + 8 /* udp */ + 8 /* vxlan */ + 14 /* inner MAC */;
    if(ps->ipproto == IPPROTO_UDP
       && ps->hdr_len >= ip_offset_1) {
      // Check for VXLAN(4789|8472) header at l4_offset,
      // and if found, populate inner MAC and IP addrs.
      // Perhaps also for Geneve(6801) and teredo(3544)?
      // UDP Header: [sPort][dPort][pduLen][csum]
      if(ps->l4_dport == 4789
	 || ps->l4_dport == 8472) {
	/* VXLAN Header: 
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
	   |R|R|R|R|I|R|R|R|            Reserved                           | 
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
	   |                VXLAN Network Identifier (VNI) |   Reserved    | 
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
	*/
	u_char *vxlan = ps->hdr + ps->l4_offset + 8;
	if((vxlan[0] != 0x08)
	   || (vxlan[1] != 0)
	   || (vxlan[2] != 0)
	   || (vxlan[3] != 0)
	   || (vxlan[7] != 0)) {
	  // only the "I" bit must be set - rest are reserved and should be zero
	  return;
	}
	uint32_t vni = vxlan[4];
	vni <<= 8;
	vni += vxlan[5];
	vni <<= 8;
	vni += vxlan[6];
	// assume not VXLAN if vni == 0
	if(vni != 0) {
	  ps->vxlan_vni = vni;
	  u_char *mac_1 = vxlan + 8;
	  // copy MAC addresses (or maybe we should just record offset to inner L2)?
	  memcpy(ps->macdst_1.mac, mac_1, 6);
	  memcpy(ps->macsrc_1.mac, mac_1 + 6, 6);
	  ps->gotInnerMAC = YES;
	  // check only for simplest IP encapsulation
	  if(mac_1[12] == 0x08
	     && mac_1[13] == 0x00
	     && ps->hdr_len > (ip_offset_1 + 20)) {
	    u_char *innerIP = mac_1 + 14;
	    if(innerIP[0] == 0x45 /* version 4, header-length 20 */) {
	      ps->src_1.type = SFLADDRESSTYPE_IP_V4;
	      memcpy(&ps->src_1.address.ip_v4.addr, innerIP + 12, 4);
	      ps->dst_1.type = SFLADDRESSTYPE_IP_V4;
	      memcpy(&ps->dst_1.address.ip_v4.addr, innerIP + 16, 4);
	      ps->ipproto_1 = innerIP[9];
	      ps->gotInnerIP = YES;
	      ps->l4_offset = ip_offset_1 + 20;
	      if(ps->hdr_len > (ps->l4_offset + 4)
		 && (ps->ipproto_1 == IPPROTO_TCP
		     || ps->ipproto_1 == IPPROTO_UDP)) {
		u_char *ptr = ps->hdr + ps->l4_offset;
		ps->l4_sport_1 = (ptr[0] << 8) + ptr[1];
		ps->l4_dport_1 = (ptr[2] << 8) + ptr[3];
	      }
	    }
	  }
	  // TODO: handle other L2 encapsulations
	  // TODO: handle inner IPv6
	}
      }
    }
  } 
	     
  int decodePendingSample(HSPPendingSample *ps) {
    if(!ps->decoded) {
      for(SFLFlow_sample_element *elem = ps->fs->elements; elem != NULL; elem = elem->nxt) {
	if(elem->tag == SFLFLOW_HEADER) {
	  SFLSampled_header *header = &elem->flowType.header;
	  ps->hdr = header->header_bytes;
	  ps->hdr_protocol = header->header_protocol;
	  ps->hdr_len = header->header_length;
	  ps->ipversion = decodePacketHeader(header, &ps->ipproto, &ps->l3_offset, &ps->l4_offset);
	  // The above just captures the main encapsulation offsets, but we also want
	  // to pull out some of the fields that are most likely to be used for lookups.
	  if(ps->hdr_protocol == SFLHEADER_ETHERNET_ISO8023) {
	    // extract outer MAC addresses
	    memcpy(ps->macdst.mac, ps->hdr, 6);
	    memcpy(ps->macsrc.mac, ps->hdr + 6, 6);
	  }
	  // extract IP src/dst addresses
	  if(ps->ipversion == 4) {
	    ps->src.type = ps->dst.type = SFLADDRESSTYPE_IP_V4;
	    memcpy(&ps->src.address.ip_v4, ps->hdr + ps->l3_offset + 12, 4);
	    memcpy(&ps->dst.address.ip_v4, ps->hdr + ps->l3_offset + 16, 4);
	  }
	  if(ps->ipversion == 6) {
	    ps->src.type = ps->dst.type = SFLADDRESSTYPE_IP_V6;
	    memcpy(&ps->src.address.ip_v6, ps->hdr + ps->l3_offset + 8, 16);
	    memcpy(&ps->dst.address.ip_v6, ps->hdr + ps->l3_offset + 24, 16);
	  }
	  // extract tunneled addresses
	  if(ps->l4_offset) {
	    u_char *ptr = ps->hdr + ps->l4_offset;
	    switch(ps->ipproto) {
	    case IPPROTO_TCP:
	      ps->l4_sport = (ptr[0] << 8) + ptr[1];
	      ps->l4_dport = (ptr[2] << 8) + ptr[3];
	      break;
	    case IPPROTO_UDP:
	      ps->l4_sport = (ptr[0] << 8) + ptr[1];
	      ps->l4_dport = (ptr[2] << 8) + ptr[3];
	      decodePendingSample_vxlan(ps);
	      break;
	    case IPPROTO_IPIP:
	      decodePendingSample_ipip(ps);
	      break;
	    }
	  }
	  break; // found header
	}
      }
      ps->decoded = YES;
    }
    return ps->ipversion;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
