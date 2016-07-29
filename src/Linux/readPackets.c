/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  /*_________________-----------------------------------__________________
    _________________   agentCB_getCounters_interface   __________________
    -----------------___________________________________------------------
  */

  static void agentCB_getCounters_interface(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;

    assert(EVCurrentBus() == sp->pollBus);

    // device name was copied as userData
    char *devName = (char *)poller->userData;
    
    if(devName) {
      // look up the adaptor objects
      SFLAdaptor *adaptor = adaptorByName(sp, devName);
      if(adaptor) {
	
	// make sure the counters are up to the second
	updateNioCounters(sp, adaptor);
	
	HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);

	// see if we were able to discern multicast and broadcast counters
	// by polling for ethtool stats.  Be careful to use unsigned 32-bit
	// arithmetic here:
#define UNSUPPORTED_SFLOW_COUNTER32 (uint32_t)-1
	uint32_t pkts_in = adaptorNIO->nio.pkts_in;
	uint32_t pkts_out = adaptorNIO->nio.pkts_out;
	uint32_t mcasts_in =  UNSUPPORTED_SFLOW_COUNTER32;
	uint32_t mcasts_out =  UNSUPPORTED_SFLOW_COUNTER32;
	uint32_t bcasts_in =  UNSUPPORTED_SFLOW_COUNTER32;
	uint32_t bcasts_out =  UNSUPPORTED_SFLOW_COUNTER32;
	// only do this if we were able to find all four
	// via ethtool, otherwise it would just be too weird...
	if(adaptorNIO->et_nfound == 4) {
	  mcasts_in = (uint32_t)adaptorNIO->et_total.mcasts_in;
	  bcasts_in = (uint32_t)adaptorNIO->et_total.bcasts_in;
	  pkts_in -= (mcasts_in + bcasts_in);
	  mcasts_out = (uint32_t)adaptorNIO->et_total.mcasts_out;
	  bcasts_out = (uint32_t)adaptorNIO->et_total.bcasts_out;
	  pkts_out -= (mcasts_out + bcasts_out);
	}
	// generic interface counters
	SFLCounters_sample_element elem = { 0 };
	elem.tag = SFLCOUNTERS_GENERIC;
	elem.counterBlock.generic.ifIndex = poller->dsi.ds_index;
	elem.counterBlock.generic.ifType = 6; // assume ethernet
	elem.counterBlock.generic.ifSpeed = adaptor->ifSpeed;
	elem.counterBlock.generic.ifDirection = adaptor->ifDirection;
	elem.counterBlock.generic.ifStatus = adaptorNIO->up ? (SFLSTATUS_ADMIN_UP | SFLSTATUS_OPER_UP) : 0;
	elem.counterBlock.generic.ifPromiscuousMode = adaptor->promiscuous;
	elem.counterBlock.generic.ifInOctets = adaptorNIO->nio.bytes_in;
	elem.counterBlock.generic.ifInUcastPkts = pkts_in;
	elem.counterBlock.generic.ifInMulticastPkts = mcasts_in;
	elem.counterBlock.generic.ifInBroadcastPkts = bcasts_in;
	elem.counterBlock.generic.ifInDiscards = adaptorNIO->nio.drops_in;
	elem.counterBlock.generic.ifInErrors = adaptorNIO->nio.errs_in;
	elem.counterBlock.generic.ifInUnknownProtos = UNSUPPORTED_SFLOW_COUNTER32;
	elem.counterBlock.generic.ifOutOctets = adaptorNIO->nio.bytes_out;
	elem.counterBlock.generic.ifOutUcastPkts = pkts_out;
	elem.counterBlock.generic.ifOutMulticastPkts = mcasts_out;
	elem.counterBlock.generic.ifOutBroadcastPkts = bcasts_out;
	elem.counterBlock.generic.ifOutDiscards = adaptorNIO->nio.drops_out;
	elem.counterBlock.generic.ifOutErrors = adaptorNIO->nio.errs_out;
	SFLADD_ELEMENT(cs, &elem);

	if(adaptorNIO->vm_or_container) {
#define HSP_DIRECTION_SWAP(g,f) do {				\
	    uint32_t _tmp = g.ifIn ## f;			\
	    g.ifIn ## f = g.ifOut ## f;				\
	    g.ifOut ## f = _tmp; } while(0)
	  HSP_DIRECTION_SWAP(elem.counterBlock.generic, UcastPkts);
	  HSP_DIRECTION_SWAP(elem.counterBlock.generic, MulticastPkts);
	  HSP_DIRECTION_SWAP(elem.counterBlock.generic, BroadcastPkts);
	  HSP_DIRECTION_SWAP(elem.counterBlock.generic, Discards);
	  HSP_DIRECTION_SWAP(elem.counterBlock.generic, Errors);
	}
	  
	// add optional interface name struct
	SFLCounters_sample_element pn_elem = { 0 };
	pn_elem.tag = SFLCOUNTERS_PORTNAME;
	pn_elem.counterBlock.portName.portName.len = my_strlen(devName);
	pn_elem.counterBlock.portName.portName.str = devName;
	SFLADD_ELEMENT(cs, &pn_elem);

	// possibly include LACP struct for bond slave
	// (used to send for bond-master too,  but that
	// was a mis-reading of the standard).
	SFLCounters_sample_element lacp_elem = { 0 };
	if(/*adaptorNIO->bond_master
	     ||*/ adaptorNIO->bond_slave) {
	  updateBondCounters(sp, adaptor);
	  lacp_elem.tag = SFLCOUNTERS_LACP;
	  lacp_elem.counterBlock.lacp = adaptorNIO->lacp; // struct copy
	  SFLADD_ELEMENT(cs, &lacp_elem);
	}

	// possibly include SFP struct with optical gauges
	SFLCounters_sample_element sfp_elem = { 0 };
	if(adaptorNIO->sfp.num_lanes) {
	  sfp_elem.tag = SFLCOUNTERS_SFP;
	  sfp_elem.counterBlock.sfp = adaptorNIO->sfp; // struct copy - picks up lasers list
	  SFLADD_ELEMENT(cs, &sfp_elem);
	}
	
	SEMLOCK_DO(sp->sync_agent) {
	  sfl_poller_writeCountersSample(poller, cs);
	}
      }
    }
  }

  static void agentCB_getCounters_interface_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)poller->magic;
    UTArrayAdd(sp->pollActions, poller);
    UTArrayAdd(sp->pollActions, agentCB_getCounters_interface);
  }

  /*_________________---------------------------__________________
    _________________       getPoller           __________________
    -----------------___________________________------------------
  */

  static SFLPoller *getPoller(HSP *sp, SFLAdaptor *adaptor)
  {
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    if(adaptorNIO->poller == NULL) {
      SFLDataSource_instance dsi;
      SFL_DS_SET(dsi, 0, adaptor->ifIndex, 0); // ds_class,ds_index,ds_instance
      uint32_t pollingInterval = sp->sFlowSettings ?
	sp->sFlowSettings->pollingInterval :
	SFL_DEFAULT_POLLING_INTERVAL;
      SEMLOCK_DO(sp->sync_agent) {
	adaptorNIO->poller = sfl_agent_addPoller(sp->agent, &dsi, sp, agentCB_getCounters_interface_request);
	sfl_poller_set_sFlowCpInterval(adaptorNIO->poller, pollingInterval);
	sfl_poller_set_sFlowCpReceiver(adaptorNIO->poller, HSP_SFLOW_RECEIVER_INDEX);
	// remember the device name to make the lookups easier later.
	// Don't want to point directly to the SFLAdaptor or SFLAdaptorNIO object
	// in case it gets freed at some point.  The device name is enough.
	adaptorNIO->poller->userData = (void *)my_strdup(adaptor->deviceName);
      }
    }
    return adaptorNIO->poller;
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
      // add sampler
      SEMLOCK_DO(sp->sync_agent) {
	adaptorNIO->sampler = sfl_agent_addSampler(sp->agent, &dsi);
	sfl_sampler_set_sFlowFsReceiver(adaptorNIO->sampler, HSP_SFLOW_RECEIVER_INDEX);
	sfl_sampler_set_sFlowFsMaximumHeaderSize(adaptorNIO->sampler, sp->sFlowSettings_file->headerBytes);
      }
      // and make sure we have a poller too
      getPoller(sp, adaptor);
    }
    return adaptorNIO->sampler;
  }

  /*_________________---------------------------__________________
    _________________    takeSample             __________________
    -----------------___________________________------------------
  */

  void takeSample(HSP *sp, SFLAdaptor *ad_in, SFLAdaptor *ad_out, SFLAdaptor *ad_tap, uint32_t isBridge, uint32_t hook, const u_char *mac_hdr, uint32_t mac_len, const u_char *cap_hdr, uint32_t cap_len, uint32_t pkt_len, uint32_t drops, uint32_t sampling_n)
  {

    if(getDebug() > 1) {
      myLog(LOG_INFO, "takeSample: hook=%u in=%s out=%s pkt_len=%u cap_len=%u mac_len=%u",
	    hook,
	    ad_in ? ad_in->deviceName : "<not found>",
	    ad_out ? ad_out->deviceName : "<not found>",
	    pkt_len,
	    cap_len,
	    mac_len);
      if(mac_len == 14) {
	u_char macdst[12], macsrc[12];
	printHex(mac_hdr+6,6,macsrc,12,NO);
	printHex(mac_hdr+0,6,macdst,12,NO);
	uint16_t ethtype = (mac_hdr[12] << 8) + mac_hdr[13];
	myLog(LOG_INFO, "%s -> %s (ethertype=0x%04X)", macsrc, macdst, ethtype);
      }
    }

    int internal_in = NO;
    int internal_out = NO;
    int bridgeModel = sp->cumulus.cumulus ? YES : isBridge;

    // If it is the container-end of a veth pair, then we want to
    // map it back to the other end that is in the global-namespace,
    // Since those are the bridge ports.
    if(ad_in) {
      if(ADAPTOR_NIO(ad_in)->vm_or_container)
	bridgeModel = YES;
      SFLAdaptor *ad_in_global = adaptorByPeerIndex(sp, ad_in->ifIndex);
      if(ad_in_global) {
	if(getDebug()) {
	  myLog(LOG_INFO, "  GlobalNS veth peer ad_in=%s(%u)",
		ad_in_global->deviceName,
		ad_in_global->ifIndex);
	}
	bridgeModel = YES;
	ad_in = ad_in_global;
      }
    }
    if(ad_out) {
      if(ADAPTOR_NIO(ad_out)->vm_or_container)
	bridgeModel = YES;
      SFLAdaptor *ad_out_global = adaptorByPeerIndex(sp, ad_out->ifIndex);
      if(ad_out_global) {
	if(getDebug()) {
	  myLog(LOG_INFO, "  GlobalNS veth peer ad_out=%s(%u)",
		ad_out_global->deviceName,
		ad_out_global->ifIndex);
	}
	bridgeModel = YES;
	ad_out = ad_out_global;
      }
    }
	
    // For a MAC that we don't recognize,  we will assume
    // that it it's going out on the physical NIC.  That may
    // be the device that we tapped here (bpfs->device) or
    // if we tapped a bridge we should look for a physical
    // device or bond that is also attached to the bridge.
    // Of course, this host may itself be a VM so the
    // "Physical" NIC may just be a virtual interface too.
    // In that case we may have to fall back on a process of
    // elimination and look for the one device on the bridge
    // that is not either a loopback or veth or associated
    // with a container or VM.  When readInterfaces() finds
    // a bridge it could try to establish the "external"
    // device for that bridge.
    
    if(!bridgeModel) {
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

    SFL_FLOW_SAMPLE_TYPE fs = { 0 };
 
    // set the ingress and egress ifIndex numbers.
    // Can be "INTERNAL" (0x3FFFFFFF) or "UNKNOWN" (0).
    fs.input = ad_in ? ad_in->ifIndex : (internal_in ? SFL_INTERNAL_INTERFACE : 0);
    fs.output = ad_out ? ad_out->ifIndex : (internal_out ? SFL_INTERNAL_INTERFACE : 0);

    SFLAdaptor *sampler_dev = ad_in ?: ad_out;

    // detect egress sampling
    if(sp->cumulus.cumulus) {
      // On Cumulus Linux the sampling direction is indicated in the low
      // bit of the pkt->hook field: 0==ingress,1==egress
      if(ad_out &&
	 (hook & 1) == 1) {
	sampler_dev = ad_out;
      }
    }
    else {
      if(ad_in && ad_out) {
	// If the ingress was a loopback and the egress is not -- and the
	// egress has an ifIndex,  then switch this over to indicate egress
	// sampling.  In a typical host scenario most samples will be
	// "lo" -> "eth0" or "eth0" -> "lo", so this ensures that
	// that we present it as bidirectional sampling on eth0.
	if(ADAPTOR_NIO(ad_in)->loopback) {
	  if(!ADAPTOR_NIO(ad_out)->loopback
	     && ad_out->ifIndex) {
	    sampler_dev = ad_out;
	  }
	}
      }
    }

    if(sampler_dev == NULL) {
      // for promiscuous tap monitoring there may be no sense of 'in'
      // or 'out' on this adaptor, but we can still set the sampler_dev.
      sampler_dev = ad_tap;
    }

    // must have a sampler_dev with an ifIndex
    if(sampler_dev && sampler_dev->ifIndex) {
      HSPAdaptorNIO *samplerNIO = ADAPTOR_NIO(sampler_dev);

      if(getDebug() > 2) {
	myLog(LOG_INFO, "selected sampler %s ifIndex=%u",
	      sampler_dev->deviceName,
	      sampler_dev->ifIndex);
      }

      SFLSampler *sampler = getSampler(sp, sampler_dev);
		  
      if(sampler) {
	SFLFlow_sample_element hdrElem = { 0 };
	hdrElem.tag = SFLFLOW_HEADER;
	uint32_t FCS_bytes = 4;
	uint32_t maxHdrLen = sampler->sFlowFsMaximumHeaderSize;
	hdrElem.flowType.header.frame_length = pkt_len + FCS_bytes;
	hdrElem.flowType.header.stripped = FCS_bytes;
		    
	u_char hdr[HSP_MAX_HEADER_BYTES];
	
	uint64_t mac_hdr_test=0;
	if(mac_hdr && mac_len > 8) {
	  memcpy(&mac_hdr_test, mac_hdr, 8);
	}

	if(mac_len == 14
	   && mac_hdr_test != 0) {
	  // set the header_protocol to ethernet and
	  // reunite the mac header and payload in one buffer
	  hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
	  memcpy(hdr, mac_hdr, mac_len);
	  maxHdrLen -= mac_len;
	  uint32_t payloadBytes = (cap_len < maxHdrLen) ? cap_len : maxHdrLen;
	  memcpy(hdr + mac_len, cap_hdr, payloadBytes);
	  hdrElem.flowType.header.header_length = payloadBytes + mac_len;
	  hdrElem.flowType.header.header_bytes = hdr;
	  hdrElem.flowType.header.frame_length += mac_len;
	}
	else {
	  // no need to copy - just point at the captured header
	  u_char ipversion = cap_hdr[0] >> 4;
	  if(ipversion != 4 && ipversion != 6) {
	    if(getDebug()) myLog(LOG_ERR, "received non-IP packet. Encapsulation is unknown");
	  }
	  else {
	    if(mac_len == 0) {
	      // assume ethernet was (or will be) the framing
	      mac_len = 14;
	    }
	    hdrElem.flowType.header.header_protocol = (ipversion == 4) ? SFLHEADER_IPv4 : SFLHEADER_IPv6;
	    hdrElem.flowType.header.stripped += mac_len;
	    hdrElem.flowType.header.header_length = (cap_len < maxHdrLen) ? cap_len : maxHdrLen;
	    hdrElem.flowType.header.header_bytes = (u_char *)cap_hdr;
	    hdrElem.flowType.header.frame_length += mac_len;
	  }
	}
		    
	SFLADD_ELEMENT(&fs, &hdrElem);
	// submit the actual sampling rate so it goes out with the sFlow feed
	// otherwise the sampler object would fill in his own (sub-sampling) rate.
	// If it's a switch port then samplerNIO->sampling_n may be set, so that
	// takes precendence (allows different ports to have different sampling
	// settings).
	uint32_t actualSamplingRate = sampling_n;
	if(samplerNIO->sampling_n_set && samplerNIO->sampling_n) {
	  actualSamplingRate = samplerNIO->sampling_n;
	}
	fs.sampling_rate = actualSamplingRate;
		    
	// estimate the sample pool from the samples.  Could maybe do this
	// above with the (possibly more granular) ulogSamplingRate, but then
	// we would have to look up the sampler object every time, which
	// might be too expensive in the case where ulogSamplingRate==1.
	sampler->samplePool += actualSamplingRate;
		    
	// accumulate any dropped-samples we detected against whichever sampler
	// sends the next sample. This is not perfect,  but is likely to accrue
	// drops against the point whose sampling-rate needs to be adjusted.
	samplerNIO->netlink_drops += drops;
	fs.drops = samplerNIO->netlink_drops;
	SEMLOCK_DO(sp->sync_agent) {
	  sfl_sampler_writeFlowSample(sampler, &fs);
	}
      }
    }
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

    // make sure slave ports are on the same
    // polling schedule as their bond master.
    syncBondPolling(sp);

    return count;
  }

  
#if defined(__cplusplus)
} /* extern "C" */
#endif

