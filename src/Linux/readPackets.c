/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  extern int debug;

#if (HSF_ULOG || HSF_NFLOG || HSF_PCAP)


  /*_________________-----------------------------------__________________
    _________________   agentCB_getCounters_interface   __________________
    -----------------___________________________________------------------
  */

  void agentCB_getCounters_interface(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;
    
    // device name was copied as userData
    char *devName = (char *)poller->userData;
    
    if(devName) {
      // look up the adaptor objects
      SFLAdaptor *adaptor = adaptorByName(sp, devName);
      if(adaptor) {
	HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      
	// make sure the counters are up to the second
	updateNioCounters(sp);
	
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
#ifdef HSP_ETHTOOL_STATS
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
#endif
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
	sfl_poller_writeCountersSample(poller, cs);
      }
    }
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
      HSPSFlow *sf = sp->sFlow;
      uint32_t pollingInterval = sf->sFlowSettings ?
	sf->sFlowSettings->pollingInterval :
	SFL_DEFAULT_POLLING_INTERVAL;
      adaptorNIO->poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters_interface);
      sfl_poller_set_sFlowCpInterval(adaptorNIO->poller, pollingInterval);
      sfl_poller_set_sFlowCpReceiver(adaptorNIO->poller, HSP_SFLOW_RECEIVER_INDEX);
      // remember the device name to make the lookups easier later.
      // Don't want to point directly to the SFLAdaptor or SFLAdaptorNIO object
      // in case it gets freed at some point.  The device name is enough.
      adaptorNIO->poller->userData = (void *)my_strdup(adaptor->deviceName);
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
      HSPSFlow *sf = sp->sFlow;
      // add sampler
      adaptorNIO->sampler = sfl_agent_addSampler(sf->agent, &dsi);
      sfl_sampler_set_sFlowFsReceiver(adaptorNIO->sampler, HSP_SFLOW_RECEIVER_INDEX);
      // and make sure we have a poller too
      getPoller(sp, adaptor);
    }
    return adaptorNIO->sampler;
  }

  /*_________________---------------------------__________________
    _________________    takeSample             __________________
    -----------------___________________________------------------
  */

  static void takeSample(HSP *sp, SFLAdaptor *ad_in, SFLAdaptor *ad_out, uint32_t isBridge, uint32_t hook, const u_char *mac_hdr, uint32_t mac_len, const u_char *cap_hdr, uint32_t cap_len, uint32_t pkt_len, uint32_t drops, uint32_t sampling_n)
  {

    if(debug > 1) {
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
    int bridgeModel = isBridge;
	
    // If it is the container-end of a veth pair, then we want to
    // map it back to the other end that is in the global-namespace,
    // Since those are the bridge ports.
    if(ad_in) {
      if(ADAPTOR_NIO(ad_in)->vm_or_container)
	bridgeModel = YES;
      SFLAdaptor *ad_in_global = adaptorByPeerIndex(sp, ad_in->ifIndex);
      if(ad_in_global) {
	if(debug) {
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
	if(debug) {
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
#ifdef HSF_CUMULUS
    // On Cumulus Linux the sampling direction is indicated in the low
    // bit of the pkt->hook field: 0==ingress,1==egress
    if(ad_out &&
       (hook & 1) == 1) {
      sampler_dev = ad_out;
    }
#else
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
#endif

    // must have a sampler_dev with an ifIndex
    if(sampler_dev && sampler_dev->ifIndex) {
      HSPAdaptorNIO *samplerNIO = ADAPTOR_NIO(sampler_dev);

      if(debug > 2) {
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
	    if(debug) myLog(LOG_ERR, "received non-IP packet. Encapsulation is unknown");
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
	sfl_sampler_writeFlowSample(sampler, &fs);
      }
    }
  }


  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

#ifdef HSF_PCAP
  // function of type pcap_handler

  void readPackets_pcap_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *buf)
  {
    static uint32_t MySkipCount=1;
    BPFSoc *bpfs = (BPFSoc *)user;
    uint32_t sr = bpfs->subSamplingRate;

    if(sr == 0) {
      // sampling disabled by setting to 0
      return;
    }
    
    if(--MySkipCount == 0) {
      /* reached zero. Set the next skip */
      MySkipCount = sr == 1 ? 1 : sfl_random((2 * sr) - 1);

      HSP *sp = bpfs->myHSP;
      
      // global MAC -> adaptor
      SFLMacAddress macdst,macsrc;
      memcpy(macdst.mac, buf, 6);
      memcpy(macsrc.mac, buf+6, 6);
      SFLAdaptor *srcdev = adaptorByMac(sp, &macsrc);
      SFLAdaptor *dstdev = adaptorByMac(sp, &macdst);
      
      if(srcdev) {
	myLog(LOG_INFO, "srcdev=%s(%u)(peer=%u)",
	      srcdev->deviceName,
	      srcdev->ifIndex,
	      srcdev->peer_ifIndex);
      }
      
      if(dstdev) {
	myLog(LOG_INFO, "dstdev=%s(%u)(peer=%u)",
	      dstdev->deviceName,
	      dstdev->ifIndex,
	      dstdev->peer_ifIndex);
      }
      
      takeSample(sp,
		 srcdev,
		 dstdev,
		 bpfs->isBridge,
		 0 /*hook*/,
		 buf /* mac hdr*/,
		 14 /* mac len */,
		 buf + 14 /* payload */,
		 hdr->caplen - 14, /* length of captured payload */
		 hdr->len, /* length of packet (pdu) */
		 bpfs->drops, /* droppedSamples */
		 bpfs->samplingRate);
    }
  }
  
  int readPackets_pcap(HSP *sp, BPFSoc *bpfs)
  {
    int batch = pcap_dispatch(bpfs->pcap,
			      HSP_READPACKET_BATCH,
			      readPackets_pcap_cb,
			      (u_char *)bpfs);
    if(batch == -1) {
      myLog(LOG_ERR, "pcap_dispatch error : %s\n", pcap_geterr(bpfs->pcap));
      // close the pcap socket so we don't spin? $$$$
    }
    return batch;
  }

#endif
  
#ifdef HSF_ULOG

  int readPackets_ulog(HSP *sp)
  {
    int batch = 0;
    static uint32_t MySkipCount=1;

    if(sp->sFlow->sFlowSettings == NULL) {
      // config was turned off
      return 0;
    }

    if(sp->sFlow->sFlowSettings->ulogSubSamplingRate == 0) {
      // packet sampling was disabled by setting desired rate to 0
      return 0;
    }

    if(sp->ulog_soc) {
      for( ; batch < HSP_READPACKET_BATCH; batch++) {
	char buf[HSP_MAX_ULOG_MSG_BYTES];
	socklen_t peerlen = sizeof(sp->ulog_peer);
	int len = recvfrom(sp->ulog_soc,
			   buf,
			   HSP_MAX_ULOG_MSG_BYTES,
			   0,
			   (struct sockaddr *)&sp->ulog_peer,
			   &peerlen);
	if(len <= 0) break;
	if(debug > 1) myLog(LOG_INFO, "got ULOG msg: %u bytes", len);
	for(struct nlmsghdr *msg = (struct nlmsghdr *)buf; NLMSG_OK(msg, len); msg=NLMSG_NEXT(msg, len)) {

	  if(debug > 1) {
	    myLog(LOG_INFO, "netlink (%u bytes left) msg [len=%u type=%u flags=0x%x seq=%u pid=%u]",
		  len,
		  msg->nlmsg_len,
		  msg->nlmsg_type,
		  msg->nlmsg_flags,
		  msg->nlmsg_seq,
		  msg->nlmsg_pid);
	  }

          // check for drops indicated by sequence no
          uint32_t droppedSamples = 0;
          if(sp->ulog_seqno) {
            droppedSamples = msg->nlmsg_seq - sp->ulog_seqno - 1;
            if(droppedSamples) {
              sp->ulog_drops += droppedSamples;
            }
          }
          sp->ulog_seqno = msg->nlmsg_seq;

	  switch(msg->nlmsg_type) {
	  case NLMSG_NOOP:
	  case NLMSG_ERROR:
	  case NLMSG_OVERRUN:
	    // ignore these
	    break;
	  case NLMSG_DONE: // last in multi-part
	  default:
	    {

	      if(--MySkipCount == 0) {
		/* reached zero. Set the next skip */
		uint32_t sr = sp->sFlow->sFlowSettings->ulogSubSamplingRate;
		MySkipCount = sr == 1 ? 1 : sfl_random((2 * sr) - 1);

		/* and take a sample */

		// we're seeing type==111 on Fedora14
		//if(msg->nlmsg_flags & NLM_F_REQUEST) { }
		//if(msg->nlmsg_flags & NLM_F_MULTI) { }
		//if(msg->nlmsg_flags & NLM_F_ACK) { }
		//if(msg->nlmsg_flags & NLM_F_ECHO) { }
		ulog_packet_msg_t *pkt = NLMSG_DATA(msg);
		
		if(debug > 1) {
		  myLog(LOG_INFO, "ULOG mark=%u ts=%s prefix=%s",
			pkt->mark,
			ctime(&pkt->timestamp_sec),
			pkt->prefix);
		}



		SFLAdaptor *dev_in = NULL;
		SFLAdaptor *dev_out = NULL;

		if(pkt->indev_name[0]) {
		  dev_in = adaptorByName(sp, pkt->indev_name);
		}
		if(pkt->outdev_name[0]) {
		  dev_out = adaptorByName(sp, pkt->outdev_name);
		}

		takeSample(sp,
			   dev_in,
			   dev_out,
			   NO,
			   pkt->hook,
			   pkt->mac,
			   pkt->mac_len,
			   pkt->payload,
			   pkt->data_len, /* length of captured payload */
			   pkt->data_len, /* length of packet (pdu) */
			   droppedSamples,
			   sp->sFlow->sFlowSettings->ulogActualSamplingRate);
	      }
	    }
	  }
	}
      }
    }
    return batch;
  }

#endif

#ifdef HSF_NFLOG

  int readPackets_nflog(HSP *sp)
  {
    int batch = 0;
    static uint32_t MySkipCount=1;
    
    if(sp->sFlow->sFlowSettings == NULL) {
      // config was turned off
      return 0;
    }


    if(sp->sFlow->sFlowSettings->nflogSubSamplingRate == 0) {
      // packet sampling was disabled by setting desired rate to 0
      return 0;
    }
    
    if(sp->nflog_soc) {
      for( ; batch < HSP_READPACKET_BATCH; batch++) {
	u_char buf[HSP_MAX_NFLOG_MSG_BYTES];
	int len = nfnl_recv(sp->nfnl,
			    buf,
			    HSP_MAX_NFLOG_MSG_BYTES);
	if(len <= 0) break;
	if(debug > 1) {
	  struct nlmsghdr *msg = (struct nlmsghdr *)buf;
	  myLog(LOG_INFO, "got NFLOG msg: bytes_read=%u nlmsg_len=%u nlmsg_type=%u OK=%s",
		len,
		msg->nlmsg_len,
		msg->nlmsg_type,
		NLMSG_OK(msg, len) ? "true" : "false");
	}
	for(struct nlmsghdr *msg = (struct nlmsghdr *)buf; NLMSG_OK(msg, len); msg=NLMSG_NEXT(msg, len)) {
	  if(debug > 1) {
	    myLog(LOG_INFO, "netlink (%u bytes left) msg [len=%u type=%u flags=0x%x seq=%u pid=%u]",
		  len,
		  msg->nlmsg_len,
		  msg->nlmsg_type,
		  msg->nlmsg_flags,
		  msg->nlmsg_seq,
		  msg->nlmsg_pid);
	  }

          // check for drops indicated by sequence no
          uint32_t droppedSamples = 0;
          if(sp->nflog_seqno) {
            droppedSamples = msg->nlmsg_seq - sp->nflog_seqno - 1;
            if(droppedSamples) {
              sp->nflog_drops += droppedSamples;
            }
          }
          sp->nflog_seqno = msg->nlmsg_seq;

	  switch(msg->nlmsg_type) {
	  case NLMSG_NOOP:
	  case NLMSG_ERROR:
	  case NLMSG_OVERRUN:
	    // ignore these
	    break;
	  case NLMSG_DONE: // last in multi-part
	  default:
	    {
	      struct nfgenmsg *genmsg;
	      struct nfattr *attr = nfnl_parse_hdr(sp->nfnl, msg, &genmsg);
	      if(attr == NULL) {
		continue;
	      }
	      int min_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
	      int attr_len = msg->nlmsg_len - NLMSG_ALIGN(min_len);
	      struct nfattr *tb[NFULA_MAX] = { 0 };

	      while (NFA_OK(attr, attr_len)) {
		if (NFA_TYPE(attr) <= NFULA_MAX) {
		  tb[NFA_TYPE(attr)-1] = attr;
		  if(debug > 2) {
		    myLog(LOG_INFO, "found attr %d attr_len=%d\n", NFA_TYPE(attr), attr_len);
		  }
		}
                attr = NFA_NEXT(attr,attr_len);
	      }
	      // get the essential fields so we know this is really a packet we can sample
	      struct nfulnl_msg_packet_hdr *msg_pkt_hdr = nfnl_get_pointer_to_data(tb, NFULA_PACKET_HDR, struct nfulnl_msg_packet_hdr);
	      u_char *cap_hdr = nfnl_get_pointer_to_data(tb, NFULA_PAYLOAD, u_char);
	      int cap_len = NFA_PAYLOAD(tb[NFULA_PAYLOAD-1]);
	      if(msg_pkt_hdr == NULL
		 || cap_hdr == NULL
		 || cap_len <= 0) {
		// not a packet header msg, or no captured payload found
		continue;
	      }

	      if(debug > 2) {
		myLog(LOG_INFO, "capture payload (cap_len)=%d\n", cap_len);
	      }

	      if(--MySkipCount == 0) {
		/* reached zero. Set the next skip */
		uint32_t sr = sp->sFlow->sFlowSettings->nflogSubSamplingRate;
		MySkipCount = sr == 1 ? 1 : sfl_random((2 * sr) - 1);
		
		/* and take a sample */
		char *prefix = nfnl_get_pointer_to_data(tb, NFULA_PREFIX, char);
		uint32_t ifin_phys = ntohl(nfnl_get_data(tb, NFULA_IFINDEX_PHYSINDEV, uint32_t));
		uint32_t ifout_phys = ntohl(nfnl_get_data(tb, NFULA_IFINDEX_PHYSOUTDEV, uint32_t));
		uint32_t ifin = ntohl(nfnl_get_data(tb, NFULA_IFINDEX_INDEV, uint32_t));
		uint32_t ifout = ntohl(nfnl_get_data(tb, NFULA_IFINDEX_OUTDEV, uint32_t));
		u_char *mac_hdr = nfnl_get_pointer_to_data(tb, NFULA_HWHEADER, u_char);
		uint16_t mac_len = ntohs(nfnl_get_data(tb, NFULA_HWLEN, uint16_t));
		uint32_t mark = ntohl(nfnl_get_data(tb, NFULA_MARK, uint32_t));
		uint32_t seq = ntohl(nfnl_get_data(tb, NFULA_SEQ, uint32_t));
		uint32_t seq_global = ntohl(nfnl_get_data(tb, NFULA_SEQ_GLOBAL, uint32_t));

		if(debug > 1) { 
		  myLog(LOG_INFO, "NFLOG prefix: %s in: %u (phys=%u) out: %u (phys=%u) seq: %u seq_global: %u mark: %u\n",
			prefix,
			ifin,
			ifin_phys,
			ifout,
			ifout_phys,
			seq,
			seq_global,
			mark);
		}

		takeSample(sp,
			   adaptorByIndex(sp, (ifin_phys ?: ifin)),
			   adaptorByIndex(sp, (ifout_phys ?: ifout)),
			   NO,
			   msg_pkt_hdr->hook,
			   mac_hdr,
			   mac_len,
			   cap_hdr,
			   cap_len, /* length of captured payload */
			   cap_len, /* length of packet (pdu) */
			   droppedSamples,
			   sp->sFlow->sFlowSettings->nflogActualSamplingRate);
	      }
	    }
	  }
	}
      }
    }
    return batch;
  }
#endif

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


#endif /* HSF_ULOG || HSF_NFLOG || HSF_PCAP */
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

