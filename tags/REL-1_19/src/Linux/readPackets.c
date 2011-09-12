/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  extern int debug;

#ifdef HSF_ULOG


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
      SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, devName);
      if(adaptor && adaptor->userData) {
	HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
      
	// make sure the counters are up to the second
	updateNioCounters(sp);
	
	// generic interface counters
	SFLCounters_sample_element elem = { 0 };
	elem.tag = SFLCOUNTERS_GENERIC;
	elem.counterBlock.generic.ifIndex = poller->dsi.ds_index;
	elem.counterBlock.generic.ifType = 6; // assume ethernet
	elem.counterBlock.generic.ifSpeed = adaptor->ifSpeed;
	elem.counterBlock.generic.ifDirection = adaptor->ifDirection;
	elem.counterBlock.generic.ifStatus = 3; // ifAdminStatus==up, ifOperstatus==up
	elem.counterBlock.generic.ifPromiscuousMode = adaptor->promiscuous;
	elem.counterBlock.generic.ifInOctets = adaptorNIO->nio.bytes_in;
	elem.counterBlock.generic.ifInUcastPkts = adaptorNIO->nio.pkts_in;
#define UNSUPPORTED_SFLOW_COUNTER32 (uint32_t)-1
	elem.counterBlock.generic.ifInMulticastPkts = UNSUPPORTED_SFLOW_COUNTER32;
	elem.counterBlock.generic.ifInBroadcastPkts = UNSUPPORTED_SFLOW_COUNTER32;
	elem.counterBlock.generic.ifInDiscards = adaptorNIO->nio.drops_in;
	elem.counterBlock.generic.ifInErrors = adaptorNIO->nio.errs_in;
	elem.counterBlock.generic.ifInUnknownProtos = UNSUPPORTED_SFLOW_COUNTER32;
	elem.counterBlock.generic.ifOutOctets = adaptorNIO->nio.bytes_out;
	elem.counterBlock.generic.ifOutUcastPkts = adaptorNIO->nio.pkts_out;
	elem.counterBlock.generic.ifOutMulticastPkts = UNSUPPORTED_SFLOW_COUNTER32;
	elem.counterBlock.generic.ifOutBroadcastPkts = UNSUPPORTED_SFLOW_COUNTER32;
	elem.counterBlock.generic.ifOutDiscards = adaptorNIO->nio.drops_out;
	elem.counterBlock.generic.ifOutErrors = adaptorNIO->nio.errs_out;
	SFLADD_ELEMENT(cs, &elem);
	sfl_poller_writeCountersSample(poller, cs);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       getSampler          __________________
    -----------------___________________________------------------
  */

  static SFLSampler *getSampler(HSP *sp, char *devName, uint32_t ifIndex)
  {
    SFLSampler *sampler = sfl_agent_getSamplerByIfIndex(sp->sFlow->agent, ifIndex);
    if(sampler == NULL) {
      SFLDataSource_instance dsi;
      SFL_DS_SET(dsi, 0, ifIndex, 0); // ds_class,ds_index,ds_instance
      HSPSFlow *sf = sp->sFlow;
      // add sampler (with sub-sampling rate), and poller too
      uint32_t samplingRate = sf->sFlowSettings->ulogSubSamplingRate;
      sampler = sfl_agent_addSampler(sf->agent, &dsi);
      sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, samplingRate);
      sfl_sampler_set_sFlowFsReceiver(sampler, HSP_SFLOW_RECEIVER_INDEX);
      if(devName) {
	uint32_t pollingInterval = sf->sFlowSettings ?
	  sf->sFlowSettings->pollingInterval :
	  SFL_DEFAULT_POLLING_INTERVAL;
	SFLPoller *poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters_interface);
	sfl_poller_set_sFlowCpInterval(poller, pollingInterval);
	sfl_poller_set_sFlowCpReceiver(poller, HSP_SFLOW_RECEIVER_INDEX);
	// remember the device name to make the lookups easier later.
	// Don't want to point directly to the SFLAdaptor or SFLAdaptorNIO object
	// in case it gets freed at some point.  The device name is enough.
	poller->userData = (void *)my_strdup(devName);
      }
    }
    return sampler;
  }

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  int readPackets(HSP *sp)
  {
    int batch = 0;
    static uint32_t MySkipCount=1;
    if(sp->sFlow->sFlowSettings->ulogSubSamplingRate == 0) {
      // packet sampling was disabled by setting desired rate to 0
      return 0;
    }
    if(sp->ulog_soc) {
      for( ; batch < HSP_READPACKET_BATCH; batch++) {
	char buf[HSP_MAX_MSG_BYTES];
	socklen_t peerlen = sizeof(sp->ulog_peer);
	int len = recvfrom(sp->ulog_soc,
			   buf,
			   HSP_MAX_MSG_BYTES,
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
		MySkipCount = sfl_random((2 * sp->sFlow->sFlowSettings->ulogSubSamplingRate) - 1);

		/* and take a sample */

		// we're seeing type==111 on Fedora14
		//if(msg->nlmsg_flags & NLM_F_REQUEST) { }
		//if(msg->nlmsg_flags & NLM_F_MULTI) { }
		//if(msg->nlmsg_flags & NLM_F_ACK) { }
		//if(msg->nlmsg_flags & NLM_F_ECHO) { }
		ulog_packet_msg_t *pkt = NLMSG_DATA(msg);
		
		if(debug > 1) {
		  myLog(LOG_INFO, "mark=%u ts=%s hook=%u in=%s out=%s len=%u prefix=%s maclen=%u\n",
			pkt->mark,
			ctime(&pkt->timestamp_sec),
			pkt->hook,
			pkt->indev_name,
			pkt->outdev_name,
			pkt->data_len,
			pkt->prefix,
			pkt->mac_len);
		  if(pkt->mac_len == 14) {
		    u_char macdst[12], macsrc[12];
		    printHex(pkt->mac+6,6,macsrc,12,NO);
		    printHex(pkt->mac+0,6,macdst,12,NO);
		    uint16_t ethtype = (pkt->mac[12] << 8) + pkt->mac[13];
		    myLog(LOG_INFO, "%s -> %s (ethertype=0x%04X)", macsrc, macdst, ethtype);
		  }
		}

		
		SFL_FLOW_SAMPLE_TYPE fs = { 0 };
	
		char *sampler_dev = NULL;
		uint32_t sampler_ifIndex = 0;

		// set the ingress and egress ifIndex numbers.
		// Can be "INTERNAL" (0x3FFFFFFF) or "UNKNOWN" (0).
		if(pkt->indev_name[0]) {
		  SFLAdaptor *in = adaptorListGet(sp->adaptorList, pkt->indev_name);
		  if(in) {
		    fs.input = in->ifIndex;
		    sampler_dev = pkt->indev_name;
		    sampler_ifIndex = in->ifIndex;
		  }
		}
		else {
		  fs.input = SFL_INTERNAL_INTERFACE;
		}
		if(pkt->outdev_name[0]) {
		  SFLAdaptor *out = adaptorListGet(sp->adaptorList, pkt->outdev_name);
		  if(out && out->ifIndex) {
		    fs.output = out->ifIndex;
		    // the sampler_dev may have already been set above.  By overriding
		    // it here we are biasing towards egress-sampling for packets that
		    // matched both an ingress and an egress interface.  In practice
		    // most packets will only match one or the other,  though.  They
		    // will either be "eth0 -> lo" or "lo -> eth0".  Since we don't
		    // usually allow "lo" to be in the adaptorList,  the upshot is
		    // that we are offering bidirectional sampling on the "eth0" (and
		    // similar) interfaces.
		    // It might be more stable if we biased towards ingress-sampling
		    // and only set these vars if they were not set before,  but
		    // further investigation is required.  For example,  the really
		    // correct thing to do might be to generate a separate sample
		    // for each interface,  even though it was the same packet.  That
		    // way we would have true bidirectional sampling on any
		    // interface that makes it into the adaptorList.
		    sampler_dev = pkt->outdev_name;
		    sampler_ifIndex = out->ifIndex;
		  }
		}
		else {
		  fs.output = SFL_INTERNAL_INTERFACE;
		}

		// must have an ifIndex
		if(sampler_ifIndex) {
		  SFLSampler *sampler = getSampler(sp, sampler_dev, sampler_ifIndex);
		  
		  if(sampler) {
		    SFLFlow_sample_element hdrElem = { 0 };
		    hdrElem.tag = SFLFLOW_HEADER;
		    uint32_t FCS_bytes = 4;
		    uint32_t maxHdrLen = sampler->sFlowFsMaximumHeaderSize;
		    hdrElem.flowType.header.frame_length = pkt->data_len + FCS_bytes;
		    hdrElem.flowType.header.stripped = FCS_bytes;
		    
		    u_char hdr[HSP_MAX_HEADER_BYTES];
		    
		    if(pkt->mac_len == 14) {
		      // set the header_protocol to ethernet and
		      // reunite the mac header and payload in one buffer
		      hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
		      memcpy(hdr, pkt->mac, 14);
		      maxHdrLen -= 14;
		      uint32_t payloadBytes = (pkt->data_len < maxHdrLen) ? pkt->data_len : maxHdrLen;
		      memcpy(hdr+14, pkt->payload, payloadBytes);
		      hdrElem.flowType.header.header_length = payloadBytes + 14;
		      hdrElem.flowType.header.header_bytes = hdr;
		      hdrElem.flowType.header.frame_length += 14;
		    }
		    else {
		      // no need to copy - just point at the payload
		      u_char ipversion = pkt->payload[0] >> 4;
		      if(ipversion != 4 && ipversion != 6) {
			if(debug) myLog(LOG_ERR, "received non-IP packet. Encapsulation is unknown");
		      }
		      else {
			hdrElem.flowType.header.header_protocol = (ipversion == 4) ? SFLHEADER_IPv4 : SFLHEADER_IPv6;
			hdrElem.flowType.header.stripped += 14; // assume ethernet was (or will be) the framing
			hdrElem.flowType.header.header_length = (pkt->data_len < maxHdrLen) ? pkt->data_len : maxHdrLen;
			hdrElem.flowType.header.header_bytes = pkt->payload;
		      }
		    }
		    
		    SFLADD_ELEMENT(&fs, &hdrElem);
		    // submit the actual sampling rate so it goes out with the sFlow feed
		    // otherwise the sampler object would fill in his own (sub-sampling) rate.
		    uint32_t actualSamplingRate = sp->sFlow->sFlowSettings->ulogActualSamplingRate;
		    fs.sampling_rate = actualSamplingRate;
		    
		    // estimate the sample pool from the samples.  Could maybe do this
		    // above with the (possibly more granular) ulogSamplingRate, but then
		    // we would have to look up the sampler object every time, which
		    // might be too expensive in the case where ulogSamplingRate==1.
		    sampler->samplePool += actualSamplingRate;
		    
		    sfl_sampler_writeFlowSample(sampler, &fs);
		  }
		}
	      }
	    }
	  } 
	}
      }
    }
    return batch;
  }

#endif /* HSF_ULOG */
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

