/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  extern int debug;

#ifdef HSF_ULOG

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  int readPackets(HSP *sp)
  {
    int batch = 0;
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
		
	      // set the ingress and egress ifIndex numbers.
	      // Can be "INTERNAL" (0x3FFFFFFF) or "UNKNOWN" (0).
	      if(pkt->indev_name[0]) {
		SFLAdaptor *in = adaptorListGet(sp->adaptorList, pkt->indev_name);
		if(in) fs.input = in->ifIndex;
		// find or create sampler for in->ifIndex $$$
	      }
	      else {
		fs.input = SFL_INTERNAL_INTERFACE;
	      }
	      if(pkt->outdev_name[0]) {
		SFLAdaptor *out = adaptorListGet(sp->adaptorList, pkt->outdev_name);
		if(out) fs.output = out->ifIndex;
		// find or create sampler for out->ifIndex $$$
	      }
	      else {
		fs.output = SFL_INTERNAL_INTERFACE;
	      }
	      SFLFlow_sample_element hdrElem = { 0 };
	      hdrElem.tag = SFLFLOW_HEADER;
	      uint32_t FCS_bytes = 4;
	      uint32_t maxHdrLen = sp->sFlow->sampler->sFlowFsMaximumHeaderSize;
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
		// just point at the payload
		// $$$ check for IPv6?  (sFlow should really have SFLHEADER_IP as an option here, so
		// that the collector can decide if it is v4 or v6)
		hdrElem.flowType.header.header_protocol = SFLHEADER_IPv4;
		hdrElem.flowType.header.stripped += 14; // assume ethernet
		hdrElem.flowType.header.header_length = (pkt->data_len < maxHdrLen) ? pkt->data_len : maxHdrLen;
		hdrElem.flowType.header.header_bytes = pkt->payload;
	      }
		
	      SFLADD_ELEMENT(&fs, &hdrElem);
	      sfl_sampler_writeFlowSample(sp->sFlow->sampler, &fs);
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

