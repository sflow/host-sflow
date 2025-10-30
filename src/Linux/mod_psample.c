/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/psample.h>
#include <stdlib.h>
#include <net/if.h>

#include "util_netlink.h"

#define HSP_PSAMPLE_READNL_RCV_BUF 16384
#define HSP_PSAMPLE_READNL_BATCH 10
#define HSP_PSAMPLE_RCVBUF 8000000

  // Shadow the attributes in linux/psample.h so
  // we can easily compile/test fields that are not
  // defined on the kernel we are compiling on.
  typedef enum {
    /* sampled packet metadata */
    HSP_PSAMPLE_ATTR_IIFINDEX,
    HSP_PSAMPLE_ATTR_OIFINDEX,
    HSP_PSAMPLE_ATTR_ORIGSIZE,
    HSP_PSAMPLE_ATTR_SAMPLE_GROUP,
    HSP_PSAMPLE_ATTR_GROUP_SEQ,
    HSP_PSAMPLE_ATTR_SAMPLE_RATE,
    HSP_PSAMPLE_ATTR_DATA,
    HSP_PSAMPLE_ATTR_TUNNEL,

    /* commands attributes */
    HSP_PSAMPLE_ATTR_GROUP_REFCOUNT,

    HSP_PSAMPLE_ATTR_PAD,
    HSP_PSAMPLE_ATTR_OUT_TC,/* u16 */
    HSP_PSAMPLE_ATTR_OUT_TC_OCC,/* u64, bytes */
    HSP_PSAMPLE_ATTR_LATENCY,/* u64, nanoseconds */
    HSP_PSAMPLE_ATTR_TIMESTAMP,/* u64, nanoseconds */
    HSP_PSAMPLE_ATTR_PROTO,/* u16 */
    HSP_PSAMPLE_ATTR_USER_COOKIE,/* binary, user provided data */
    HSP_PSAMPLE_ATTR_SAMPLE_PROBABILITY,/* no argument, interpret rate in
					 * PSAMPLE_ATTR_SAMPLE_RATE as a
					 * probability scaled 0 - U32_MAX.
					 */
    
    __HSP_PSAMPLE_ATTR_MAX
  } EnumHSPPsampleAttributes;
  
  typedef enum {
    HSP_PSAMPLE_STATE_INIT=0,
    HSP_PSAMPLE_STATE_GET_FAMILY,
    HSP_PSAMPLE_STATE_JOIN_GROUP,
    HSP_PSAMPLE_STATE_RUN } EnumPsampleState;

  typedef struct _HSP_mod_PSAMPLE {
    EnumPsampleState state;
    EVBus *packetBus;
    EVEvent *psampleEvent;
    bool psample_configured;
    int nl_sock;
    uint32_t nl_seq;
    int retry_countdown;
#define HSP_PSAMPLE_WAIT_RETRY_S 15
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id;
    // psample channel groups
    uint32_t grp_ingress;
    uint32_t grp_egress;
    uint32_t last_grp_seq[2];
    bool probability_warning;
  } HSP_mod_PSAMPLE;

  /*_________________---------------------------__________________
    _________________    getFamily_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void getFamily_PSAMPLE(EVMod *mod)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    EVDebug(mod, 1, "getFamily");
    mdata->state = HSP_PSAMPLE_STATE_GET_FAMILY;
    mdata->retry_countdown = HSP_PSAMPLE_WAIT_RETRY_S;
    int status = UTNLGeneric_send(mdata->nl_sock,
				  mod->id,
				  GENL_ID_CTRL,
				  CTRL_CMD_GETFAMILY,
				  CTRL_ATTR_FAMILY_NAME,
				  PSAMPLE_GENL_NAME,
				  sizeof(PSAMPLE_GENL_NAME)+1,
				  ++mdata->nl_seq);
    if(status < 0) {
      EVDebug(mod, 1, "getFamily_PSAMPLE() UTNLGeneric_send failed: %s",
	      strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void joinGroup_PSAMPLE(EVMod *mod)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    EVDebug(mod, 1, "joinGroup");
    mdata->state = HSP_PSAMPLE_STATE_JOIN_GROUP;
    // register for the multicast group_id
    if(setsockopt(mdata->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &mdata->group_id,
		  sizeof(mdata->group_id)) == -1) {
      myLog(LOG_ERR, "error joining PSAMPLE netlink group %u : %s",
	    mdata->group_id,
	    strerror(errno));
      // go back to the retry loop
      // Note that if we have dropped privileges in the interim then
      // we will continue to fail here, with "Operation not permitted"
      // even if "sudo modprobe sample" has installed the kernel module.
      // Not sure if we should consider that a fatal error or not?
      mdata->state = HSP_PSAMPLE_STATE_GET_FAMILY;
    }
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(EVMod *mod, struct nlmsghdr *nlh, int numbytes)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    int msglen = nlh->nlmsg_len;
    if(msglen > numbytes) {
      EVDebug(mod, 0, "processNetlink_GENERIC msglen too long");
      return;
    }
    if(msglen < (NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN)) {
      EVDebug(mod, 0, "processNetlink_GENERIC msglen too short");
      return;
    }
    char *msg = (char *)NLMSG_DATA(nlh);
    msglen -= NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    EVDebug(mod, 1, "generic netlink CMD = %u", genl->cmd);
    msglen -= GENL_HDRLEN;

    struct nlattr *attr0 = (struct nlattr *)(msg + GENL_HDRLEN);
    for(int attrs_len = msglen;
	UTNLA_OK(attr0, attrs_len);
	attr0 = UTNLA_NEXT(attr0, attrs_len)) {
      switch(attr0->nla_type) {
      case CTRL_ATTR_VERSION:
	mdata->genetlink_version = *(uint32_t *)UTNLA_DATA(attr0);
	break;
      case CTRL_ATTR_FAMILY_ID:
	mdata->family_id = *(uint16_t *)UTNLA_DATA(attr0);
	EVDebug(mod, 1, "generic family id: %u", mdata->family_id); 
	break;
      case CTRL_ATTR_FAMILY_NAME:
	EVDebug(mod, 1, "generic family name: %s", (char *)UTNLA_DATA(attr0));
	break;
      case CTRL_ATTR_MCAST_GROUPS:
	{
	  struct nlattr *attr1 = (struct nlattr *)UTNLA_DATA(attr0);
	  for(int attr0_len = UTNLA_PAYLOAD(attr0);
	      UTNLA_OK(attr1, attr0_len);
	      attr1 = UTNLA_NEXT(attr1, attr0_len)) {
	    char *grp_name=NULL;
	    uint32_t grp_id=0;
	    struct nlattr *attr2 = UTNLA_DATA(attr1);
	    for(int attr1_len = UTNLA_PAYLOAD(attr1);
		UTNLA_OK(attr2, attr1_len);
		attr2 = UTNLA_NEXT(attr2, attr1_len)) {
	      switch(attr2->nla_type) {
	      case CTRL_ATTR_MCAST_GRP_NAME:
		grp_name = (char *)UTNLA_DATA(attr2);
		EVDebug(mod, 1, "multicast group: %s", grp_name);
		break;
	      case CTRL_ATTR_MCAST_GRP_ID:
		grp_id = *(uint32_t *)UTNLA_DATA(attr2);
		EVDebug(mod, 1, "multicast group id: %u", grp_id);
		break;
	      }
	    }
	    if(mdata->state == HSP_PSAMPLE_STATE_GET_FAMILY
	       && grp_name
	       && grp_id
	       && my_strequal(grp_name, PSAMPLE_NL_MCGRP_SAMPLE_NAME)) {
	      EVDebug(mod, 1, "psample found group %s=%u", grp_name, grp_id);
	      mdata->group_id = grp_id;
	      joinGroup_PSAMPLE(mod);
	    }
	  }
	}
	break;
      default:
	EVDebug(mod, 1, "psample attr type: %u (nested=%u) len: %u",
		attr0->nla_type,
		attr0->nla_type & NLA_F_NESTED,
		attr0->nla_len);
      }
    }
  }


  /*_________________---------------------------__________________
    _________________  processNetlink_PSAMPLE   __________________
    -----------------___________________________------------------
  */

  static void freeExtendedElements(SFLFlow_sample_element *elements) {
    for(SFLFlow_sample_element *elem = elements; elem; ) {
      SFLFlow_sample_element *next_elem = elem->nxt;
      my_free(elem);
      elem = next_elem;
    }
  }

  static void processNetlink_PSAMPLE(EVMod *mod, struct nlmsghdr *nlh, int numbytes)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    int msglen = nlh->nlmsg_len;
    if(msglen > numbytes) {
      EVDebug(mod, 0, "processNetlink_PSAMPLE msglen too long");
      return;
    }
    if(msglen < (NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN)) {
      EVDebug(mod, 0, "processNetlink_PSAMPLE msglen too short");
      return;
    }
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    msglen -= NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    EVDebug(mod, 2, "processNetlink_PSAMPLE (type=%u) CMD = %u", nlh->nlmsg_type, genl->cmd);
    msglen -= GENL_HDRLEN;

    HSPPSample psmp = {};
    SFLFlow_sample_element *ext_elems = NULL;
    // TODO: tunnel encap/decap may be avaiable too
    bool free_ext_elems = YES;
    bool sample_prob = NO;

    struct nlattr *ps_attr = (struct nlattr *)(msg + GENL_HDRLEN);
    for(int attrs_len = msglen;
	UTNLA_OK(ps_attr, attrs_len);
	ps_attr = UTNLA_NEXT(ps_attr, attrs_len)) {
      u_char *datap = UTNLA_DATA(ps_attr);
      int datalen = UTNLA_PAYLOAD(ps_attr);

      switch(ps_attr->nla_type) {
      case PSAMPLE_ATTR_IIFINDEX: psmp.ifin = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_OIFINDEX: psmp.ifout = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_ORIGSIZE: psmp.pkt_len = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_SAMPLE_GROUP: psmp.grp_no = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_GROUP_SEQ: psmp.grp_seq = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_SAMPLE_RATE: psmp.sample_n = *(uint32_t *)datap; break;
      case HSP_PSAMPLE_ATTR_SAMPLE_PROBABILITY: sample_prob = YES; break;
      case HSP_PSAMPLE_ATTR_PROTO: psmp.proto = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_DATA:
	psmp.hdr = datap;
	psmp.hdr_len = datalen;
	break;
      case HSP_PSAMPLE_ATTR_OUT_TC:
	{
	  // queue id
	  SFLFlow_sample_element *egress_Q = my_calloc(sizeof(SFLFlow_sample_element));
	  egress_Q->tag = SFLFLOW_EX_EGRESS_Q;
	  psmp.egressQ_id = *(uint16_t *)datap;
	  egress_Q->flowType.egress_queue.queue = psmp.egressQ_id;
	  ADD_TO_LIST(ext_elems, egress_Q);
	}
	break;
      case HSP_PSAMPLE_ATTR_OUT_TC_OCC:
	{
	  // queue occupancy (bytes)
	  SFLFlow_sample_element *Q_depth = my_calloc(sizeof(SFLFlow_sample_element));
	  Q_depth->tag = SFLFLOW_EX_Q_DEPTH;
	  psmp.egressQ_byts = *(uint64_t *)datap;
	  Q_depth->flowType.queue_depth.depth = psmp.egressQ_byts; // Will take lo 32-bits
	  ADD_TO_LIST(ext_elems, Q_depth);
	}
	break;
      case HSP_PSAMPLE_ATTR_LATENCY:
	{
	  // transit latency (nS)
	  SFLFlow_sample_element *transit = my_calloc(sizeof(SFLFlow_sample_element));
	  transit->tag = SFLFLOW_EX_TRANSIT;
	  psmp.transit_nS = *(uint64_t *)datap;
	  transit->flowType.transit_delay.delay = psmp.transit_nS; // Will take lo 32-bits
	  ADD_TO_LIST(ext_elems, transit);
	}
	break;
      case HSP_PSAMPLE_ATTR_TIMESTAMP:
	{
	  // wall clock timestamp - unixtime UTC (nS)
	  SFLFlow_sample_element *tstamp = my_calloc(sizeof(SFLFlow_sample_element));
	  tstamp->tag = SFLFLOW_EX_TIMESTAMP;
	  psmp.timestamp_nS = *(uint64_t *)datap;
	  tstamp->flowType.timestamp.nanoseconds = psmp.timestamp_nS;
	  ADD_TO_LIST(ext_elems, tstamp);
	}
	break;
      }
    }

    if(sample_prob
       && psmp.sample_n) {
      // sampling rate is actually a sampling probability expressed
      // as a 32-bit number X, where probability = UINT_MAX / X.
      // Unusual to change the meaning of a netlink attribute by
      // side-effect like this. Not my favorite PSAMPLE patch. Conversion
      // back to 1-in-N results in a error than can be significant.
      if(!mdata->probability_warning) {
	mdata->probability_warning = YES;
	myLog(LOG_ERR, "Use of PSAMPLE_ATTR_SAMPLE_PROBABILITY is not compatible with sFlow");
      }
      ldiv_t ratio = ldiv(UINT_MAX, psmp.sample_n);
      psmp.sample_n = ratio.quot;
      // see if we should round up
      if(ratio.rem > (UINT_MAX / 2))
	psmp.sample_n++;
    }
    
    //#define TEST_PSAMPLE_EXTENSIONS 1
#ifdef TEST_PSAMPLE_EXTENSIONS
    {
      uint16_t queueIdx = 7;
      uint64_t queueDepth = 22222;
      uint64_t transitDelay = 33333L;
      SFLFlow_sample_element *egress_Q = my_calloc(sizeof(SFLFlow_sample_element));
      egress_Q->tag = SFLFLOW_EX_EGRESS_Q;
      psmp.egressQ_id = *(uint16_t *)(&queueIdx);
      egress_Q->flowType.egress_queue.queue = psmp.egressQ_id;
      ADD_TO_LIST(ext_elems, egress_Q);
      // queue occupancy (bytes)
      SFLFlow_sample_element *Q_depth = my_calloc(sizeof(SFLFlow_sample_element));
      Q_depth->tag = SFLFLOW_EX_Q_DEPTH;
      psmp.egressQ_byts = *(uint64_t *)(&queueDepth);
      Q_depth->flowType.queue_depth.depth = psmp.egressQ_byts; // Will take lo 32-bits
      ADD_TO_LIST(ext_elems, Q_depth);
      // transit latency (nS)
      SFLFlow_sample_element *transit = my_calloc(sizeof(SFLFlow_sample_element));
      transit->tag = SFLFLOW_EX_TRANSIT;
      psmp.egressQ_nS = *(uint64_t *)(&transitDelay);
      transit->flowType.transit_delay.delay = psmp.egressQ_nS; // Will take lo 32-bits
      ADD_TO_LIST(ext_elems, transit);
    }
#endif

    EVDebug(mod, 3, "grp=%u", psmp.grp_no);

    // share on bus
    // TOOD: consider having all the packet-sampling modules
    // do this, then only call "takeSample()" in one place?
    EVEventTx(mod, mdata->psampleEvent, &psmp, sizeof(psmp));
    
    // TODO: this filter can be pushed into kernel with BPF expression on socket
    // but that might affect control messages?  For now it seems unlikely that
    // doing the fitering here will be catastophic, but we can always revisit.
    if(psmp.grp_no
       && (psmp.grp_no == mdata->grp_ingress
	   || psmp.grp_no == mdata->grp_egress)
       && psmp.hdr
       && psmp.hdr_len
       && psmp.pkt_len
       && psmp.sample_n) {
      
      // index for grp data
      int egress = (psmp.grp_no == mdata->grp_egress) ? 1 : 0;

      // confirmation that we have moved to state==run
      if(mdata->state == HSP_PSAMPLE_STATE_JOIN_GROUP)
	mdata->state = HSP_PSAMPLE_STATE_RUN;

      uint32_t drops = 0;
      if(mdata->last_grp_seq[egress]) {
	drops = psmp.grp_seq - mdata->last_grp_seq[egress] - 1;
	if(drops > 0x7FFFFFFF)
	  drops = 1;
      }
      mdata->last_grp_seq[egress] = psmp.grp_seq;

      EVDebug(mod, 2, "grp=%u in=%u out=%u proto=%u n=%u seq=%u drops=%u pktlen=%u",
	      psmp.grp_no,
	      psmp.ifin,
	      psmp.ifout,
	      psmp.proto,
	      psmp.sample_n,
	      psmp.grp_seq,
	      drops,
	      psmp.pkt_len);

      SFLAdaptor *inDev = adaptorByIndex(sp, psmp.ifin);
      SFLAdaptor *outDev = adaptorByIndex(sp, psmp.ifout);
      SFLAdaptor *samplerDev = egress ? outDev : inDev;
      if(!samplerDev) {
        // handle startup race-condition where interface has not been discovered yet
        EVDebug(mod, 2, "unknown ifindex %u (startup race-condition?)", psmp.ifin);
	freeExtendedElements(ext_elems);
        return;
      }

      // See if the sample_n matches what we think was configured
      HSPAdaptorNIO *nio = ADAPTOR_NIO(samplerDev);
      bool takeIt = YES;
      uint32_t this_sample_n = psmp.sample_n;
      
      if(psmp.sample_n != nio->sampling_n) {

	EVDebug(mod, 2, "psample sampling N (%u) != configured N (%u)",
		psmp.sample_n,
		nio->sampling_n);

	if(psmp.sample_n < nio->sampling_n) {
	  // apply sub-sampling on this interface.  We may get here if the
	  // hardware or kernel is configured to sample at 1:N and then
	  // hsflowd.conf or DNS-SD adjusts it to 1:M dynamically.  This
	  // could be a legitimate use-case, especially if the same PSAMPLE
	  // group is feeding more than one consumer.
	  nio->subSampleCount += psmp.sample_n;
	  if(nio->subSampleCount >= nio->sampling_n) {
	    this_sample_n = nio->subSampleCount;
	    nio->subSampleCount = 0;
	  }
	  else {
	    takeIt = NO;
	  }
	}
      }

      if(takeIt) {
	// take the sample - this will take over responsibility for
	// freeing the extended elements when the sample has
	// been fully processed.
	free_ext_elems = NO;
	takeSample(sp,
		   inDev,
		   outDev,
		   samplerDev,
		   psmp.proto,
		   sp->psample.ds_options,
		   0, // hook
		   psmp.hdr, // mac hdr
		   14, // mac hdr len
		   psmp.hdr + 14, // payload
		   psmp.hdr_len - 14, // captured payload len
		   psmp.pkt_len - 14, // whole pdu len
		   drops,
		   this_sample_n,
		   ext_elems);
      }
    }
    if(free_ext_elems) {
      // we didn't pass these on, so clean up
      freeExtendedElements(ext_elems);
    }
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(EVMod *mod, struct nlmsghdr *nlh, int numbytes)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(mod, nlh, numbytes);
    }
    else if(nlh->nlmsg_type == mdata->family_id) {
      processNetlink_PSAMPLE(mod, nlh, numbytes);
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_PSAMPLE     __________________
    -----------------___________________________------------------
  */

  static void readNetlink_PSAMPLE(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    uint8_t recv_buf[HSP_PSAMPLE_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < HSP_PSAMPLE_READNL_BATCH; batch++) {
      int msglen = recv(sock->fd, recv_buf, sizeof(recv_buf), 0);
      if(msglen < sizeof(struct nlmsghdr))
	break;
      EVDebug(mod, 4, "readNetlink_PSAMPLE - msg = %d bytes", msglen);
      int numbytes = msglen;
      struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
      while(NLMSG_OK(nlh, numbytes)){
	if(nlh->nlmsg_type == NLMSG_DONE)
	  break;
	if(nlh->nlmsg_type == NLMSG_ERROR){
	  struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	  if(err_msg->error == 0) {
	    EVDebug(mod, 1, "received Netlink ACK");
	  }
	  else {
	    // TODO: parse NLMSGERR_ATTR_OFFS to get offset?  Might be helpful
	    EVDebug(mod, 1, "state %u: error in netlink message: %d : %s",
		    mdata->state,
		    err_msg->error,
		    strerror(-err_msg->error));
	  }
	  break;
	}
	processNetlink(mod, nlh, numbytes);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
  
    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)
  
    if(mdata->psample_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    if(sp->psample.group != 0) {
      // PSAMPLE group is set, This is always the ingress sampling channel,
      // with the next one up being for egress samples. Capture that here.
      if(sp->psample.ingress)
	mdata->grp_ingress = sp->psample.group;
      if(sp->psample.egress)
	mdata->grp_egress = sp->psample.group + 1;
      // Open the netfilter socket while we are still root
      mdata->nl_sock = UTNLGeneric_open(mod->id);
      if(mdata->nl_sock > 0) {
	// increase socket receiver buffer size
	UTSocketRcvbuf(mdata->nl_sock, HSP_PSAMPLE_RCVBUF);
	// and submit for polling
	EVBusAddSocket(mod,
		       mdata->packetBus,
		       mdata->nl_sock,
		       readNetlink_PSAMPLE,
		       NULL);
	// kick off with the family lookup request
	getFamily_PSAMPLE(mod);
      }
    }

    mdata->psample_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    
    switch(mdata->state) {
    case HSP_PSAMPLE_STATE_INIT:
      // waiting for evt_config_changed
      break;
    case HSP_PSAMPLE_STATE_GET_FAMILY:
      // waiting for family info response
      if(--mdata->retry_countdown <= 0)
	getFamily_PSAMPLE(mod);
      break;
    case HSP_PSAMPLE_STATE_JOIN_GROUP:
      // joined group, waiting for first matching sample
      break;
    case HSP_PSAMPLE_STATE_RUN:
      // got at least one sample
      break;
    }
  }
  
  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_psample(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_PSAMPLE));
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_TICK), evt_tick);
    mdata->psampleEvent = EVGetEvent(mdata->packetBus, HSPEVENT_PSAMPLE);

    // if ds_options not set, apply defaults for kernel/asic sampling where
    // we know the interface index of the sampling datasource because
    // we know if the sample was taken on ingress or egress (indicated
    // by psample group channel number) and we know the in/out ifindex
    // numbers for the packet.
    if(sp->psample.ds_options == 0)
      sp->psample.ds_options = (HSP_SAMPLEOPT_DEV_SAMPLER
				| HSP_SAMPLEOPT_DEV_POLLER
				| HSP_SAMPLEOPT_BRIDGE
				| HSP_SAMPLEOPT_PSAMPLE);
    
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
