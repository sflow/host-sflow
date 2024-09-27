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
#include <net/if.h>

#include "util_netlink.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define HSP_PSAMPLE_READNL_RCV_BUF 16384
#define HSP_PSAMPLE_RCVMSG_CBUFLEN 256
#define HSP_PSAMPLE_READNL_BATCH 10
#define HSP_PSAMPLE_MM_BATCH 8
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

    __HSP_PSAMPLE_ATTR_MAX
  } EnumHSPPsampleAttributes;
  
  typedef enum {
    HSP_PSAMPLE_STATE_INIT=0,
    HSP_PSAMPLE_STATE_GET_FAMILY,
    HSP_PSAMPLE_STATE_WAIT,
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
    struct mmsghdr mmsgheader[HSP_PSAMPLE_MM_BATCH];
    struct iovec iov[HSP_PSAMPLE_MM_BATCH];
    char controlbuf[HSP_PSAMPLE_MM_BATCH][HSP_PSAMPLE_RCVMSG_CBUFLEN];
    UTSockAddr peer[HSP_PSAMPLE_MM_BATCH];
    char msgbuf[HSP_PSAMPLE_MM_BATCH][HSP_PSAMPLE_READNL_RCV_BUF];
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
    UTNLGeneric_send(mdata->nl_sock,
		     mod->id,
		     GENL_ID_CTRL,
		     CTRL_CMD_GETFAMILY,
		     CTRL_ATTR_FAMILY_NAME,
		     PSAMPLE_GENL_NAME,
		     sizeof(PSAMPLE_GENL_NAME)+1,
		     ++mdata->nl_seq);
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
    }
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    char *msg = (char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    EVDebug(mod, 1, "generic netlink CMD = %u", genl->cmd);

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *attr = (struct nlattr *)(msg + offset);
      if(attr->nla_len == 0 ||
	 (attr->nla_len + offset) > msglen) {
	myLog(LOG_ERR, "processNetlink_GENERIC attr parse error");
	break; // attr parse error
      }
      char *attr_datap = (char *)attr + NLA_HDRLEN;
      switch(attr->nla_type) {
      case CTRL_ATTR_VERSION:
	mdata->genetlink_version = *(uint32_t *)attr_datap;
	break;
      case CTRL_ATTR_FAMILY_ID:
	mdata->family_id = *(uint16_t *)attr_datap;
	EVDebug(mod, 1, "generic family id: %u", mdata->family_id); 
	break;
      case CTRL_ATTR_FAMILY_NAME:
	EVDebug(mod, 1, "generic family name: %s", attr_datap); 
	break;
      case CTRL_ATTR_MCAST_GROUPS:
	for(int grp_offset = NLA_HDRLEN; grp_offset < attr->nla_len;) {
	  struct nlattr *grp_attr = (struct nlattr *)(msg + offset + grp_offset);
	  if(grp_attr->nla_len == 0 ||
	     (grp_attr->nla_len + grp_offset) > attr->nla_len) {
	    myLog(LOG_ERR, "processNetlink_GENERIC grp_attr parse error");
	    break;
	  }
	  char *grp_name=NULL;
	  uint32_t grp_id=0;
	  for(int gf_offset = NLA_HDRLEN; gf_offset < grp_attr->nla_len; ) {
	    struct nlattr *gf_attr = (struct nlattr *)(msg + offset + grp_offset + gf_offset);
	    if(gf_attr->nla_len == 0 ||
	       (gf_attr->nla_len + gf_offset) > grp_attr->nla_len) {
	      myLog(LOG_ERR, "processNetlink_GENERIC gf_attr parse error");
	      break;
	    }
	    char *grp_attr_datap = (char *)gf_attr + NLA_HDRLEN;
	    switch(gf_attr->nla_type) {
	    case CTRL_ATTR_MCAST_GRP_NAME:
	      grp_name = grp_attr_datap;
	      EVDebug(mod, 1, "psample multicast group: %s", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      EVDebug(mod, 1, "psample multicast group id: %u", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(mdata->state == HSP_PSAMPLE_STATE_GET_FAMILY
	     && grp_name
	     && grp_id
	     && my_strequal(grp_name, PSAMPLE_NL_MCGRP_SAMPLE_NAME)) {
	    EVDebug(mod, 1, "psample found group %s=%u", grp_name, grp_id);
	    mdata->group_id = grp_id;
	    joinGroup_PSAMPLE(mod);
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	EVDebug(mod, 1, "psample attr type: %u (nested=%u) len: %u",
		attr->nla_type,
		attr->nla_type & NLA_F_NESTED,
		attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
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

  static void processNetlink_PSAMPLE(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    EVDebug(mod, 2, "psample netlink (type=%u) CMD = %u", nlh->nlmsg_type, genl->cmd);

    HSPPSample psmp = {};
    SFLFlow_sample_element *ext_elems = NULL;
    // TODO: tunnel encap/decap may be avaiable too

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *ps_attr = (struct nlattr *)(msg + offset);
      if(ps_attr->nla_len == 0 ||
	 (ps_attr->nla_len + offset) > msglen) {
	myLog(LOG_ERR, "processNetlink_PSAMPLE attr parse error");
	break;
      }
      u_char *datap = UTNLA_DATA(ps_attr);
      int datalen = UTNLA_PAYLOAD(ps_attr);

      switch(ps_attr->nla_type) {
	// TODO: interpret PSAMPLE_ATTR_PROTO
      case PSAMPLE_ATTR_IIFINDEX: psmp.ifin = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_OIFINDEX: psmp.ifout = *(uint16_t *)datap; break;
      case PSAMPLE_ATTR_ORIGSIZE: psmp.pkt_len = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_SAMPLE_GROUP: psmp.grp_no = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_GROUP_SEQ: psmp.grp_seq = *(uint32_t *)datap; break;
      case PSAMPLE_ATTR_SAMPLE_RATE: psmp.sample_n = *(uint32_t *)datap; break;
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
      }
      offset += NLMSG_ALIGN(ps_attr->nla_len);
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

      EVDebug(mod, 2, "grp=%u in=%u out=%u n=%u seq=%u drops=%u pktlen=%u",
	      psmp.grp_no,
	      psmp.ifin,
	      psmp.ifout,
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
	takeSample(sp,
		   inDev,
		   outDev,
		   samplerDev,
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
      else {
	// clean up
	freeExtendedElements(ext_elems);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(mod, nlh);
    }
    else if(nlh->nlmsg_type == mdata->family_id) {
      processNetlink_PSAMPLE(mod, nlh);
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_PSAMPLE     __________________
    -----------------___________________________------------------
  */

  static void readNetlink_PSAMPLE(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_PSAMPLE *mdata = (HSP_mod_PSAMPLE *)mod->data;
    
    int batch = 0;
    for( ; batch < HSP_PSAMPLE_READNL_BATCH; batch++) {

      // wire up my packet buffers (may only
      // need the msg_namelen to be reset every time)
      for(uint32_t ii = 0; ii < HSP_PSAMPLE_MM_BATCH; ii++) {
	struct msghdr *mh = &mdata->mmsgheader[ii].msg_hdr;
	mh->msg_control = &mdata->controlbuf[ii];
	mh->msg_controllen = HSP_PSAMPLE_RCVMSG_CBUFLEN;
	mh->msg_name = &mdata->peer[ii];
	mh->msg_namelen = sizeof(mdata->peer[ii]);
	mh->msg_iov = &mdata->iov[ii];
	mh->msg_iovlen = 1;
	mh->msg_flags = 0;
	mdata->iov[ii].iov_base = mdata->msgbuf[ii];;
	mdata->iov[ii].iov_len = HSP_PSAMPLE_READNL_RCV_BUF;
      }
      int flags = 0;
      struct timespec timeout = {};
      int cc = recvmmsg(sock->fd, mdata->mmsgheader, HSP_PSAMPLE_MM_BATCH, flags, &timeout);
      
      if(cc > 1)
	EVDebug(mod, 0, "recvmmsg got %u msgs\n", cc);
      
      if(cc <= 0) {
	if(errno != EAGAIN) {
	  myLog(LOG_ERR, "recvmmsg() failed, cc=%d, %s\n", cc, strerror(errno));
	}
	return;
      }
      for(int ii = 0; ii < cc; ii++) {
	struct mmsghdr *mm = &mdata->mmsgheader[ii];      
	int numbytes = mm->msg_len;
	if(numbytes > 0) {
	  struct nlmsghdr *nlh = (struct nlmsghdr*) mdata->msgbuf[ii];
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
	    processNetlink(mod, nlh);
	    nlh = NLMSG_NEXT(nlh, numbytes);
	  }
	}
      }
    }

    // This should have advanced the state past GET_FAMILY
    if(mdata->state == HSP_PSAMPLE_STATE_GET_FAMILY) {
      EVDebug(mod, 1, "failed to get family details - wait before trying again");
      mdata->state = HSP_PSAMPLE_STATE_WAIT;
      mdata->retry_countdown = HSP_PSAMPLE_WAIT_RETRY_S;
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
      break;
    case HSP_PSAMPLE_STATE_WAIT:
      // pausing before trying again
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
