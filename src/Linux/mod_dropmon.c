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
#include <linux/net_dropmon.h>
#include <net/if.h>
#include "util_netlink.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef DROPMON_GENL_NAME
  #define DROPMON_GENL_NAME "NET_DM"
#endif

  // these will go away - just to get things to compile:
#define DROPMON_NL_MCGRP_SAMPLE_NAME "mcgrp"

  
#define HSP_DROPMON_READNL_RCV_BUF 8192
#define HSP_DROPMON_READNL_BATCH 100
#define HSP_DROPMON_RCVBUF 8000000

  typedef enum {
    HSP_DROPMON_STATE_INIT=0,
    HSP_DROPMON_STATE_GET_FAMILY,
    HSP_DROPMON_STATE_WAIT,
    HSP_DROPMON_STATE_JOIN_GROUP,
    HSP_DROPMON_STATE_CONFIGURE,
    HSP_DROPMON_STATE_RUN } EnumDropmonState;
  
  typedef struct _HSP_mod_DROPMON {
    EnumDropmonState state;
    EVBus *packetBus;
    bool dropmon_configured;
    int nl_sock;
    uint32_t nl_seq;
    int retry_countdown;
#define HSP_DROPMON_WAIT_RETRY_S 15
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id;
    uint32_t headerSize;
    uint32_t maxAttr;
    uint32_t last_grp_seq;
  } HSP_mod_DROPMON;


  /*_________________---------------------------__________________
    _________________    getFamily_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void getFamily_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    myDebug(1, "dropmon: getFamily");
    mdata->state = HSP_DROPMON_STATE_GET_FAMILY;
    UTNLGeneric_send(mdata->nl_sock,
		     mod->id,
		     GENL_ID_CTRL,
		     CTRL_CMD_GETFAMILY,
		     CTRL_ATTR_FAMILY_NAME,
		     DROPMON_GENL_NAME,
		     sizeof(DROPMON_GENL_NAME)+1,
		     ++mdata->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void joinGroup_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    myDebug(1, "dropmon: joinGroup");
    mdata->state = HSP_DROPMON_STATE_JOIN_GROUP;
    // register for the multicast group_id
    if(setsockopt(mdata->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &mdata->group_id,
		  sizeof(mdata->group_id)) == -1) {
      // TODO: go back to previous state? close socket?
      myLog(LOG_ERR, "error joining DROPMON netlink group %u : %s",
	    mdata->group_id,
	    strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________    start_DROPMON          __________________
    -----------------___________________________------------------
TODO: enhance util_netlink to offer this variant.  If it's common to
set flags in one go then one with a vararg list of attr-types might be reuseable?
So here we would just call something like:
 UTNLGeneric_setFlags(sock, id, type, cmd, seqNo, NET_DM_ATTR_SW_DROPS, NET_DM_ATTR_HW_DROPS)
*/

  int start_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    myDebug(1, "dropmon: start");
    // TODO: possibly add intermediate state:  HSPDROPMON_STATE_START
    mdata->state = HSP_DROPMON_STATE_RUN;
    
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr1 = { };
    struct nlattr attr2 = { };

    attr1.nla_len = sizeof(attr1);
    attr1.nla_type = NET_DM_ATTR_SW_DROPS;
    attr2.nla_len = sizeof(attr1);
    attr2.nla_type = NET_DM_ATTR_HW_DROPS;

    ge.cmd = GENL_ID_CTRL;
    ge.version = 1;

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ge) + sizeof(attr1) + sizeof(attr2));
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = NET_DM_CMD_START;
    nlh.nlmsg_seq = ++mdata->nl_seq;
    nlh.nlmsg_pid = UTNLGeneric_pid(mod->id);

    struct iovec iov[4] = {
      { .iov_base = &nlh,  .iov_len = sizeof(nlh) },
      { .iov_base = &ge,   .iov_len = sizeof(ge) },
      { .iov_base = &attr1, .iov_len = sizeof(attr1) },
      { .iov_base = &attr2, .iov_len = sizeof(attr2) },
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 4 };
    return sendmsg(mdata->nl_sock, &msg, 0);
  }

  /*_________________---------------------------__________________
    _________________    configure_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void configure_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    myDebug(1, "dropmon: configure");
    mdata->state = HSP_DROPMON_STATE_CONFIGURE;
    uint8_t alertMode = NET_DM_ALERT_MODE_PACKET;
    uint32_t truncLen = SFL_DEFAULT_HEADER_SIZE; // TODO: parameter?
    uint32_t queueLen = 100; // TODO: parameter?
    // TODO: go back to previous state on failure? close socket?
    UTNLGeneric_send(mdata->nl_sock,
		     mod->id,
		     mdata->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_TRUNC_LEN,
		     &truncLen,
		     sizeof(truncLen),
		     ++mdata->nl_seq);
    UTNLGeneric_send(mdata->nl_sock,
		     mod->id,
		     mdata->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_QUEUE_LEN,
		     &queueLen,
		     sizeof(queueLen),
		     ++mdata->nl_seq);
    UTNLGeneric_send(mdata->nl_sock,
		     mod->id,
		     mdata->family_id,
		     NET_DM_CMD_CONFIG,
		     NET_DM_ATTR_ALERT_MODE,
		     &alertMode,
		     sizeof(alertMode),
		     ++mdata->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    char *msg = (char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    myDebug(1, "generic netlink CMD = %u", genl->cmd);

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
	myDebug(1, "generic family id: %u", mdata->family_id); 
	break;
      case CTRL_ATTR_FAMILY_NAME:
	myDebug(1, "generic family name: %s", attr_datap); 
	break;
      case CTRL_ATTR_HDRSIZE:
	mdata->headerSize = *(uint32_t *)attr_datap;
	myDebug(1, "generic family headerSize: %u", mdata->headerSize); 
	break;
      case CTRL_ATTR_MAXATTR:
	mdata->maxAttr = *(uint32_t *)attr_datap;
	myDebug(1, "generic family maxAttr: %u", mdata->maxAttr);
	break;
      case CTRL_ATTR_OPS:
	myDebug(1, "generic family OPS");
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
	      myDebug(1, "dropmon multicast group: %s", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      myDebug(1, "dropmon multicast group id: %u", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(mdata->state == HSP_DROPMON_STATE_GET_FAMILY
	     && grp_name
	     && grp_id == NET_DM_GRP_ALERT) {
	    myDebug(1, "dropmon found group %s=%u", grp_name, grp_id);
	    mdata->group_id = grp_id;
	    // TODO: if any of this fails,  should we close the socket and go all the way back to the start of the state machine?
	    joinGroup_DROPMON(mod);
	    configure_DROPMON(mod);
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	myDebug(1, "dropmon attr type: %u (nested=%u) len: %u",
		attr->nla_type,
		attr->nla_type & NLA_F_NESTED,
		attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_DROPMON   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_DROPMON(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    myDebug(1, "dropmon netlink (type=%u) CMD = %u", nlh->nlmsg_type, genl->cmd);
    
    // sFlow strutures to fill in
    SFLDataSource_instance dsi;
    SFLEvent_discarded_packet discard = { };
    SFLFlow_sample_element hdrElem = { .tag=SFLFLOW_HEADER };
    // and some parameters to pick up for cross-check below
    uint32_t trunc_len=0;
    uint32_t orig_len=0;

    struct nlattr *attr = (struct nlattr *)(msg + GENL_HDRLEN);
    int len = msglen - GENL_HDRLEN;
    while(UTNLA_OK(attr, len)) {
      u_char *datap = UTNLA_DATA(attr);
      int datalen = UTNLA_PAYLOAD(attr);
      
      u_char hex[1024];
      printHex(datap, datalen, hex, 1023, YES);
      myDebug(1, "nla_type=%u, datalen=%u, payload=%s", attr->nla_type, datalen, hex);

      bool nested = attr->nla_type & NLA_F_NESTED;
      int attributeType = attr->nla_type & ~NLA_F_NESTED;
      switch(attributeType) {
      case NET_DM_ATTR_ALERT_MODE:
	myDebug(3, "dropmon: u8=ALERT_MODE=%u", *(uint8_t *)datap);
	// enum net_dm_alert_mode NET_DM_ALERT_MODE_PACKET == 1
	// TODO: bail if not packet?
	break;
      case NET_DM_ATTR_PC:
	myDebug(3, "dropmon: u64=PC=0x%"PRIx64, *(uint64_t *)datap);
	break;
      case NET_DM_ATTR_SYMBOL:
	myDebug(3, "dropmon: string=ATTR_SYMBOL=%s", datap);
	// TODO: parse or lookup this symbol to get the reason code?
	break;
      case NET_DM_ATTR_IN_PORT:
	myDebug(3, "dropmon: nested=IN_PORT");
	if(nested) {
	  struct nlattr *port_attr = (struct nlattr *)datap;
	  int port_len = datalen;
	  while(UTNLA_OK(port_attr, port_len)) {
	    switch(port_attr->nla_type) {
	    case NET_DM_ATTR_PORT_NETDEV_IFINDEX:
	      myDebug(3, "dropmon: u32=NETDEV_IFINDEX=%u", *(uint32_t *)UTNLA_DATA(port_attr));
	      discard.input = *(uint32_t *)UTNLA_DATA(port_attr);
	      break;
	    case NET_DM_ATTR_PORT_NETDEV_NAME:
	      myDebug(3, "dropmon: string=NETDEV_NAME=%s", (char *)UTNLA_DATA(port_attr));
	      break;
	    }
	    port_attr = UTNLA_NEXT(port_attr, port_len);
	  }
	}
	break;
      case NET_DM_ATTR_TIMESTAMP:
	myDebug(3, "dropmon: u64=TIMESTAMP=%"PRIu64, *(uint64_t *)datap);
	break;
      case NET_DM_ATTR_PROTO:
	myDebug(3, "dropmon: u16=PROTO=0x%04x", *(uint16_t *)datap);
	// TODO: do we need to interpret protocol = 0x0800 as IPv4 and 0x86DD as IPv6?
	// do we get MAC layer here at all?
	break;
      case NET_DM_ATTR_PAYLOAD:
	myDebug(3, "dropmon: PAYLOAD");
	hdrElem.flowType.header.header_length = datalen;
	hdrElem.flowType.header.header_bytes = datap;
	break;
      case NET_DM_ATTR_PAD:
	myDebug(3, "dropmon: PAD");
	break;
      case NET_DM_ATTR_TRUNC_LEN:
	myDebug(3, "dropmon: u32=TRUNC_LEN=%u", *(uint32_t *)datap);
	trunc_len = *(uint32_t *)datap;
	break;
      case NET_DM_ATTR_ORIG_LEN:
	myDebug(3, "dropmon: u32=ORIG_LEN=%u", *(uint32_t *)datap);
	orig_len = *(uint32_t *)datap;
	break;
      case NET_DM_ATTR_QUEUE_LEN:
	myDebug(3, "dropmon: u32=QUEUE_LEN=%u", *(uint32_t *)datap);
	break;
      case NET_DM_ATTR_STATS:
	myDebug(3, "dropmon: nested=ATTR_STATS");
	break;
      case NET_DM_ATTR_HW_STATS:
	myDebug(3, "dropmon: nested=HW_STATS");
	break;
      case NET_DM_ATTR_ORIGIN:
	myDebug(3, "dropmon: u16=ORIGIN=%u", *(uint16_t *)datap);
	break;
      case NET_DM_ATTR_HW_TRAP_GROUP_NAME:
	myDebug(3, "dropmon: string=TRAP_GROUP_NAME=%s", datap);
	break;
      case NET_DM_ATTR_HW_TRAP_NAME:
	myDebug(3, "dropmon: string=TRAP_NAME=%s", datap);
	break;
      case NET_DM_ATTR_HW_ENTRIES:
	myDebug(3, "dropmon: nested=HW_ENTRIES");
	break;
      case NET_DM_ATTR_HW_ENTRY:
	myDebug(3, "dropmon: nested=HW_ENTRY");
	break;
      case NET_DM_ATTR_HW_TRAP_COUNT:
	myDebug(3, "dropmon: u32=SW_DROPS=%u", *(uint32_t *)datap);
	break;
      case NET_DM_ATTR_SW_DROPS:
	myDebug(3, "dropmon: flag=SW_DROPS");
	break;
      case NET_DM_ATTR_HW_DROPS:
	myDebug(3, "dropmon: flag=HW_DROPS");
	break;
      }
      attr = UTNLA_NEXT(attr, len);
    }
    
    // cross check: make sure frame_length is not missing
    if(hdrElem.flowType.header.frame_length == 0)
      hdrElem.flowType.header.frame_length = hdrElem.flowType.header.header_length;
    
    // cross check: trunc_len
    if(trunc_len
       && trunc_len < hdrElem.flowType.header.header_length)
      hdrElem.flowType.header.header_length = trunc_len;

    // cross check: orig_len
    if(orig_len
       && orig_len > hdrElem.flowType.header.frame_length)
      hdrElem.flowType.header.frame_length = orig_len;

    // TODO: apply notifier->sFlowEsMaximumHeaderSize

    // cross check: protocol
    if(!hdrElem.flowType.header.header_protocol)
      hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
    
    // TODO: add hash table to look up notifiers by ifIndex?
    SFL_DS_SET(dsi, 0, discard.input, 0);
    SFLNotifier *notifier = sfl_agent_addNotifier(sp->agent, &dsi);
    sfl_notifier_set_sFlowEsReceiver(notifier, HSP_SFLOW_RECEIVER_INDEX);
    SFLADD_ELEMENT(&discard, &hdrElem);
    sfl_notifier_writeEventSample(notifier, &discard);

    if(mdata->state == HSP_DROPMON_STATE_CONFIGURE)
      mdata->state = HSP_DROPMON_STATE_RUN;
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(mod, nlh);
    }
    else if(nlh->nlmsg_type == mdata->family_id) {
      processNetlink_DROPMON(mod, nlh);
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_DROPMON     __________________
    -----------------___________________________------------------
  */

  static void readNetlink_DROPMON(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    uint8_t recv_buf[HSP_DROPMON_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < HSP_DROPMON_READNL_BATCH; batch++) {
      int numbytes = recv(sock->fd, recv_buf, sizeof(recv_buf), 0);
      if(numbytes <= 0)
	break;
      struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
      while(NLMSG_OK(nlh, numbytes)){
	if(nlh->nlmsg_type == NLMSG_DONE)
	  break;
	if(nlh->nlmsg_type == NLMSG_ERROR){
	  struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	  if(err_msg->error == 0) {
	    myDebug(1, "received Netlink ACK");
	  }
	  else {
	    // TODO: parse NLMSGERR_ATTR_OFFS to get offset?  Might be helpful
	    myDebug(1, "dropmon state %u: error in netlink message: %d : %s",
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

    // This should have advanced the state past GET_FAMILY
    if(mdata->state == HSP_DROPMON_STATE_GET_FAMILY) {
      myDebug(1, "dropmon: failed to get family details - wait before trying again");
      mdata->state = HSP_DROPMON_STATE_WAIT;
      mdata->retry_countdown = HSP_DROPMON_WAIT_RETRY_S;
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
  
    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)
  
    if(mdata->dropmon_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    if(sp->dropmon.group != 0) {
      // DROPMON group is set, so open the netfilter socket while we are still root
      mdata->nl_sock = UTNLGeneric_open(mod->id);
      if(mdata->nl_sock > 0) {
	// increase socket receiver buffer size
	UTSocketRcvbuf(mdata->nl_sock, HSP_DROPMON_RCVBUF);
	// and submit for polling
	EVBusAddSocket(mod,
		       mdata->packetBus,
		       mdata->nl_sock,
		       readNetlink_DROPMON,
		       NULL);
	// kick off with the family lookup request
	getFamily_DROPMON(mod);
      }
    }

    mdata->dropmon_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    
    switch(mdata->state) {
    case HSP_DROPMON_STATE_INIT:
      // waiting for evt_config_changed
      break;
    case HSP_DROPMON_STATE_GET_FAMILY:
      // waiting for family info response
      break;
    case HSP_DROPMON_STATE_WAIT:
      // pausing before trying again
      if(--mdata->retry_countdown <= 0)
	getFamily_DROPMON(mod);
      break;
    case HSP_DROPMON_STATE_JOIN_GROUP:
      // joined group, waiting for first matching sample
      break;
    case HSP_DROPMON_STATE_CONFIGURE:
      // waiting for configure response
      start_DROPMON(mod);
      break;
    case HSP_DROPMON_STATE_RUN:
      // got at least one sample
      break;
    }
  }
  
  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------

TODO: should we use a separate thread (bus) for this so that it
can be a little more indenpendent of the packet sampling?
  */

  void mod_dropmon(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_DROPMON));
    // HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_TICK), evt_tick);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
