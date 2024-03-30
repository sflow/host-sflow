/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <linux/types.h>
#include <linux/netlink.h>
#include <net/if.h>
#define HSP_READPACKET_BATCH_NFLOG 10000
/* Set this to 65K+ to make sure we handle the
   case where virtual port TSOs coallesce packets
   (ignoring MTU constraints). */
#define HSP_MAX_NFLOG_MSG_BYTES 65536 + 128
#define HSP_NFLOG_RCV_BUF 8000000

#include <linux/netfilter/nfnetlink_log.h>
#include <libnfnetlink.h>

  typedef struct _HSP_mod_NFLOG {
    EVBus *packetBus;
    bool nflog_configured;
    // nflog packet sampling
    struct nfnl_handle *nfnl;
    uint32_t nflog_seqno;
    uint32_t nflog_drops;
    uint32_t subSamplingRate;
    uint32_t actualSamplingRate;
  } HSP_mod_NFLOG;

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static void readPackets_nflog(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_NFLOG *mdata = (HSP_mod_NFLOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    int batch = 0;
    static uint32_t MySkipCount=1;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return;
    }

    if(mdata->subSamplingRate == 0) {
      // packet sampling was disabled by setting desired rate to 0
      return;
    }

    for( ; batch < HSP_READPACKET_BATCH_NFLOG; batch++) {
      u_char buf[HSP_MAX_NFLOG_MSG_BYTES];
      int len = nfnl_recv(mdata->nfnl,
			  buf,
			  HSP_MAX_NFLOG_MSG_BYTES);
      if(len <= 0) break;
      if(EVDebug(mod, 2, NULL)) {
	struct nlmsghdr *msg = (struct nlmsghdr *)buf;
	myLog(LOG_INFO, "got NFLOG msg: bytes_read=%u nlmsg_len=%u nlmsg_type=%u OK=%s",
	      len,
	      msg->nlmsg_len,
	      msg->nlmsg_type,
	      NLMSG_OK(msg, len) ? "true" : "false");
      }
      for(struct nlmsghdr *msg = (struct nlmsghdr *)buf; NLMSG_OK(msg, len); msg=NLMSG_NEXT(msg, len)) {
	if(EVDebug(mod, 2, NULL)) {
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
	if(mdata->nflog_seqno) {
	  droppedSamples = msg->nlmsg_seq - mdata->nflog_seqno - 1;
	  if(droppedSamples) {
	    mdata->nflog_drops += droppedSamples;
	  }
	}
	mdata->nflog_seqno = msg->nlmsg_seq;

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
	    struct nfattr *attr = nfnl_parse_hdr(mdata->nfnl, msg, &genmsg);
	    if(attr == NULL) {
	      continue;
	    }
	    int min_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
	    int attr_len = msg->nlmsg_len - NLMSG_ALIGN(min_len);
	    struct nfattr *tb[NFULA_MAX] = { 0 };

	    while (NFA_OK(attr, attr_len)) {
	      if (NFA_TYPE(attr) <= NFULA_MAX) {
		tb[NFA_TYPE(attr)-1] = attr;
		EVDebug(mod, 3, "found attr %d attr_len=%d\n", NFA_TYPE(attr), attr_len);
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

	    EVDebug(mod, 3, "capture payload (cap_len)=%d\n", cap_len);

	    if(--MySkipCount == 0) {
	      /* reached zero. Set the next skip */
	      uint32_t sr = mdata->subSamplingRate;
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

	      if(EVDebug(mod, 2, NULL)) {
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
			 NULL,
 			 sp->nflog.ds_options,
			 msg_pkt_hdr->hook,
			 mac_hdr,
			 mac_len,
			 cap_hdr,
			 cap_len, /* length of captured payload */
			 cap_len, /* length of packet (pdu) */
			 droppedSamples,
			 mdata->actualSamplingRate,
			 NULL);
	    }
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     openNFLOG             __________________
    -----------------___________________________------------------
  */

  static bool bind_group_nflog(struct nfnl_handle *nfnl, uint32_t group)
  {
    // need a sub-system handle too.  Seems odd that it's still called NFNL_SUBSYS_ULOG,  but this
    // works so I'm not arguing:
    struct nfnl_subsys_handle *subsys = nfnl_subsys_open(nfnl, NFNL_SUBSYS_ULOG, NFULNL_MSG_MAX, 0);
    if(!subsys) {
      myLog(LOG_ERR, "NFLOG nfnl_subsys_open() failed: %s", strerror(errno));
      return NO;
    }
    /* These details were borrowed from libnetfilter_log.c */
    union {
      char buf[NFNL_HEADER_LEN
	       +NFA_LENGTH(sizeof(struct nfulnl_msg_config_cmd))];
      struct nlmsghdr nmh;
    } u;
    struct nfulnl_msg_config_cmd cmd;
    nfnl_fill_hdr(subsys, &u.nmh, 0, 0, group,
		  NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);
    cmd.command =  NFULNL_CFG_CMD_BIND;
    nfnl_addattr_l(&u.nmh, sizeof(u), NFULA_CFG_CMD, &cmd, sizeof(cmd));
    if(nfnl_query(nfnl, &u.nmh) < 0) {
      myLog(LOG_ERR, "NFLOG bind group failed: %s", strerror(errno));
      return NO;
    }
    return YES;
  }

  static int openNFLOG(EVMod *mod)
  {
    HSP_mod_NFLOG *mdata = (HSP_mod_NFLOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    // open the netfilter socket to ULOG
    mdata->nfnl = nfnl_open();
    if(mdata->nfnl == NULL) {
      myLog(LOG_ERR, "nfnl_open() failed: %s\n", strerror(errno));
      return -1;
    }

    /* subscribe to group  */
    if(!bind_group_nflog(mdata->nfnl, sp->nflog.group)) {
      myLog(LOG_ERR, "bind_group_nflog() failed\n");
      return -1;
    }

    // increase receiver buffer size
    nfnl_set_rcv_buffer_size(mdata->nfnl, HSP_NFLOG_RCV_BUF);

    // get the fd
    int fd = nfnl_fd(mdata->nfnl);
    EVDebug(mod, 1, "NFLOG socket fd=%d", fd);

    // set the socket to non-blocking
    int fdFlags = fcntl(fd, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "NFLOG fcntl(O_NONBLOCK) failed: %s", strerror(errno));
      return -1;
    }

    // make sure it doesn't get inherited, e.g. when we fork a script
    fdFlags = fcntl(fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(fd, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "NFLOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
      return -1;
    }

    return fd;
  }

  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

  static void setSamplingRate(EVMod *mod) {
    HSP_mod_NFLOG *mdata = (HSP_mod_NFLOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    uint32_t samplingRate = sp->sFlowSettings->samplingRate;

    // set defaults assuming we will get 1:1 on ULOG or NFLOG and do our own sampling.
    mdata->subSamplingRate = samplingRate;
    mdata->actualSamplingRate = samplingRate;

    if(sp->hardwareSampling) {
      // all sampling is done in the hardware
      mdata->subSamplingRate = 1;
      return;
    }

    // calculate the NFLOG sub-sampling rate to use.  We may get the local NFLOG sampling-rate
    // from the probability setting in the config file and the desired sampling rate from DNS-SD,
    // so that's why we have to reconcile the two here.
    uint32_t nflogsr = sp->nflog.samplingRate;
    if(nflogsr > 1) {
      // use an integer divide to get the sub-sampling rate, but make sure we round up
      mdata->subSamplingRate = (samplingRate + nflogsr - 1) / nflogsr;
      // and pre-calculate the actual sampling rate that we will end up applying
      mdata->actualSamplingRate = mdata->subSamplingRate * nflogsr;
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NFLOG *mdata = (HSP_mod_NFLOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    setSamplingRate(mod);

    if(mdata->nflog_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    if(sp->nflog.group != 0) {
      // NFLOG group is set, so open the netfilter
      // socket to NFLOG while we are still root
      int fd = openNFLOG(mod);
      if(fd > 0)
	EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_nflog, NULL);
    }

    mdata->nflog_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    setSamplingRate(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_nflog(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_NFLOG));
    HSP_mod_NFLOG *mdata = (HSP_mod_NFLOG *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
