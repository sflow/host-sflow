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

#define HSP_READPACKET_BATCH_ULOG 10000
#define HSP_DEFAULT_ULOG_GROUP 1
#include <linux/netfilter_ipv4/ipt_ULOG.h>
#define HSP_MAX_ULOG_MSG_BYTES 10000
#define HSP_ULOG_RCV_BUF 8000000

  typedef struct _HSP_mod_ULOG {
    EVBus *packetBus;
    bool ulog_configured;
    int ulog_soc;
    uint32_t ulog_seqno;
    uint32_t ulog_drops;
    struct sockaddr_nl ulog_bind;
    uint32_t subSamplingRate;
    uint32_t actualSamplingRate;
  } HSP_mod_ULOG;

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  int readPackets_ulog(EVMod *mod, EVBus *bus, int fd, void *data)
  {
    HSP_mod_ULOG *mdata = (HSP_mod_ULOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    int batch = 0;
    static uint32_t MySkipCount=1;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return 0;
    }

    if(mdata->subSamplingRate == 0) {
      // packet sampling was disabled by setting desired rate to 0
      return 0;
    }

    for( ; batch < HSP_READPACKET_BATCH_ULOG; batch++) {
      char buf[HSP_MAX_ULOG_MSG_BYTES];
      int len = recvfrom(mdata->ulog_soc, buf, HSP_MAX_ULOG_MSG_BYTES, 0, NULL, NULL);
      if(len <= 0) break;
      myDebug(1, "got ULOG msg: %u bytes", len);
      for(struct nlmsghdr *msg = (struct nlmsghdr *)buf; NLMSG_OK(msg, len); msg=NLMSG_NEXT(msg, len)) {
	
	myDebug(1, "netlink (%u bytes left) msg [len=%u type=%u flags=0x%x seq=%u pid=%u]",
		len,
		msg->nlmsg_len,
		msg->nlmsg_type,
		msg->nlmsg_flags,
		msg->nlmsg_seq,
		msg->nlmsg_pid);
	
	// check for drops indicated by sequence no
	uint32_t droppedSamples = 0;
	if(mdata->ulog_seqno) {
	  droppedSamples = msg->nlmsg_seq - mdata->ulog_seqno - 1;
	  if(droppedSamples) {
	    mdata->ulog_drops += droppedSamples;
	  }
	}
	mdata->ulog_seqno = msg->nlmsg_seq;
	
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
	      uint32_t sr = mdata->subSamplingRate;
	      MySkipCount = sr == 1 ? 1 : sfl_random((2 * sr) - 1);
	      
	      /* and take a sample */
	      
	      // we're seeing type==111 on Fedora14
	      //if(msg->nlmsg_flags & NLM_F_REQUEST) { }
	      //if(msg->nlmsg_flags & NLM_F_MULTI) { }
	      //if(msg->nlmsg_flags & NLM_F_ACK) { }
	      //if(msg->nlmsg_flags & NLM_F_ECHO) { }
	      ulog_packet_msg_t *pkt = NLMSG_DATA(msg);
	      
	      myDebug(LOG_INFO, "ULOG mark=%u ts=%s prefix=%s",
		      pkt->mark,
		      ctime(&pkt->timestamp_sec),
		      pkt->prefix);
	      
	      
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
			 NULL,
			 NO,
			 pkt->hook,
			 pkt->mac,
			 pkt->mac_len,
			 pkt->payload,
			 pkt->data_len, /* length of captured payload */
			 pkt->data_len, /* length of packet (pdu) */
			 droppedSamples,
			 mdata->actualSamplingRate);
	    }
	  }
	}
      }
    }
    return batch;
  }


  /*_________________---------------------------__________________
    _________________     openULOG              __________________
    -----------------___________________________------------------
  */

  static int openULOG(EVMod *mod)
  {
    HSP_mod_ULOG *mdata = (HSP_mod_ULOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // open the netfilter socket to ULOG
    mdata->ulog_soc = socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
    myDebug(1, "ULOG socket fd=%d", mdata->ulog_soc);
    if(mdata->ulog_soc < 0) {
      myLog(LOG_ERR, "openULOG() failed: %s\n", strerror(errno));
      return -1;
    }
    // set the socket to non-blocking
    int fdFlags = fcntl(mdata->ulog_soc, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(mdata->ulog_soc, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "ULOG fcntl(O_NONBLOCK) failed: %s", strerror(errno));
      return -1;
    }
      
    // make sure it doesn't get inherited, e.g. when we fork a script
    fdFlags = fcntl(mdata->ulog_soc, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(mdata->ulog_soc, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "ULOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
      return -1;
    }
      
    // bind
    mdata->ulog_bind.nl_family = AF_NETLINK;
    mdata->ulog_bind.nl_pid = getpid();
    // Note that the ulogGroup setting is only ever retrieved from the config file (i.e. not settable by DNSSD)
    mdata->ulog_bind.nl_groups = 1 << (sp->ulog.group - 1); // e.g. 16 => group 5
    if(bind(mdata->ulog_soc, (struct sockaddr *)&mdata->ulog_bind, sizeof(mdata->ulog_bind)) == -1) {
      myLog(LOG_ERR, "ULOG bind() failed: %s", strerror(errno));
      return -1;
    }
    
    // increase receiver buffer size
    uint32_t rcvbuf = HSP_ULOG_RCV_BUF;
    if(setsockopt(mdata->ulog_soc, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
      myLog(LOG_ERR, "setsockopt(SO_RCVBUF=%d) failed: %s", HSP_ULOG_RCV_BUF, strerror(errno));
      // not a show-stopper
    }
    return mdata->ulog_soc;
  }

  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

  static void setSamplingRate(EVMod *mod) {
    HSP_mod_ULOG *mdata = (HSP_mod_ULOG *)mod->data;
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

    // calculate the ULOG sub-sampling rate to use.  We may get the local ULOG sampling-rate
    // from the probability setting in the config file and the desired sampling rate from DNS-SD,
    // so that's why we have to reconcile the two here.
    uint32_t ulogsr = sp->ulog.samplingRate;
    if(ulogsr > 1) {
      // use an integer divide to get the sub-sampling rate, but make sure we round up
      mdata->subSamplingRate = (samplingRate + ulogsr - 1) / ulogsr;
      // and pre-calculate the actual sampling rate that we will end up applying
      mdata->actualSamplingRate = mdata->subSamplingRate * ulogsr;
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_ULOG *mdata = (HSP_mod_ULOG *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    setSamplingRate(mod);

    if(mdata->ulog_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    if(sp->ulog.group != 0) {
      // ULOG group is set, so open the netfilter socket to ULOG
      int fd = openULOG(mod);
      if(fd > 0)
	EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_ulog, mod);
    }
    
    mdata->ulog_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_intf_changed       __________________
    -----------------___________________________------------------
  */

  static void evt_intf_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    setSamplingRate(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_ulog(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_ULOG));
    HSP_mod_ULOG *mdata = (HSP_mod_ULOG *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTF_CHANGED), evt_intf_changed);
  }

  
#if defined(__cplusplus)
} /* extern "C" */
#endif

