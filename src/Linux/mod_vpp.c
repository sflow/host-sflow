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
#include <net/if.h>

#include "util_netlink.h"

#define HSP_VPP_READNL_RCV_BUF 16384
#define HSP_VPP_READNL_BATCH 10

  // ==================== shared with vpp-sflow plugin =========================
  // See https://github.com/sflow/vpp-sflow

#define SFLOW_VPP_NETLINK_USERSOCK_MULTICAST 29

  typedef enum {
    SFLOW_VPP_MSG_STATUS=1,
    SFLOW_VPP_MSG_IF_COUNTERS
  } EnumSFlowVppMsgType;

  typedef enum {
    SFLOW_VPP_ATTR_PORTNAME,      /* string */
    SFLOW_VPP_ATTR_IFINDEX,       /* u32 */
    SFLOW_VPP_ATTR_IFTYPE,        /* u32 */
    SFLOW_VPP_ATTR_IFSPEED,       /* u64 */
    SFLOW_VPP_ATTR_IFDIRECTION,   /* u32 */
    SFLOW_VPP_ATTR_OPER_UP,       /* u32 */
    SFLOW_VPP_ATTR_ADMIN_UP,      /* u32 */
    SFLOW_VPP_ATTR_RX_OCTETS,     /* u64 */
    SFLOW_VPP_ATTR_TX_OCTETS,     /* u64 */
    SFLOW_VPP_ATTR_RX_PKTS,       /* u64 */
    SFLOW_VPP_ATTR_TX_PKTS,       /* u64 */
    SFLOW_VPP_ATTR_RX_BCASTS,     /* u64 */
    SFLOW_VPP_ATTR_TX_BCASTS,     /* u64 */
    SFLOW_VPP_ATTR_RX_MCASTS,     /* u64 */
    SFLOW_VPP_ATTR_TX_MCASTS,     /* u64 */
    SFLOW_VPP_ATTR_RX_DISCARDS,   /* u64 */
    SFLOW_VPP_ATTR_TX_DISCARDS,   /* u64 */
    SFLOW_VPP_ATTR_RX_ERRORS,     /* u64 */
    SFLOW_VPP_ATTR_TX_ERRORS,     /* u64 */
    SFLOW_VPP_ATTR_HW_ADDRESS,    /* binary */
    SFLOW_VPP_ATTR_UPTIME_S,      /* u32 */
    SFLOW_VPP_ATTR_OSINDEX,       /* u32 Linux ifIndex number, where applicable */
    SFLOW_VPP_ATTR_DROPS,         /* u32 all FIFO and netlink sendmsg drops */
    SFLOW_VPP_ATTR_SEQ,           /* u32 send seq no */
    /* enum shared with vpp-sflow, so only add here */
    __SFLOW_VPP_ATTR_MAX
  } EnumSFlowVppAttributes;

#define SFLOW_VPP_PSAMPLE_GROUP_INGRESS 3
#define SFLOW_VPP_PSAMPLE_GROUP_EGRESS 4
  
  // =========================================================================

  typedef struct _HSPVppPort {
    uint32_t vpp_index;
    uint32_t os_index;
    char *portName;
    uint32_t ifType;
    uint32_t ifDirection;
    bool operUp:1;
    bool adminUp:1;
    bool osIndexAttr:1;
    bool active:1;
    uint32_t samplingN;
    uint64_t ifSpeed;
    SFLHost_nio_counters ctrs;
    HSP_ethtool_counters et_ctrs;
    u_char mac[6];
  } HSPVppPort;
  
  typedef struct _HSP_mod_VPP {
    EVBus *packetBus;
    EVBus *pollBus;
    bool vpp_configured;
    int nl_sock;
    uint32_t group_id;
    UTHash *ports;
    uint32_t vpp_uptime_S;
    uint32_t vpp_drops;
    uint32_t last_grp_seq[2];
  } HSP_mod_VPP;

  /*_________________---------------------------__________________
    _________________     HSPVppPort            __________________
    -----------------___________________________------------------
  */

  static HSPVppPort *getPort(EVMod *mod, uint32_t vpp_index, int create) {
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    HSPVppPort search = { .vpp_index=vpp_index };
    HSPVppPort *port = UTHashGet(mdata->ports, &search);
    if(port == NULL
       && create) {
      port = (HSPVppPort *)my_calloc(sizeof(HSPVppPort));
      port->vpp_index = vpp_index;
      UTHashAdd(mdata->ports, port);
    }
    return port;
  }

  static HSPVppPort *getPortByOsIndex(EVMod *mod, uint32_t os_index) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPVppPort *port = NULL;
    if(os_index >= sp->vpp.ifOffset) {
      uint32_t vpp_index = os_index- sp->vpp.ifOffset;
      HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
      HSPVppPort search = { .vpp_index=vpp_index };
      port = UTHashGet(mdata->ports, &search);
    }
    return port;
  }

  /*_________________---------------------------__________________
    _________________    portSetOsIndex         __________________
    -----------------___________________________------------------
  */
  
  static uint32_t portSetOsIndex(EVMod *mod, HSPVppPort *port, bool osIndexAttr, uint32_t os_index) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // accept os_index if set, otherwise make up an ifIndex using an offset to reduce the
    // probability of a clash between vpp and Linux. The offset can be adjusted as a config parameter (ifOffset).
    // Another option made possible here is to turn off the translation from vpp ifIndex to Linux ifIndex
    // altogether with "vpp { osIndex=OFF }", but that will still add the offset to try and avoid any clash
    // with Linux ifIndex numbers, and then subtract it again just before the samples go out (see below).
    if(os_index
       && sp->vpp.osIndex)
      port->os_index = os_index;
    else
      port->os_index = sp->vpp.ifOffset + port->vpp_index;
    // remember that we heard this from vpp
    port->osIndexAttr = osIndexAttr;
    // and decide if it's OK to let packet-samples through (this
    // avoids a race where a VPP restart will result in some packet
    // samples coming through before the mapping to os_index has
    // been learned and communicated).
    port->active = (sp->vpp.ifOffset == 0
		    || sp->vpp.osIndex == NO
		    || port->osIndexAttr);
    EVDebug(mod, 1, "portSetOsIndex %s vpp_index=%u attr=%s offset=%u so os_index %u => %u active=%s",
	    port->portName,
	    port->vpp_index,
	    osIndexAttr ? "YES" : "NO",
	    sp->vpp.ifOffset,
	    os_index,
	    port->os_index,
	    port->active ? "YES" : "NO");
    return port->os_index;
  }

  /*_________________---------------------------__________________
    _________________      portGetAdaptor       __________________
    -----------------___________________________------------------
  */
  
  static SFLAdaptor *portGetAdaptor(EVMod *mod, HSPVppPort *port, bool create) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *ad = adaptorByIndex(sp, port->os_index);
    if(ad == NULL
       && create) {
      EVDebug(mod, 1, "portGetAdaptor %s adding new adaptor for os_index == %u",
	      port->portName,
	      port->os_index);
      ad = nioAdaptorNew(mod, port->portName, port->mac, port->os_index);
      adaptorAddOrReplace(sp->adaptorsByIndex, ad, "byIndex");
      adaptorAddOrReplace(sp->adaptorsByMac, ad, "byMac");
      // I don't think we should put these into adaptorsByName or adaptorsByPeerIndex, right?
    }
    return ad;
  }

  /*_________________---------------------------__________________
    _________________    joinGroup_VPP          __________________
    -----------------___________________________------------------
  */

  static void joinGroup_VPP(EVMod *mod)
  {
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    EVDebug(mod, 1, "joinGroup");
    // register for the multicast group_id
    if(setsockopt(mdata->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &mdata->group_id,
		  sizeof(mdata->group_id)) == -1) {
      myLog(LOG_ERR, "error joining VPP netlink group %u : %s",
	    mdata->group_id,
	    strerror(errno));
    }
  }

  /*_________________-------------------__________________
    _________________    getAttrInt     __________________
    -----------------___________________------------------
  */

  // Be flexible about integer sizes in case we change our minds about them at the sender.
  static uint64_t getAttrInt(u_char *datap, int len) {
    switch(len) {
    case 1:
      return *datap;
      break;
    case 2:
      return *(uint16_t *)datap;
      break;
    case 4:
      return *(uint32_t *)datap;
    case 8:
      return *(uint64_t *)datap;
    }
    return 0;
  }
      

  /*_________________---------------------------__________________
    _________________ processNetlink_VPP_STATUS __________________
    -----------------___________________________------------------
  */

  static void processNetlink_VPP_STATUS(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    if(msglen < NLA_HDRLEN)
      return;
    
    for(int offset = 0; offset < msglen; ) {
      struct nlattr *attr = (struct nlattr *)(msg + offset);
      if(attr->nla_len == 0 ||
	 (attr->nla_len + offset) > msglen) {
	myLog(LOG_ERR, "processNetlink_VPP_IF_STATUS attr parse error");
	break;
      }
      
      u_char *datap = UTNLA_DATA(attr);
      int datalen = UTNLA_PAYLOAD(attr);

      switch(attr->nla_type) {
      case SFLOW_VPP_ATTR_UPTIME_S:
	mdata->vpp_uptime_S = getAttrInt(datap, datalen);
	EVDebug(mod, 1, "VPP uptime=%u", mdata->vpp_uptime_S);
	break;
      case SFLOW_VPP_ATTR_DROPS:
	mdata->vpp_drops = getAttrInt(datap, datalen);
	EVDebug(mod, 1, "VPP drops=%u", mdata->vpp_drops);
	break;
      case SFLOW_VPP_ATTR_SEQ:
	EVDebug(mod, 1, "VPP seq=%"PRIu64, getAttrInt(datap, datalen));
	break;
      default:
	EVDebug(mod, 1, "unknowattr %d\n", attr->nla_type);
	break;
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }

  /*_________________--------------------------------__________________
    _________________ processNetlink_VPP_IF_COUNTERS __________________
    -----------------________________________________------------------
  */
    
    static void processNetlink_VPP_IF_COUNTERS(EVMod *mod, struct nlmsghdr *nlh)
  {
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    u_char *msg = (u_char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    if(msglen < NLA_HDRLEN)
      return;

    HSPVppPort in = {};
    char portName[SFL_MAX_PORTNAME_LEN+1];
    bool os_index_attr_included = NO;
 
    for(int offset = 0; offset < msglen; ) {
      struct nlattr *attr = (struct nlattr *)(msg + offset);
      if(attr->nla_len == 0 ||
	 (attr->nla_len + offset) > msglen) {
	myLog(LOG_ERR, "processNetlink_VPP_IF_COUNTERS attr parse error");
	break;
      }
      
      u_char *datap = UTNLA_DATA(attr);
      int datalen = UTNLA_PAYLOAD(attr);

      switch(attr->nla_type) {
      case SFLOW_VPP_ATTR_PORTNAME:
	{
	  uint32_t len = (datalen > SFL_MAX_PORTNAME_LEN) ? SFL_MAX_PORTNAME_LEN : datalen;
	  memcpy(portName, datap, len);
	  portName[len] = '\0';
	  EVDebug(mod, 0, "PORTNAME=%s (datalen=%u)", portName, datalen);
	  in.portName = portName;
	}
	break;
      case SFLOW_VPP_ATTR_IFINDEX:
	in.vpp_index = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_OSINDEX:
	os_index_attr_included = YES;
	in.os_index = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_IFTYPE:
	in.ifType = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_IFSPEED:
	in.ifSpeed = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_IFDIRECTION:
	in.ifDirection = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_OPER_UP:
	in.operUp = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_ADMIN_UP:
	in.adminUp = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_RX_OCTETS:
	in.ctrs.bytes_in = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_TX_OCTETS:
	in.ctrs.bytes_out = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_RX_PKTS:
	in.ctrs.pkts_in = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_TX_PKTS:
	in.ctrs.pkts_out = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_RX_BCASTS:
	in.et_ctrs.bcasts_in = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_TX_BCASTS:
	in.et_ctrs.bcasts_out = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_RX_MCASTS:
	in.et_ctrs.mcasts_in = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_TX_MCASTS:
	in.et_ctrs.mcasts_out = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_RX_DISCARDS:
	in.ctrs.drops_in = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_TX_DISCARDS:
	in.ctrs.drops_out = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_RX_ERRORS:
	in.ctrs.errs_in = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_TX_ERRORS:
	in.ctrs.errs_out = getAttrInt(datap, datalen);
	break;
      case SFLOW_VPP_ATTR_HW_ADDRESS:
	if(datalen == 6)
	  memcpy(in.mac, datap, 6);
	break;
      case SFLOW_VPP_ATTR_SEQ:
	EVDebug(mod, 1, "VPP seq=%"PRIu64, getAttrInt(datap, datalen));
	break;
      default:
	EVDebug(mod, 1, "unknown attr %d\n", attr->nla_type);
	break;
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
    if(in.vpp_index
       && in.portName) {
      // port struct seems complete - so update stored state.
      bool newPort = NO;
      HSPVppPort *port = getPort(mod, in.vpp_index, NO);
      if(port == NULL) {
	newPort = YES;
	port = getPort(mod, in.vpp_index, YES);
      }
      setStr(&port->portName, in.portName);
      portSetOsIndex(mod, port, os_index_attr_included, in.os_index);
      port->operUp = in.operUp;
      port->adminUp = in.adminUp;
      port->ifType = in.ifType;
      port->ifDirection = in.ifDirection;
      port->ifSpeed = in.ifSpeed;
      port->ctrs = in.ctrs;
      port->et_ctrs = in.et_ctrs;
      memcpy(port->mac, in.mac, 6);

      SFLAdaptor *adaptor = portGetAdaptor(mod, port, YES);
      if(adaptor) {
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	if(nio) {
	  // nake sure hsflowd does not poll counters for this interface
	  // if it appears in /proc/net/dev.  Those counters will be wrong
	  // if VPP is using the port.
	  nio->procNetDev = NO;

	  nio->et_found = HSP_ETCTR_MC_IN
	    | HSP_ETCTR_MC_OUT
	    | HSP_ETCTR_BC_IN
	    | HSP_ETCTR_BC_OUT
	    | HSP_ETCTR_UNKN
	    | HSP_ETCTR_OPER
	    | HSP_ETCTR_ADMIN;
	  accumulateNioCounters(sp, adaptor, &port->ctrs, &port->et_ctrs);
	  nio->et_last.adminStatus = port->adminUp;
	  nio->et_last.operStatus = port->operUp;
	  nio->last_update = mdata->pollBus->now.tv_sec;
	  adaptor->ifDirection = port->ifDirection;
	  // Request a poller for this adaptor if one is not already there.
	  // This is done with an event because it is usually called from
	  // the packetBus, but here we are already on the pollBus so it will
	  // take effect immediately:
	  EVEvent *req_poller = EVGetEvent(mdata->pollBus, HSPEVENT_REQUEST_POLLER);
	  EVEventTx(sp->rootModule, req_poller, &adaptor->ifIndex, sizeof(adaptor->ifIndex));
	  // Which means we should have a poller now.
	  if(nio->poller) {
	    // Make sure it does not call back on it's own schedule.
	    nio->poller->getCountersFn = NULL;
	    if(newPort) {
	      // reset the seqNo in case hsflowd had already found and sent
	      // counters samples for this port (e.g. if found in Linux).
	      sfl_poller_resetCountersSeqNo(nio->poller);
	    }
	    SFL_COUNTERS_SAMPLE_TYPE cs = {};
	    sendInterfaceCounterSample(mod, nio->poller, adaptor, &cs);
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    processNetlink         __________________
    -----------------___________________________------------------
  */

  static void processNetlink(EVMod *mod, struct nlmsghdr *nlh)
  {
    // HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    switch(nlh->nlmsg_type) {
    case SFLOW_VPP_MSG_STATUS:
      processNetlink_VPP_STATUS(mod, nlh);
      break;
    case SFLOW_VPP_MSG_IF_COUNTERS:
      processNetlink_VPP_IF_COUNTERS(mod, nlh);
      break;
    default:
      EVDebug(mod, 0, "unknown netlink msgType: %u", nlh->nlmsg_type);
      break;
    }
  }

  /*_________________---------------------------__________________
    _________________     readNetlink_VPP       __________________
    -----------------___________________________------------------
v  */

  static void readNetlink_VPP(EVMod *mod, EVSocket *sock, void *magic)
  {
    uint8_t recv_buf[HSP_VPP_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < HSP_VPP_READNL_BATCH; batch++) {
      int numbytes = recv(sock->fd, recv_buf, sizeof(recv_buf), 0);
      if(numbytes <= 0) {
	if(errno != EAGAIN) {
	  myLog(LOG_ERR, "recv() failed, %d => %s\n", numbytes, strerror(errno));
	}
	return;
      }
      
      struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
      while(NLMSG_OK(nlh, numbytes)){
	processNetlink(mod, nlh);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
  
    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)
  
    if(mdata->vpp_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }
    
    if(mdata->group_id != 0) {
      // Open the netfilter socket while we are still root
      mdata->nl_sock = UTNLUsersock_open(getpid());
      if(mdata->nl_sock > 0) {
	// join multicast group
	joinGroup_VPP(mod);
	// and submit for polling
	EVBusAddSocket(mod,
		       mdata->pollBus,
		       mdata->nl_sock,
		       readNetlink_VPP,
		       NULL);
      }
    }
    mdata->vpp_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    // TODO: send vpp commands to set up sFlow?
    // TODO: notice if interfaces gone away?
    // TODO: configure switchports?
  }

  /*_________________---------------------------__________________
    _________________       evt_psample         __________________
    -----------------___________________________------------------
  */

  static void evt_psample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPPSample *psmp = (HSPPSample *)data;
    if(psmp->grp_no == SFLOW_VPP_PSAMPLE_GROUP_INGRESS
       || psmp->grp_no == SFLOW_VPP_PSAMPLE_GROUP_EGRESS) {
      EVDebug(mod, 3, "Got VPP PSample");
      bool egress = (psmp->grp_no == SFLOW_VPP_PSAMPLE_GROUP_EGRESS);
      HSPVppPort *rx_prt, *tx_prt;
      SFLAdaptor *rx_dev, *tx_dev, *sampler_dev;
      bool active = NO;
      if(egress) {
	rx_prt = getPort(mod, psmp->ifin, NO);
  	rx_dev = rx_prt ? portGetAdaptor(mod, rx_prt, NO) : NULL;
	tx_prt = getPort(mod, psmp->ifout, YES);
	active = tx_prt->active;
	tx_dev = portGetAdaptor(mod, tx_prt, YES);
	sampler_dev = tx_dev;
      }
      else {
	tx_prt = getPort(mod, psmp->ifout, NO);
	tx_dev = tx_prt ? portGetAdaptor(mod, tx_prt, NO) : NULL;
	rx_prt = getPort(mod, psmp->ifin, YES);
	active = rx_prt->active;
	rx_dev = portGetAdaptor(mod, rx_prt, YES);
	sampler_dev = rx_dev;
      }
      if(sampler_dev) {
	uint32_t drops = 0;
	if(mdata->last_grp_seq[egress]) {
	  drops = psmp->grp_seq - mdata->last_grp_seq[egress] - 1;
	  if(drops > 0x7FFFFFFF)
	    drops = 1;
	}
	mdata->last_grp_seq[egress] = psmp->grp_seq;

	if(active)
	  takeSample(sp,
		     rx_dev,
		     tx_dev,
		     sampler_dev,
		     sp->psample.ds_options,
		     0, // hook
		     psmp->hdr, // mac hdr
		     14, // mac hdr len
		     psmp->hdr + 14, // payload
		     psmp->hdr_len - 14, // captured payload len
		     psmp->pkt_len - 14, // whole pdu len
		     drops + mdata->vpp_drops,
		     psmp->sample_n,
		     NULL);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_flow_sample     __________________
    -----------------___________________________------------------
   packet bus
  */

  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSPPendingSample *ps = (HSPPendingSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the VPP ifIndex namespace. For packet samples that means:
    // 1. sampler ds_index
    // 2. flow_sample input, output ports
    // If a mapping is missing for the sampler we have to block the sample.
    // If a mapping is missing for in/out ports we have to zero it out (0 == unknown)
    uint32_t osIndex = SFL_DS_INDEX(ps->sampler->dsi);
    HSPVppPort *vppPort = getPortByOsIndex(mod, osIndex);
    if(vppPort == NULL) {
      EVDebug(mod, 2, "suppress packet sample from non-vpp port (osIndex=%u)", osIndex);
      ps->suppress = YES;
    }
    else {
      // fix datasource
      sfl_sampler_set_dsAlias(ps->sampler, vppPort->vpp_index);
      // fix in/out
      if(ps->fs->input
	 && ps->fs->input != SFL_INTERNAL_INTERFACE) {
	// translate, or mark unknown
	HSPVppPort *in = getPortByOsIndex(mod, ps->fs->input);
	ps->fs->input = in ? in->vpp_index : 0;
      }
      if(ps->fs->output
	 && ps->fs->output != SFL_INTERNAL_INTERFACE
	 && (ps->fs->output & 0x80000000) == 0) {
	// translate, or mark unknown
	HSPVppPort *out = getPortByOsIndex(mod, ps->fs->output);
	ps->fs->output = out ? out->vpp_index : 0;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_discard_sample     __________________
    -----------------___________________________------------------
   packet bus
  */

  static void evt_discard_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSPPendingEvtSample *ps = (HSPPendingEvtSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the SONiC ifIndex namespace.
    uint32_t dsClass = ps->discard->ds_class;
    uint32_t osIndex = ps->discard->ds_index;
    HSPVppPort *vppPort = NULL;
    uint32_t dsIndexAlias = 0;
    if(dsClass == SFL_DSCLASS_IFINDEX
       && osIndex != 0) {
      vppPort = getPortByOsIndex(mod, osIndex);
      dsIndexAlias = vppPort ? vppPort->vpp_index : 0;
      // Note that if dsIndexAlias is 0 that means "no alias"
      sfl_notifier_set_dsAlias(ps->notifier, dsIndexAlias);
    }
    // fix in/out
    if(ps->discard->input
       && ps->discard->input != SFL_INTERNAL_INTERFACE) {
      // translate, or mark unknown
	HSPVppPort *in = getPortByOsIndex(mod, ps->discard->input);
	ps->discard->input = in ? in->vpp_index : 0;
    }
    if(ps->discard->output
       && ps->discard->output != SFL_INTERNAL_INTERFACE
       && (ps->discard->output & 0x80000000) == 0) {
      // translate, or mark unknown
      HSPVppPort *out = getPortByOsIndex(mod, ps->discard->output);
      ps->discard->output = out ? out->vpp_index : 0;
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_cntr_sample     __________________
    -----------------___________________________------------------
    poll bus
  */

  static void evt_cntr_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSPPendingCSample *ps = (HSPPendingCSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the VPP ifIndex namespace. For interface counter samples that means:
    // 1. poller ds_index
    // 2. generic counters ifIndex
    uint32_t osIndex = SFL_DS_INDEX(ps->poller->dsi);
    HSPVppPort *vppPort = getPortByOsIndex(mod, osIndex);
    if(vppPort == NULL) {
      // in this mode we do not report on anything that is not a VPP interface
      ps->suppress = YES;
    }
    else {
      // fix datasource
      sfl_poller_set_dsAlias(ps->poller, vppPort->vpp_index);
      // look through counter structures
      for(SFLCounters_sample_element *elem = ps->cs->elements;
	  elem != NULL;
	  elem = elem->nxt) {
	if(elem->tag == SFLCOUNTERS_GENERIC) {
	  // fix generic ifIndex
	  elem->counterBlock.generic.ifIndex = vppPort->vpp_index;
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_vpp(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_VPP));
    HSP_mod_VPP *mdata = (HSP_mod_VPP *)mod->data;
    
    // TODO: should this be an hsflowd.conf parameter?
    mdata->group_id = SFLOW_VPP_NETLINK_USERSOCK_MULTICAST;

    mdata->ports = UTHASH_NEW(HSPVppPort, vpp_index, UTHASH_DFLT);
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_PSAMPLE), evt_psample);

    if(sp->vpp.osIndex == NO) {
      // If we are not trying to map into the Linux ifIndex namespace then the poller and
      // sampler objects will be using vpp_index numbers offset by sp->vpp.ifOffset.  That
      // will (hopefully) ensure that they do not clash with any other netdevs that that hsflowd
      // concerned with, but to translate the sFlow export back into the VPP namespace we
      // have to intercept the samples as they go out here.  This is similar to the behavior in
      // mod_sonic.
      // (Note that in future we could do this more elegantly by including a "namespace" key
      // that applies to any adaptor lookup, but the sFlow data model presents as one namespace
      // with a flat 32-bit ifIndex space, so it's likely that we will always have to do some
      // flattening like this to present a clean model to the sFlow collector.)
      EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_FLOW_SAMPLE), evt_flow_sample);
      EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTF_EVENT_SAMPLE), evt_discard_sample);
      EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_COUNTER_SAMPLE), evt_cntr_sample);
    }
    
    // TODO: check these flags
    if(sp->vpp.ds_options == 0)
      sp->vpp.ds_options = (HSP_SAMPLEOPT_DEV_SAMPLER
			    | HSP_SAMPLEOPT_DEV_POLLER
			    | HSP_SAMPLEOPT_BRIDGE
			    | HSP_SAMPLEOPT_VPP);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
