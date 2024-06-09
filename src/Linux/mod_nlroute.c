/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <net/if.h>

#include "util_netlink.h"

  typedef struct _HSP_mod_NLROUTE {
    EVSocket *nlSoc;
    uint32_t seqNo;
    UTArray *requestQ;
    uint32_t changes;
  } HSP_mod_NLROUTE;

  /*_________________---------------------------__________________
    _________________    sendNextRequest        __________________
    -----------------___________________________------------------
  */

  static void sendNextRequest(EVMod *mod) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    if(UTArrayN(mdata->requestQ)) {
      intptr_t ifIndex = (intptr_t)UTArrayPop(mdata->requestQ);
      UTNLRoute_send(mdata->nlSoc->fd, mod->id, ifIndex, IFLA_IFALIAS, ++mdata->seqNo);
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_intf_read          __________________
    -----------------___________________________------------------
  */

  static void evt_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *ad = NULL;
    memcpy(&ad, data, dataLen);
    // Make sure we don't get queue build-up here
    if(UTArrayN(mdata->requestQ) > UTHashN(sp->adaptorsByIndex)) {
      EVDebug(mod, 1, "evt_intf_read: not queueing new request");
      return;
    }
    // only need the ifIndex (so it's OK if adaptor is deleted before we query)
    intptr_t ifIndex = ad->ifIndex;
    UTArrayPush(mdata->requestQ, (void *)ifIndex);
  }

  /*_________________---------------------------__________________
    _________________    readNetlinkCB          __________________
    -----------------___________________________------------------
  */

  static void readNetlinkCB(EVMod *mod, EVSocket *soc, void *magic) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    char buf[65536];
    int rc = recv(soc->fd, buf, 65536, 0);
    if (rc < 0) {
      EVDebug(mod, 1, "readNetlinkCB failed: %s", strerror(errno));
    }
    else {
      struct nlmsghdr *recv_hdr = (struct nlmsghdr*)buf;
      struct ifinfomsg *infomsg = NLMSG_DATA(recv_hdr);
      uint32_t ifIndex = infomsg->ifi_index;
      SFLAdaptor *ad = adaptorByIndex(sp, ifIndex);
      if(ad) {
	struct rtattr *rta = IFLA_RTA(infomsg);
	int len = recv_hdr->nlmsg_len;
	while (RTA_OK(rta, len)){
	  if(rta->rta_type == IFLA_IFALIAS) {
	    char *ifAlias = RTA_DATA(rta);
	    bool changed = setAdaptorAlias(sp, ad, ifAlias, "netlink");
	    if(changed) {
	      EVDebug(mod, 1, "adaptor %s set alias %s", ad->deviceName, ifAlias);
	      mdata->changes++;
	    }
	  }
	  rta = RTA_NEXT(rta, len);
	}
      }
    }
    // sendNextRequest(mod);
  }
  
  /*_________________---------------------------__________________
    _________________    evt_deci               __________________
    -----------------___________________________------------------
  */

  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    sendNextRequest(mod);
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    EVDebug(mod, 1, "seqNo=%u, changes=%u, requestQ depth=%u",
	    mdata->seqNo,
	    mdata->changes,
	    UTArrayN(mdata->requestQ));
  }
  
  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_nlroute(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_NLROUTE));
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    mdata->requestQ = UTArrayNew(UTARRAY_DFLT);
    EVBus *pollBus = EVCurrentBus();
    // open netlink socket while we still have root privileges
    int nl_sock = UTNLRoute_open(mod->id);
    mdata->nlSoc = EVBusAddSocket(mod, pollBus, nl_sock, readNetlinkCB, NULL);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_INTF_READ), evt_intf_read);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TICK), evt_tick); // logging
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_DECI), evt_deci); // sending requests
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
