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
    uint32_t readCount;
    uint32_t readCountStart;
    bool sweeping;
    uint32_t cursor;
    uint32_t changes;
  } HSP_mod_NLROUTE;

  /*_________________---------------------------__________________
    _________________    sendNextRequest        __________________
    -----------------___________________________------------------
  */

  static bool sendNextRequest(EVMod *mod) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *ad = UTHashNext(sp->adaptorsByIndex, &mdata->cursor);
    if(ad) {
      UTNLRoute_send(mdata->nlSoc->fd, mod->id, ad->ifIndex, IFLA_IFALIAS, ++mdata->seqNo);
      return YES;
    }
    mdata->sweeping = NO;
    return NO;
  }

  /*_________________---------------------------__________________
    _________________    evt_intf_read          __________________
    -----------------___________________________------------------
  */

  static void evt_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    mdata->readCount++;
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
      // If we complete a transaction successfully, we can submit another right away?
      // Don't do this - may run too hot. Allow deci-tick batch to regulate.
      // sendNextRequest(mod);
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_deci               __________________
    -----------------___________________________------------------
  */

  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    if(mdata->sweeping) {
      for(uint32_t batch = 0; batch < 5; batch++) {
	if(sendNextRequest(mod) == NO)
	  break;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_tock               __________________
    -----------------___________________________------------------
  */

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    if(mdata->readCount != mdata->readCountStart
       && mdata->sweeping == NO) {
      // start a new sweep of the interfaces
      EVDebug(mod, 1, "evt_tock: start new sweep");
      mdata->readCountStart = mdata->readCount;
      mdata->cursor = 0;
      mdata->sweeping = YES;
    }
    EVDebug(mod, 1, "readCount=%u, readCountStart=%u, seqNo=%u, changes=%u, cursor=%u, sweeping=%u",
	    mdata->readCount,
	    mdata->readCountStart,
	    mdata->seqNo,
	    mdata->changes,
	    mdata->cursor,
	    mdata->sweeping);
  }
  
  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_nlroute(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_NLROUTE));
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    EVBus *pollBus = EVCurrentBus();
    // open netlink socket while we still have root privileges
    int nl_sock = UTNLRoute_open(mod->id);
    mdata->nlSoc = EVBusAddSocket(mod, pollBus, nl_sock, readNetlinkCB, NULL);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_INTF_READ), evt_intf_read);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TOCK), evt_tock); // trigger sweep
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_DECI), evt_deci); // batch requests
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
