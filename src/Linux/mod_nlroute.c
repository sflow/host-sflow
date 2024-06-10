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

  // module to read NETLINK_ROUTE
  // initally just to pull in IFLA_IFALIAS

  typedef struct _HSP_mod_NLROUTE {
    int nl_sock;
    EVSocket *evSoc;
    uint32_t seqNo;
    bool sweeping;
    uint32_t cursor;
    uint32_t changes;
    uint32_t deciBatch;
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
      UTNLRoute_send(mdata->nl_sock, mod->id, ad->ifIndex, IFLA_IFALIAS, ++mdata->seqNo);
      return YES;
    }
    mdata->sweeping = NO;
    return NO;
  }

  /*_________________---------------------------__________________
    _________________        readAlias          __________________
    -----------------___________________________------------------
  */

  static void readAlias(EVMod *mod) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    uint32_t ifIndex = 0;
    char alias[HSP_READNL_RCV_BUF+1];
    uint aliasLen = HSP_READNL_RCV_BUF;
    alias[0] = '\0';
    int rc = UTNLRoute_recv(mdata->nl_sock, IFLA_IFALIAS, &ifIndex, alias, &aliasLen);
    if (rc <= 0) {
      EVDebug(mod, 1, "UTNLRoute_recv() failed: rc=%d : %s", rc, strerror(errno));
    }
    else {
      EVDebug(mod, 3, "UTNLRoute_recv() ifIndex=%u, aliasLen=%u", ifIndex, aliasLen);
      if(alias[0] != '\0'
	 && aliasLen > 0) {
	alias[aliasLen] = '\0'; // make sure the string is terminated
	EVDebug(mod, 1, "UTNLRoute_recv() ifIndex=%u, alias=%s", ifIndex, alias);
	SFLAdaptor *ad = adaptorByIndex(sp, ifIndex);
	if(ad) {
	  bool changed = setAdaptorAlias(sp, ad, alias, "netlink");
	  if(changed) {
	    EVDebug(mod, 1, "adaptor %s set alias %s", ad->deviceName, alias);
	    mdata->changes++;
	    // TODO: send HSPEVENT_INTFS_CHANGED here? For example,  may need
	    // to trigger another agent-address election.  Would be better for
	    // readInterfaces() to be told and have it raise that event at
	    // the end, though.  What is the mechanism?  Do we need a flag in
	    // nio?
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    readNetlinkCB          __________________
    -----------------___________________________------------------
  */

  static void readNetlinkCB(EVMod *mod, EVSocket *soc, void *magic) {
    readAlias(mod);
  }

  /*_________________---------------------------__________________
    _________________    evt_intf_read          __________________
    -----------------___________________________------------------
    Only used when there is no rate-limit
  */

  static void evt_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    // make the request sychronously right here and now
    SFLAdaptor *ad = NULL;
    if(dataLen == sizeof(ad)) {
      memcpy(&ad, data, dataLen);
      // send request
      UTNLRoute_send(mdata->nl_sock, mod->id, ad->ifIndex, IFLA_IFALIAS, ++mdata->seqNo);
      // block here to recv immediately
      readAlias(mod);
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_end          __________________
    -----------------___________________________------------------
    Only used when rate-limit is set
  */

  static void evt_intfs_end(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    if(mdata->sweeping == NO) {
      // start a new sweep of the interfaces
      EVDebug(mod, 1, "start new sweep");
      mdata->cursor = 0;
      mdata->sweeping = YES;
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_deci               __________________
    -----------------___________________________------------------
    Only used when rate-limit is set
  */

  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    if(mdata->sweeping) {
      for(uint32_t batch = 0; batch < mdata->deciBatch; batch++) {
	if(sendNextRequest(mod) == NO)
	  break;
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_tock               __________________
    -----------------___________________________------------------
    Only used when rate-limit is set
  */

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    EVDebug(mod, 1, "seqNo=%u, changes=%u, cursor=%u, sweeping=%u",
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
    HSP *sp = (HSP *)EVROOTDATA(mod);
    EVBus *pollBus = EVCurrentBus();
    if(sp->nlroute.limit) {
      mdata->nl_sock = UTNLRoute_open(mod->id, YES, 1000000); // non-blocking socket
      mdata->evSoc = EVBusAddSocket(mod, pollBus, mdata->nl_sock, readNetlinkCB, NULL);
      mdata->deciBatch = sp->nlroute.limit / 10;
      if (mdata->deciBatch == 0)
	mdata->deciBatch = 1;
      EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_INTFS_END), evt_intfs_end); // trigger sweep
      EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_DECI), evt_deci); // batch requests
      EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TOCK), evt_tock); // logging
    }
    else {
      // no rate limit => will read immediately
      mdata->nl_sock = UTNLRoute_open(mod->id, NO, 1000000); // blocking socket
      EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_INTF_READ), evt_intf_read);
    }
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
