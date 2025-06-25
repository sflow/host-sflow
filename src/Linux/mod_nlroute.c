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
#include <linux/net_namespace.h>
#include <linux/if_link.h>
#include <net/if.h>

#include "util_netlink.h"

  static const char *ifla_name[] = {
    "IFLA_UNSPEC",
    "IFLA_ADDRESS",
    "IFLA_BROADCAST",
    "IFLA_IFNAME",
    "IFLA_MTU",
    "IFLA_LINK",
    "IFLA_QDISC",
    "IFLA_STATS",
    "IFLA_COST",
    "IFLA_PRIORITY",
    "IFLA_MASTER",
    "IFLA_WIRELESS",
    "IFLA_PROTINFO",
    "IFLA_TXQLEN",
    "IFLA_MAP",
    "IFLA_WEIGHT",
    "IFLA_OPERSTATE",
    "IFLA_LINKMODE",
    "IFLA_LINKINFO",
    "IFLA_NET_NS_PID",
    "IFLA_IFALIAS",
    "IFLA_NUM_VF",
    "IFLA_VFINFO_LIST",
    "IFLA_STATS64",
    "IFLA_VF_PORTS",
    "IFLA_PORT_SELF",
    "IFLA_AF_SPEC",
    "IFLA_GROUP",
    "IFLA_NET_NS_FD",
    "IFLA_EXT_MASK",
    "IFLA_PROMISCUITY",
    "IFLA_NUM_TX_QUEUES",
    "IFLA_NUM_RX_QUEUES",
    "IFLA_CARRIER",
    "IFLA_PHYS_PORT_ID",
    "IFLA_CARRIER_CHANGES",
    "IFLA_PHYS_SWITCH_ID",
    "IFLA_LINK_NETNSID",
    "IFLA_PHYS_PORT_NAME",
    "IFLA_PROTO_DOWN",
    "IFLA_GSO_MAX_SEGS",
    "IFLA_GSO_MAX_SIZE",
    "IFLA_PAD",
    "IFLA_XDP",
    "IFLA_EVENT",
    "IFLA_NEW_NETNSID",
    "IFLA_IF_NETNSID",
    "IFLA_CARRIER_UP_COUNT",
    "IFLA_CARRIER_DOWN_COUNT",
    "IFLA_NEW_IFINDEX",
    "IFLA_MIN_MTU",
    "IFLA_MAX_MTU",
    "IFLA_PROP_LIST",
    "IFLA_ALT_IFNAME",
    "IFLA_PERM_ADDRESS",
    "IFLA_PROTO_DOWN_REASON",
    "IFLA_PARENT_DEV_NAME",
    "IFLA_PARENT_DEV_BUS_NAME",
    "IFLA_GRO_MAX_SIZE",
    "IFLA_TSO_MAX_SIZE",
    "IFLA_TSO_MAX_SEGS",
    "IFLA_ALLMULTI",
    "IFLA_DEVLINK_PORT",
    "IFLA_GSO_IPV4_MAX_SIZE",
    "IFLA_GRO_IPV4_MAX_SIZE",
    "IFLA_DPLL_PIN"
  };

#define MY_IFLA_MAX (sizeof(ifla_name) / sizeof(char *))

  static const char *ifa_name[] = {
    "IFA_UNSPEC",
    "IFA_ADDRESS",
    "IFA_LOCAL",
    "IFA_LABEL",
    "IFA_BROADCAST",
    "IFA_ANYCAST",
    "IFA_CACHEINFO",
    "IFA_MULTICAST",
    "IFA_FLAGS",
    "IFA_RT_PRIORITY",
    "IFA_TARGET_NETNSID",
    "IFA_PROTO",
  };

#define MY_IFA_MAX (sizeof(ifa_name) / sizeof(char *))

  typedef struct _HSPNLRequest {
    struct _HSPNLRequest *prev;
    struct _HSPNLRequest *next;
    int reqType;
    uint32_t seqNo;
    // for link, addr
    uint32_t ifIndex;
    // for ns
    HSPGetNSID get_nsid;
    int fd;
  } HSPNLRequest;

  // module to read NETLINK_ROUTE
  // initally just to pull in IFLA_IFALIAS
  // and now also LINK_NETNSID, but may
  // eventually take over most of what
  // currently happens in readInterfaces.c

  typedef struct _HSP_mod_NLROUTE {
    int nl_sock;
    int nl_sock_strict;
    uint32_t seqNo;
    bool sweeping;
    uint32_t cursor;
    uint32_t changes;
    uint32_t deciBatch;
    UTQ(HSPNLRequest) requestQ;
    UTHash *requestHT;
    EVEvent *evt_get_nsid_ans;
  } HSP_mod_NLROUTE;

  static void processNetlinkCB(void *magic, struct nlmsghdr *recv_hdr, int msglen);

  /*_________________---------------------------__________________
    _________________    attribute names        __________________
    -----------------___________________________------------------
  */

  static const char *iflaName(int ifla) {
    return (ifla < MY_IFLA_MAX) ? ifla_name[ifla] : "<ifla_unknown>";
  }

  static const char *ifaName(int ifa) {
    return (ifa < MY_IFA_MAX) ? ifa_name[ifa] : "<ifa_unknown>";
  }

  /*_________________---------------------------__________________
    _________________    HSPNLRequestEnqueue    __________________
    -----------------___________________________------------------
  */

  static void HSPNLRequestEnqueue(EVMod *mod, HSPNLRequest *req) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    UTQ_ADD_TAIL(mdata->requestQ, req);
  }

  /*_________________---------------------------__________________
    _________________    HSPNLRequestNew        __________________
    -----------------___________________________------------------
  */

  static HSPNLRequest *HSPNLRequestNew(EVMod *mod, int reqType, uint32_t ifIndex) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSPNLRequest *req = my_calloc(sizeof(HSPNLRequest));
    req->seqNo = ++mdata->seqNo;
    req->reqType = reqType;
    req->ifIndex = ifIndex;
    return req;
  }

  /*_________________---------------------------__________________
    _________________    HSPNLRequestPrint      __________________
    -----------------___________________________------------------
  */

  static void HSPNLRequestPrint(HSPNLRequest *req, UTStrBuf *strBuf) {
    UTStrBuf_printf(strBuf, "req(seqNo=%u,type=%u,ifIndex=%u)",
		    req->seqNo,
		    req->reqType,
		    req->ifIndex);
  }

  /*_________________----------------------------__________________
    _________________ queueNextInterfaceRequests __________________
    -----------------____________________________------------------
  */

  static bool queueNextInterfaceRequests(EVMod *mod) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *ad = UTHashNext(sp->adaptorsByIndex, &mdata->cursor);
    if(ad) {
      HSPNLRequest *req1 = HSPNLRequestNew(mod, RTM_GETLINK, ad->ifIndex);
      HSPNLRequestEnqueue(mod, req1);
      HSPNLRequest *req2 = HSPNLRequestNew(mod, RTM_GETADDR, ad->ifIndex);
      HSPNLRequestEnqueue(mod, req2);
      return YES;
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________    sendNextRequest        __________________
    -----------------___________________________------------------
  */

  static bool sendNextRequest(EVMod *mod) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    if(UTQ_EMPTY(mdata->requestQ))
      return NO;
    HSPNLRequest *req = NULL;
    UTQ_REMOVE_HEAD(mdata->requestQ, req);
    if(req == NULL)
      return NO;

    UTStrBuf *strBuf = UTStrBuf_new();
    HSPNLRequestPrint(req, strBuf);
    
    if(req->reqType != RTM_GETLINK
       && req->reqType != RTM_GETADDR)
      goto not_sent;
    
    EVDebug(mod, 1,  "sending request %s", UTSTRBUF_STR(strBuf));
    int rc = -1;
    if(req->reqType == RTM_GETLINK
       && mdata->nl_sock >= 0)
      rc = UTNLRoute_link_send(mdata->nl_sock, mod->id, req->ifIndex, req->seqNo);
    else if(req->reqType == RTM_GETADDR
	    && mdata->nl_sock_strict >= 0)
      rc = UTNLRoute_addr_send(mdata->nl_sock_strict, mod->id, req->ifIndex, req->seqNo);
    else if(req->reqType == RTM_GETNSID
	    && mdata->nl_sock) {
      // open /proc/<nspid>/ns/net
      char topath[HSP_MAX_PATHLEN];
      snprintf(topath, HSP_MAX_PATHLEN, PROCFS_STR "/%u/ns/net", req->get_nsid.nspid);
      req->fd = open(topath, O_RDONLY | O_CLOEXEC);
      if(req->fd < 0) {
	EVDebug(mod, 1, "cannot open %s : %s", topath, strerror(errno));
	goto not_sent;
      }
      rc = UTNLRoute_ns_send(mdata->nl_sock, mod->id, req->fd, req->seqNo);
    }
    else
      goto not_sent;
    if (rc <= 0) {
      myLog(LOG_ERR, "UTNLRoute_*_send(%s) failed: rc=%d : %s",
	    UTSTRBUF_STR(strBuf),
	    rc,
	    strerror(errno));
      goto not_sent;
    }

    // sent OK - register the request
    UTHashAdd(mdata->requestHT, req);
    UTStrBuf_free(strBuf);
    return YES;

  not_sent:
    // clean up
    if(req->fd > 0)
      close(req->fd);
    if(req)
      my_free(req);
    if(strBuf)
      UTStrBuf_free(strBuf);
    return NO;
  }

  /*_________________---------------------------__________________
    _________________    processNetlink_error   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_error(EVMod *mod, struct nlmsghdr *recv_hdr, int msglen, HSPNLRequest *req)  {
    EVDebug(mod, 1, "processNetlink_error");
    struct nlmsgerr *errmsg = NLMSG_DATA(recv_hdr);
    EVDebug(mod, 1, "nlmsg_err = %s", strerror(0 - errmsg->error));
    // uint16_t len = recv_hdr->nlmsg_len;
    // struct nlmsghdr *err_hdr = &errmsg->msg;
    // call processNetlinkCB again with err_hdr, but this time
    // req will not look up
    // processNetlinkCB(mod, err_hdr, len);
  }

  /*_________________---------------------------__________________
    _________________        readAlias          __________________
    -----------------___________________________------------------
  */

  static void readAlias(EVMod *mod, uint32_t ifIndex, char *alias, int aliasLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    EVDebug(mod, 3, "readAlias() ifIndex=%u, aliasLen=%u", ifIndex, aliasLen);
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

  /*_________________---------------------------__________________
    _________________    processNetlink_ifinfo  __________________
    -----------------___________________________------------------
  */

  static void processNetlink_ifinfo(EVMod *mod, struct nlmsghdr *recv_hdr, int msglen, HSPNLRequest *req)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    EVDebug(mod, 1, "processNetlink_ifinfo");
    uint16_t len = recv_hdr->nlmsg_len;
    char buf[HSP_READNL_RCV_BUF+1];
    buf[0] = '\0';
    struct ifinfomsg *infomsg = NLMSG_DATA(recv_hdr);
    uint32_t ifIndex = infomsg->ifi_index;
    struct rtattr *rta = IFLA_RTA(infomsg);
    while (RTA_OK(rta, len)){
      // extra check to reassure coverity
      if(len > msglen)
	break;
      uint32_t rttype = (rta->rta_type & ~NLA_F_NESTED);
      uint32_t nested = rta->rta_type & NLA_F_NESTED;
      void *data = RTA_DATA(rta);
      uint32_t dataLen = RTA_PAYLOAD(rta);
      EVDebug(mod, 1, "  rttype=%s(%u) nested=%u payload=%u",
	      iflaName(rttype),
	      rttype,
	      nested,
	      dataLen);
      switch(rttype) {
      case IFLA_IFNAME:
	if(dataLen)
	  memcpy(buf, data, dataLen);
	buf[dataLen] = '\0';
	EVDebug(mod, 1, "IFLA_IFNAME=%s", buf);
	break;
      case IFLA_IFALIAS:
	if(dataLen)
	  memcpy(buf, data, dataLen);
	buf[dataLen] = '\0';
	EVDebug(mod, 1, "IFLA_IFALIAS=%s", buf);
	readAlias(mod, ifIndex, buf, dataLen);
	break;
      case IFLA_ADDRESS:
      case IFLA_PERM_ADDRESS:
	u_char hex[64];
	printHex(data, dataLen, hex, 64, YES);
	EVDebug(mod, 1, "%s=%s", iflaName(rttype), hex);
	break;
      case IFLA_NET_NS_PID:
	EVDebug(mod, 1, "  IFLA_NET_NS_PID");
	break;
      case IFLA_LINK_NETNSID:
	{
	  uint32_t nsid = *(uint32_t *)data;
	  EVDebug(mod, 1, "IFLA_LINK_NETNSID=%u", htonl(nsid));
	  SFLAdaptor *ad = adaptorByIndex(sp, ifIndex);
	  if(ad)
	    setAdaptorNETNSID(sp, ad, nsid, "netlink");
	}
	break;
      }
      rta = RTA_NEXT(rta, len);
    }
  }

  /*_________________---------------------------__________________
    _________________   addressFamilyName       __________________
    -----------------___________________________------------------
  */
  static const char *addressFamilyName(int fam) {
    switch(fam) {
    case AF_INET: return "IP";
    case AF_INET6: return "IP6";
    }
    return "other";
  }
  
  /*_________________---------------------------__________________
    _________________    processNetlink_ifaddr  __________________
    -----------------___________________________------------------
  */

  static void processNetlink_ifaddr(EVMod *mod, struct nlmsghdr *recv_hdr, int msglen, HSPNLRequest *req)  {
    EVDebug(mod, 1, "processNetlink_ifaddr");
    uint16_t len = recv_hdr->nlmsg_len;
    struct ifaddrmsg *addrmsg = NLMSG_DATA(recv_hdr);
    uint32_t link_index = addrmsg->ifa_index;
    EVDebug(mod, 1, "address fam=%s prefixLen=%d, link-index=%u",
	    addressFamilyName(addrmsg->ifa_family),
	    addrmsg->ifa_prefixlen,
	    link_index);
    struct rtattr *rta = IFA_RTA(addrmsg);
    while (RTA_OK(rta, len)){
      // extra check to reassure coverity
      if(len > msglen)
	break;

      EVDebug(mod, 1, "  rta_type=%s(%u) payload=%u",
	      ifaName(rta->rta_type),
	      rta->rta_type,
	      RTA_PAYLOAD(rta));

      switch(rta->rta_type) {
      case IFA_LOCAL:
      case IFA_ADDRESS:
	{
	  EVDebug(mod, 1, "LOCAL or ADDRESS");
	  // IFA_ADDRESS is the other end of a point-to-point (see linux/if_addr.h)
	  SFLAddress addr = {};
	  switch(addrmsg->ifa_family) {
	  case AF_INET6:
	    addr.type = SFLADDRESSTYPE_IP_V6;
	    memcpy(addr.address.ip_v6.addr, RTA_DATA(rta), 16);
	    break;
	  case AF_INET:
	    addr.type = SFLADDRESSTYPE_IP_V4;
	    memcpy(&addr.address.ip_v4.addr, RTA_DATA(rta), 4);
	    break;
	  default:
	    EVDebug(mod, 1, "skipping address_family %s",
		    addressFamilyName(addrmsg->ifa_family));
	    break;
	  }
	  char buf[64];
	  EVDebug(mod, 1, "addr=%s", SFLAddress_print(&addr, buf, 64));
	}
	break;
      case IFA_TARGET_NETNSID:
	EVDebug(mod, 1, "IFA_TARGET_NETNSID");
	break;
      }
      rta = RTA_NEXT(rta, len);
    }
  }

  /*_________________---------------------------__________________
    _________________      processNetlink_ns    __________________
    -----------------___________________________------------------
  */

  static void processNetlink_ns(EVMod *mod, struct nlmsghdr *recv_hdr, int msglen, HSPNLRequest *req)  {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    EVDebug(mod, 1, "processNetlink_ns");
    uint16_t len = recv_hdr->nlmsg_len;
    struct rtgenmsg *genmsg = NLMSG_DATA(recv_hdr);
    struct rtattr *rta = UTNLA_RTA(genmsg);
    while (RTA_OK(rta, len)){
      // extra check to reassure coverity
      if(len > msglen)
	break;
      if(rta->rta_type == NETNSA_NSID) {
	req->get_nsid.nsid = *(uint32_t *)RTA_DATA(rta);
	req->get_nsid.found = YES;
      }
    }
    rta = RTA_NEXT(rta, len);
    // clear state in the request
    if(req->fd) {
      close(req->fd);
      req->fd = 0;
    }
    // and announce the answer, found or not
    EVEventTx(mod, mdata->evt_get_nsid_ans, &req->get_nsid, sizeof(req->get_nsid));
  }

  /*_________________---------------------------__________________
    _________________    processNetlinkCB       __________________
    -----------------___________________________------------------
  */

  static void processNetlinkCB(void *magic, struct nlmsghdr *recv_hdr, int msglen) {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    // extra check to reassure coverity
    bool done = (recv_hdr->nlmsg_flags & NLM_F_MULTI) == 0;
    uint16_t len = recv_hdr->nlmsg_len;
    if((int)len > msglen) {
      EVDebug(mod, 1, "processNetlinkCB msg len error %d > %d", (int)len, msglen);
      return;
    }
    EVDebug(mod, 1, "processNetlinkCB got nlmsg_type==%u", recv_hdr->nlmsg_type);
    HSPNLRequest search = { .seqNo = recv_hdr->nlmsg_seq };
    HSPNLRequest *req = UTHashGet(mdata->requestHT, &search);
    if(req) {
      EVDebug(mod, 1, "found seqNo %u==%u request (ifIndex=%u reqType=%u)",
	      recv_hdr->nlmsg_seq,
	      req->seqNo,
	      req->ifIndex,
	      req->reqType);
    }
    else {
      EVDebug(mod, 1, "seqNo %u not found in requestHT", recv_hdr->nlmsg_seq);
    }

    switch(recv_hdr->nlmsg_type) {
    case NLMSG_NOOP:
      EVDebug(mod, 1, "NOOP");
      break;
    case NLMSG_ERROR:
      EVDebug(mod, 1, "ERROR");
      processNetlink_error(mod, recv_hdr, msglen, req);
      break;
    case NLMSG_DONE:
      EVDebug(mod, 1, "DONE");
      done = YES; // end of multi-part message
      break;
    case NLMSG_OVERRUN:
      EVDebug(mod, 1, "OVERRUN");
      break;
    case RTM_NEWLINK:
    case RTM_GETLINK:
      EVDebug(mod, 1, "LINK");
      processNetlink_ifinfo(mod, recv_hdr, msglen, req);
      break;

    case RTM_SETLINK:
      break;
    case RTM_NEWADDR:
    case RTM_GETADDR:
    case RTM_DELADDR:
      EVDebug(mod, 1, "ADDR");
      processNetlink_ifaddr(mod, recv_hdr, msglen, req);
      break;
    case RTM_NEWROUTE:
    case RTM_GETROUTE:
    case RTM_DELROUTE:
      EVDebug(mod, 1, "ROUTE");
      break;
    case RTM_NEWNEIGH:
    case RTM_GETNEIGH:
    case RTM_DELNEIGH:
      EVDebug(mod, 1, "NEIGH");
      // (e.g. ARP) => struct ndmsg
      break;
    case RTM_NEWPREFIX:
      EVDebug(mod, 1, "PREFIX");
      break;
    case RTM_NEWNSID:
    case RTM_GETNSID:
      EVDebug(mod, 1, "NSID");
      processNetlink_ns(mod, recv_hdr, msglen, req);
      break;
    case RTM_NEWSTATS:
    case RTM_GETSTATS:
      EVDebug(mod, 1, "STATS");
      break;
    case RTM_NEWVLAN:
    case RTM_GETVLAN:
    case RTM_DELVLAN:
      EVDebug(mod, 1, "VLAN");
      break;
    }
    if(req
       && done) {
      // avoid double-free - only free req if it was found in the HT
      if(UTHashDel(mdata->requestHT, req))
	my_free(req);
    }
  }

  /*_________________---------------------------__________________
    _________________    readNetlinkCB          __________________
    -----------------___________________________------------------
  */

  static void readNetlinkCB(EVMod *mod, EVSocket *soc, void *magic) {
    UTNLRoute_recv_nlmsg(mod, soc->fd, processNetlinkCB);
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_end          __________________
    -----------------___________________________------------------
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
  */

  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    int outstandingRequests = UTHashN(mdata->requestHT);
    if(mdata->sweeping) {
      for(uint32_t batch = 0; batch < mdata->deciBatch; batch++) {
	if(queueNextInterfaceRequests(mod) == NO)
	  mdata->sweeping = NO;
      }
    }
    if(outstandingRequests == 0)
      sendNextRequest(mod);
  }
  
  /*_________________---------------------------__________________
    _________________    evt_tock               __________________
    -----------------___________________________------------------
  */
  
  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_NLROUTE *mdata = (HSP_mod_NLROUTE *)mod->data;
    EVDebug(mod, 1, "seqNo=%u, changes=%u, cursor=%u, sweeping=%u, requests=%u",
	    mdata->seqNo,
	    mdata->changes,
	    mdata->cursor,
	    mdata->sweeping,
	    UTHashN(mdata->requestHT));
  }
  
  /*_________________---------------------------__________________
    _________________    namespace lookup api   __________________
    -----------------___________________________------------------
    Provide this as a serice to other modules that want to make this lookup (e.g. mod_k8s)
  */
  
  static void evt_get_nsid(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    EVDebug(mod, 1, "evt_get_nsid");
    if(dataLen == sizeof(HSPGetNSID)) {
      HSPNLRequest *req = HSPNLRequestNew(mod, RTM_GETNSID, 0);
      memcpy(&req->get_nsid, data, dataLen);
      EVDebug(mod, 1, "evt_get_nsid lookup nspid %u", req->get_nsid.nspid);
      HSPNLRequestEnqueue(mod, req);
    }
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
    mdata->requestHT = UTHASH_NEW(HSPNLRequest, seqNo, UTHASH_DFLT);
    uint32_t nl_groups = 0;
    // nl_groups |= 1 << RTNLGRP_LINK;
    // nl_groups |= 1 << RTNLGRP_IPV4_IFADDR;
    // nl_groups |= 1 << RTNLGRP_IPV6_IFADDR;
    // nl_groups |= 1 << RTNLGRP_IPV6_IFINFO;
    // nl_groups |= 1 << RTNLGRP_NSID;
    // nl_groups |= 1 << RTNLGRP_NOTIFY;
    // if we want to join groups > 32 such as RTNLGRP_BRVLAN then we can't do this:
    // nl_groups |= 1 << RTNLGRP_BRVLAN;
    // instead we need to use setsockopt(NETLINK_ADD_MEMBERSHIP)

    // open 2 sockets - one with "strict" filtering-mode.  We need to use
    // strict mode to, for example, dump all addresses for a given ifIndex.
    mdata->nl_sock = UTNLRoute_open(mod->id, YES, 1000000, nl_groups, NO);
    mdata->nl_sock_strict = UTNLRoute_open(mod->id, YES, 1000000, nl_groups, YES);

#if 0
    // If we want to react to any new interface being set up or modified
    // in any namespace, (which we probably will want to do) then we should
    // set this NETLINK_LISTEN_ALL_NSID option. This seems to be the way to
    // apply it to a socket.
    int opt = 1;
    if(setsockopt(mdata->nl_sock,
		  SOL_SOCKET,
		  NETLINK_LISTEN_ALL_NSID,
		  &opt,
		  sizeof(opt)) < 0)
      EVDebug(mod, 1, "setsockopt(NETLINK_LISTEN_ALL_NSID) failed: %s", strerror(errno));
#endif

    // The two sockets can both use the same callback
    if(mdata->nl_sock > 0)
      EVBusAddSocket(mod, pollBus, mdata->nl_sock, readNetlinkCB, NULL);
    if(mdata->nl_sock_strict > 0)
      EVBusAddSocket(mod, pollBus, mdata->nl_sock_strict, readNetlinkCB, NULL);
    mdata->deciBatch = sp->nlroute.limit / 10;
    if(mdata->deciBatch == 0)
      mdata->deciBatch = 1;
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_INTFS_END), evt_intfs_end); // trigger sweep
    // GET_NSID api
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_GET_NSID), evt_get_nsid);
    mdata->evt_get_nsid_ans = EVGetEvent(pollBus, HSPEVENT_GET_NSID_ANS);
    // time
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_DECI), evt_deci); // batch requests
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TOCK), evt_tock); // logging
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
