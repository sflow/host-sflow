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
#include <fnmatch.h>

#include "util_netlink.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef DROPMON_GENL_NAME
  #define DROPMON_GENL_NAME "NET_DM"
#endif

#define HSP_REPLICATE_DROPMON_DEFS 1
#ifdef  HSP_REPLICATE_DROPMON_DEFS
  /* Replicate the definitions we need from net_dropmon.h here,
     so we can compile on an older OS if necessary. This assumes
     that the kernel will only ever add to these, and never
     change them.
  */
  
  /* net_dm_addr */
#define NET_DM_ATTR_UNSPEC 0
#define NET_DM_ATTR_ALERT_MODE 1                 /* u8 */
#define NET_DM_ATTR_PC 2                         /* u64 */
#define NET_DM_ATTR_SYMBOL 3                     /* string */
#define NET_DM_ATTR_IN_PORT 4                    /* nested */
#define NET_DM_ATTR_TIMESTAMP 5                  /* u64 */
#define NET_DM_ATTR_PROTO 6                      /* u16 */
#define NET_DM_ATTR_PAYLOAD 7                    /* binary */
#define NET_DM_ATTR_PAD 8
#define NET_DM_ATTR_TRUNC_LEN 9                  /* u32 */
#define NET_DM_ATTR_ORIG_LEN 10                  /* u32 */
#define NET_DM_ATTR_QUEUE_LEN 11                 /* u32 */
#define NET_DM_ATTR_STATS 12                     /* nested */
#define NET_DM_ATTR_HW_STATS 13                  /* nested */
#define NET_DM_ATTR_ORIGIN 14                    /* u16 */
#define NET_DM_ATTR_HW_TRAP_GROUP_NAME 15        /* string */
#define NET_DM_ATTR_HW_TRAP_NAME 16              /* string */
#define NET_DM_ATTR_HW_ENTRIES 17                /* nested */
#define NET_DM_ATTR_HW_ENTRY 18                  /* nested */
#define NET_DM_ATTR_HW_TRAP_COUNT 19             /* u32 */
#define NET_DM_ATTR_SW_DROPS 20                  /* flag */
#define NET_DM_ATTR_HW_DROPS 21                  /* flag */
#define NET_DM_ATTR_FLOW_ACTION_COOKIE 22        /* binary */
#define NET_DM_ATTR_REASON 23                    /* string */
#define NET_DM_ATTR_MAX NET_DM_ATTR_REASON

/* net_dm_alert_mode */
#define NET_DM_ALERT_MODE_SUMMARY 0
#define NET_DM_ALERT_MODE_PACKET 1

/* net_dm_attr_port */
#define NET_DM_ATTR_PORT_NETDEV_IFINDEX 0        /* u32 */
#define NET_DM_ATTR_PORT_NETDEV_NAME 1           /* string */
#define NET_DM_ATTR_PORT_MAX NET_DM_ATTR_PORT_NETDEV_NAME
  
#endif /* HSP_REPLICATE_DROPMON_DEFS */		      
  
#define HSP_DROPMON_READNL_RCV_BUF 16384
#define HSP_DROPMON_READNL_BATCH 100
#define HSP_DROPMON_RCVBUF 8000000
#define HSP_DROPMON_QUEUE 1000 // seems to be default (in kernel net/core/drop_monitor.c)

  typedef enum {
    HSP_DROPMON_STATE_INIT=0,
    HSP_DROPMON_STATE_GET_FAMILY,
    HSP_DROPMON_STATE_WAIT,
    HSP_DROPMON_STATE_GOT_GROUP,
    HSP_DROPMON_STATE_JOIN_GROUP,
    HSP_DROPMON_STATE_CONFIGURE,
    HSP_DROPMON_STATE_START,
    HSP_DROPMON_STATE_RUN,
    HSP_DROPMON_STATE_STOP
  } EnumDropmonState;

  static const char *HSPDropmonStateNames[] = {
    "INIT",
    "GET_FAMILY",
    "WAIT",
    "GOT_GROUP",
    "JOIN_GROUP",
    "CONFIGURE",
    "START",
    "RUN",
    "STOP"
  };
  
  typedef struct _HSPDropPoint {
    char *dropPoint;
    EnumSFLDropReason reason;
    bool pattern;
  } HSPDropPoint;
    
  typedef struct _HSP_mod_DROPMON {
    EnumDropmonState state;
    EVBus *packetBus;
    bool dropmon_configured;
    int nl_sock;
    EVSocket *nl_evsock;
    uint32_t nl_seq;
    int retry_countdown;
#define HSP_DROPMON_WAIT_RETRY_S 15
    uint32_t genetlink_version;
    uint16_t family_id;
    uint32_t group_id;
    uint32_t headerSize;
    uint32_t maxAttr;
    uint32_t last_grp_seq;
    UTHash *dropPoints_sw;
    UTHash *dropPoints_hw;
    UTHash *dropPoints_rn;
    UTArray *dropPatterns_sw;
    UTArray *dropPatterns_hw;
    UTArray *dropPatterns_rn;
    UTHash *notifiers;
    uint32_t feedControlErrors;
    int quota;   // notification rate-limit
    uint32_t noQuota; // number of rate-limit drops
    uint32_t ignoredDrops_hw;
    uint32_t ignoredDrops_sw;
    uint32_t ignoredDrops_rn;
    uint32_t totalDrops_thisTick; // for threshold
    bool dropmon_disabled;
    EVEvent *evt_intf_es;
  } HSP_mod_DROPMON;


  /*_________________---------------------------__________________
    _________________     state change          __________________
    -----------------___________________________------------------
  */

  static void setState(EVMod *mod, EnumDropmonState newState) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    if(newState != mdata->state) {
      EVDebug(mod, 1, "state %s -> %s",
	      HSPDropmonStateNames[mdata->state],
	      HSPDropmonStateNames[newState]);
      mdata->state = newState;
    }
  }

  /*_________________---------------------------__________________
    _________________      addDropPoint         __________________
    -----------------___________________________------------------
  */

  static HSPDropPoint *newDropPoint(char *dropPointStr, bool pattern, EnumSFLDropReason reason) {
    HSPDropPoint *dp = (HSPDropPoint *)my_calloc(sizeof(HSPDropPoint));
    dp->dropPoint = my_strdup(dropPointStr);
    dp->pattern = pattern;
    dp->reason = reason;
    return dp;
  }

  static void addDropPoint_sw(EVMod *mod, HSPDropPoint *dropPoint) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    if(dropPoint->pattern)
      UTArrayAdd(mdata->dropPatterns_sw, dropPoint);
    else {
      if(UTHashGet(mdata->dropPoints_sw, dropPoint))
	EVDebug(mod, 0, "WARNING: duplicate software-dropPoint key: %s", dropPoint->dropPoint);
      UTHashAdd(mdata->dropPoints_sw, dropPoint);
    }
  }

  static void addDropPoint_hw(EVMod *mod, HSPDropPoint *dropPoint) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    if(dropPoint->pattern)
      UTArrayAdd(mdata->dropPatterns_hw, dropPoint);
    else {
      if(UTHashGet(mdata->dropPoints_hw, dropPoint))
	EVDebug(mod, 0, "WARNING: duplicate hardware-dropPoint key: %s", dropPoint->dropPoint);
      UTHashAdd(mdata->dropPoints_hw, dropPoint);
    }
  }

  static void addDropPoint_rn(EVMod *mod, HSPDropPoint *dropPoint) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    if(dropPoint->pattern)
      UTArrayAdd(mdata->dropPatterns_rn, dropPoint);
    else {
      if(UTHashGet(mdata->dropPoints_rn, dropPoint))
        EVDebug(mod, 0, "WARNING: duplicate reason-dropPoint key: %s", dropPoint->dropPoint);
      UTHashAdd(mdata->dropPoints_rn, dropPoint);
    }
  }

  /*_________________---------------------------__________________
    _________________    getDropPoint           __________________
    -----------------___________________________------------------
  */

  static HSPDropPoint *getDropPoint_sw(EVMod *mod, char *sw_symbol) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;

    // we may have been configured to ignore sw drops
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(!sp->dropmon.sw
       && !sp->dropmon.sw_passive) {
      mdata->ignoredDrops_sw++;
      return NULL;
    }

    // direct lookup
    HSPDropPoint search = { .dropPoint = sw_symbol };
    HSPDropPoint *dp = UTHashGet(mdata->dropPoints_sw, &search);
    if(dp)
      return dp;

    // see if we can find it via a pattern
    UTARRAY_WALK(mdata->dropPatterns_sw, dp) {
      if(fnmatch(dp->dropPoint, sw_symbol, FNM_CASEFOLD) == 0) {
	// yes - add the direct lookup to the hash table for next time and return it
	EVDebug(mod, 2, "dropPoint pattern %s matched %s", dp->dropPoint, sw_symbol);
	dp = newDropPoint(sw_symbol, NO, dp->reason);
	addDropPoint_sw(mod, dp);
	return dp;
      }
    }

    return NULL;
  }

  static HSPDropPoint *getDropPoint_hw(EVMod *mod, char *group, char *dropPointStr) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;

    // we may have been configured to ignore hw drops
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(!sp->dropmon.hw
       && !sp->dropmon.hw_passive) {
      mdata->ignoredDrops_hw++;
      return NULL;
    }

    // direct lookup
    HSPDropPoint search = { .dropPoint = dropPointStr };
    HSPDropPoint *dp = UTHashGet(mdata->dropPoints_hw, &search);
    if(dp)
      return dp;

    if(group) {
      // see if we have an entry just for the group
      search.dropPoint = group;
      dp = UTHashGet(mdata->dropPoints_hw, &search);
      if(dp)
	return dp;
    }
    
    // see if we can find it via a pattern
    UTARRAY_WALK(mdata->dropPatterns_hw, dp) {
      if(fnmatch(dp->dropPoint, dropPointStr, FNM_CASEFOLD) == 0) {
	// yes - add the direct lookup to the hash table for next time
	EVDebug(mod, 2, "dropPoint pattern %s matched grp=%s str=%s",
		dp->dropPoint,
		group ?: "<not supplied>",
		dropPointStr);
	dp = newDropPoint(dropPointStr, NO, dp->reason);
	addDropPoint_hw(mod, dp);
	return dp;
      }
    }

    return NULL;
  }

  static HSPDropPoint *getDropPoint_rn(EVMod *mod, char *dropReason) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;

    // we may have been configured to ignore rn drops
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(!sp->dropmon.rn) {
      mdata->ignoredDrops_rn++;
      return NULL;
    }

    // direct lookup
    HSPDropPoint search = { .dropPoint = dropReason };
    HSPDropPoint *dp = UTHashGet(mdata->dropPoints_rn, &search);
    if(dp)
      return dp;

    // see if we can find it via a pattern
    UTARRAY_WALK(mdata->dropPatterns_rn, dp) {
      if(fnmatch(dp->dropPoint, dropReason, FNM_CASEFOLD) == 0) {
	// yes - add the direct lookup to the hash table for next time and return it
	EVDebug(mod, 2, "dropPoint pattern %s matched %s", dp->dropPoint, dropReason);
	dp = newDropPoint(dropReason, NO, dp->reason);
	addDropPoint_rn(mod, dp);
	return dp;
      }
    }

    return NULL;
  }

  /*_________________---------------------------__________________
    _________________   sFlow reason codes      __________________
    -----------------___________________________------------------
  */

#define SFL_DROP(nm,cd) { .name=#nm, .code=cd },
  static struct { char *name; int code; } sflow_codes[] = {
#include "sflow_drop.h"
  };
#undef SFL_DROP

  static int getReasonCode(char *reasonName) {
    int entries = sizeof(sflow_codes) / sizeof(sflow_codes[0]);
    for(int ii = 0; ii < entries; ii++) {
      if(my_strequal(reasonName, sflow_codes[ii].name))
	return sflow_codes[ii].code;
    }
    return -1; // not found
  }

  /*_________________---------------------------__________________
    _________________    loadDropPoints         __________________
    -----------------___________________________------------------
  */

  typedef struct {
    char *op;
    char *dp;
    char *reason;
  } HSPDropPointLoader;

#define HSP_DROPPOINT(op,dp,reason) { #op, #dp, #reason },
  static HSPDropPointLoader LoadDropPoints_sw[] = {
#include "dropPoints_sw.h"
  };
  static HSPDropPointLoader LoadDropPoints_hw[] = {
#include "dropPoints_hw.h"
  };
  static HSPDropPointLoader LoadDropPoints_rn[] = {
#include "dropPoints_rn.h"
  };
#undef HSP_DROPPOINT

#define HSP_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

  static HSPDropPoint *buildDropPoint(EVMod *mod, HSPDropPointLoader *loader) {
    EVDebug(mod, 1, "loading dropPoint %s %s: reason=\"%s\"",
	    loader->op,
	    loader->dp,
	    loader->reason);

    int reasonCode = -1;
    // allow a blank reason to go through as reasonCode==-1,
    // otherwise fail if the lookup fails.
    if(loader->reason
       && my_strlen(loader->reason) > 0) {
      reasonCode = getReasonCode(loader->reason);
      if(reasonCode < 0) {
	EVDebug(mod, 1, "skipping dropPoint: failed reason code lookup \"%s\"", loader->reason);
	return NULL;
      }
    }
 
    // check operator
    bool eq = my_strequal(loader->op, "==");
    bool isPattern = my_strequal(loader->op, "*=");
    if(!eq && !isPattern) {
      EVDebug(mod, 1, "skipping dropPoint: bad operator \"%s\"", loader->op);
      return NULL;
    }
    // All OK
    return newDropPoint(loader->dp, isPattern, reasonCode);
  }

  static void loadDropPoints(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->dropmon.sw
       || sp->dropmon.sw_passive) {
      for(int ii = 0; ii < HSP_ARRAY_SIZE(LoadDropPoints_sw); ii++) {
	HSPDropPoint *dp = buildDropPoint(mod, &LoadDropPoints_sw[ii]);
	if(dp)
	  addDropPoint_sw(mod, dp);
      }
    }

    if(sp->dropmon.hw
       || sp->dropmon.hw_passive) {
      for(int ii = 0; ii < HSP_ARRAY_SIZE(LoadDropPoints_hw); ii++) {
	HSPDropPoint *dp = buildDropPoint(mod, &LoadDropPoints_hw[ii]);
	if(dp)
	  addDropPoint_hw(mod, dp);
      }
      if(sp->dropmon.hw_unknown) {
	// Option to match everything that falls through the classifier. This
	// is the same as including "HSP_DROPPOINT(*=,*,unknown)" in dropPoints_hw.h
	// except that we can turn it on/off in the config.
	HSPDropPointLoader dplAll = { "*=", "*", "unknown" };
	HSPDropPoint *dp = buildDropPoint(mod, &dplAll);
	if(dp)
	  addDropPoint_hw(mod, dp);
      }
    }

    if(sp->dropmon.rn) {
      for(int ii = 0; ii < HSP_ARRAY_SIZE(LoadDropPoints_rn); ii++) {
	HSPDropPoint *dp = buildDropPoint(mod, &LoadDropPoints_rn[ii]);
	if(dp)
	  addDropPoint_rn(mod, dp);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    getFamily_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void getFamily_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    setState(mod, HSP_DROPMON_STATE_GET_FAMILY);
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

  static bool joinGroup_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    setState(mod, HSP_DROPMON_STATE_JOIN_GROUP);
    // register for the multicast group_id
    if(setsockopt(mdata->nl_sock,
		  SOL_NETLINK,
		  NETLINK_ADD_MEMBERSHIP,
		  &mdata->group_id,
		  sizeof(mdata->group_id)) == -1) {
      myLog(LOG_ERR, "error joining DROPMON netlink group %u : %s",
	    mdata->group_id,
	    strerror(errno));
      return NO;
    }
    return YES;
  }

  /*_________________---------------------------__________________
    _________________    start_DROPMON          __________________
    -----------------___________________________------------------
TODO: enhance util_netlink to offer this variant:
 UTNLGeneric_setFlags(sock, id, type, cmd, seqNo, NET_DM_ATTR_SW_DROPS, NET_DM_ATTR_HW_DROPS)
Or we could call with a vararg list of strutures containing nlattr type,len,payload details.
That would allow everything to stay on the stack as it does here, which has nice properties.
*/

  static int start_DROPMON(EVMod *mod, bool startIt, bool sw, bool hw)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;

    // Always transition state even on no-op
    setState(mod,
	     startIt
	     ? HSP_DROPMON_STATE_START
	     : HSP_DROPMON_STATE_STOP);
    
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr[2] = { };

    int fl = 0; // count flags
    if(sw) {
      attr[fl].nla_len = sizeof(struct nlattr);
      attr[fl].nla_type = NET_DM_ATTR_SW_DROPS;
      fl++;
    }
    if(hw) {
      attr[fl].nla_len = sizeof(struct nlattr);
      attr[fl].nla_type = NET_DM_ATTR_HW_DROPS;
      fl++;
    }

    if(fl == 0) {
      // no-op
      return 0;
    }

    ge.cmd = startIt
      ? NET_DM_CMD_START
      : NET_DM_CMD_STOP;
    ge.version = 1;

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ge) + (fl * sizeof(struct nlattr)));
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = mdata->family_id;
    nlh.nlmsg_seq = ++mdata->nl_seq;
    nlh.nlmsg_pid = UTNLGeneric_pid(mod->id);

    // There will be either 3 or 4 elements in this msg
    struct iovec iov[4] = {
      { .iov_base = &nlh,  .iov_len = sizeof(nlh) },
      { .iov_base = &ge,   .iov_len = sizeof(ge) },
      { .iov_base = &attr[0], .iov_len = sizeof(struct nlattr) },
      { .iov_base = &attr[1], .iov_len = sizeof(struct nlattr) },
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
				 struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = (2 + fl) };
    return sendmsg(mdata->nl_sock, &msg, 0);
  }

  /*_________________---------------------------__________________
    _________________    configure_DROPMON      __________________
    -----------------___________________________------------------
  */

  static void configure_DROPMON(EVMod *mod)
  {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    setState(mod, HSP_DROPMON_STATE_CONFIGURE);
    uint8_t alertMode = NET_DM_ALERT_MODE_PACKET;
    uint32_t truncLen = SFL_DEFAULT_HEADER_SIZE; // TODO: parameter? Write to notifier too?
    uint32_t queueLen = HSP_DROPMON_QUEUE; // TODO: parameter?
    // This control will fail if the feed has already been configured and started externally.
    // TODO: set these in one message?
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
      case CTRL_ATTR_HDRSIZE:
	mdata->headerSize = *(uint32_t *)attr_datap;
	EVDebug(mod, 1, "generic family headerSize: %u", mdata->headerSize); 
	break;
      case CTRL_ATTR_MAXATTR:
	mdata->maxAttr = *(uint32_t *)attr_datap;
	EVDebug(mod, 1, "generic family maxAttr: %u", mdata->maxAttr);
	break;
      case CTRL_ATTR_OPS:
	EVDebug(mod, 1, "generic family OPS");
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
	      EVDebug(mod, 1, "multicast group: %s", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(uint32_t *)grp_attr_datap;
	      EVDebug(mod, 1, "multicast group id: %u", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(mdata->state == HSP_DROPMON_STATE_GET_FAMILY
	     && grp_name
	     && grp_id == NET_DM_GRP_ALERT) {
	    EVDebug(mod, 1, "found group %s=%u", grp_name, grp_id);
	    mdata->group_id = grp_id;
	    // could go ahead and run configure_DROPMON, start_DROPMON
	    // here, but want that logic to be down in evt_tick() so
	    // just set the state and breathe for a moment:
	    setState(mod, HSP_DROPMON_STATE_GOT_GROUP);
	  }
	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	EVDebug(mod, 1, "attr type: %u (nested=%u) len: %u",
		attr->nla_type,
		attr->nla_type & NLA_F_NESTED,
		attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }

  static SFLNotifier *getSFlowNotifier(EVMod *mod, uint32_t ifIndex) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLNotifier search = { };
    SFL_DS_SET(search.dsi, 0, ifIndex, 0);
    SFLNotifier *notifier = UTHashGet(mdata->notifiers, &search);
    if(!notifier) {
      notifier = sfl_agent_addNotifier(sp->agent, &search.dsi);
      sfl_notifier_set_sFlowEsReceiver(notifier, HSP_SFLOW_RECEIVER_INDEX);
      UTHashAdd(mdata->notifiers, notifier);
    }
    return notifier;
  }

  /*_________________---------------------------__________________
    _________________      hideDrop             __________________
    -----------------___________________________------------------
  */

  static bool hideDrop(EVMod *mod, char *dropStr) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if((dropStr
	&& regexec(sp->dropmon.hide_regex, dropStr, 0, NULL, 0) == 0)) {
      EVDebug(mod, 4, "hw drop (%s) hidden by regex\n", dropStr);
      return YES;
    }
    return NO;
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
    EVDebug(mod, 3, "netlink (type=%u) CMD = %u", nlh->nlmsg_type, genl->cmd);
    
    // sFlow strutures to fill in
    SFLEvent_discarded_packet discard = { .reason = SFLDrop_unknown };
    SFLFlow_sample_element hdrElem = { .tag=SFLFLOW_HEADER };
    SFLFlow_sample_element fnElem = { .tag=SFLFLOW_EX_FUNCTION };
    SFLFlow_sample_element hwElem = { .tag=SFLFLOW_EX_HW_TRAP };
    SFLFlow_sample_element rnElem = { .tag=SFLFLOW_EX_LINUX_REASON };
    
    // and some parameters to pick up for cross-check below
    uint32_t trunc_len=0;
    uint32_t orig_len=0;
    uint16_t skb_protocol=0;
    char *hw_group=NULL;
    char *hw_name=NULL;
    char *sw_symbol=NULL;
    char *reason=NULL;

    // increment counter for threshold check
    mdata->totalDrops_thisTick++;
    
    struct nlattr *attr = (struct nlattr *)(msg + GENL_HDRLEN);
    int len = msglen - GENL_HDRLEN;
    while(UTNLA_OK(attr, len)) {

      u_char *datap = UTNLA_DATA(attr);
      int datalen = UTNLA_PAYLOAD(attr);
      
      if(EVDebug(mod, 4, NULL)) {
	u_char hex[1024];
	printHex(datap, datalen, hex, 1023, YES);
	EVDebug(mod, 4, "nla_type=%u, datalen=%u, payload=%s", attr->nla_type, datalen, hex);
      }

      bool nested = attr->nla_type & NLA_F_NESTED;
      int attributeType = attr->nla_type & ~NLA_F_NESTED;
      switch(attributeType) {
      case NET_DM_ATTR_ALERT_MODE:
	EVDebug(mod, 4, "u8=ALERT_MODE=%u", *(uint8_t *)datap);
	// enum net_dm_alert_mode NET_DM_ALERT_MODE_PACKET == 1
	// TODO: what to do if not packet?
	break;
      case NET_DM_ATTR_PC:
	EVDebug(mod, 4, "u64=PC=0x%"PRIx64, *(uint64_t *)datap);
	break;
      case NET_DM_ATTR_SYMBOL:
	EVDebug(mod, 4, "string=ATTR_SYMBOL=%s", datap);
	sw_symbol = (char *)datap;
	break;
      case NET_DM_ATTR_IN_PORT:
	EVDebug(mod, 4, "nested=IN_PORT");
	if(!nested) {
	  EVDebug(mod, 4, "forcing NET_DM_ATTR_IN_PORT to be interpreted as nested attribute");
	  nested = YES;
	}
	if(nested) {
	  struct nlattr *port_attr = (struct nlattr *)datap;
	  int port_len = datalen;
	  while(UTNLA_OK(port_attr, port_len)) {
	    switch(port_attr->nla_type) {
	    case NET_DM_ATTR_PORT_NETDEV_IFINDEX:
	      EVDebug(mod, 4, "u32=NETDEV_IFINDEX=%u", *(uint32_t *)UTNLA_DATA(port_attr));
	      discard.input = *(uint32_t *)UTNLA_DATA(port_attr);
	      break;
	    case NET_DM_ATTR_PORT_NETDEV_NAME:
	      EVDebug(mod, 4, "string=NETDEV_NAME=%s", (char *)UTNLA_DATA(port_attr));
	      break;
	    }
	    port_attr = UTNLA_NEXT(port_attr, port_len);
	  }
	}
	break;
      case NET_DM_ATTR_TIMESTAMP:
	EVDebug(mod, 4, "u64=TIMESTAMP=%"PRIu64, *(uint64_t *)datap);
	break;
      case NET_DM_ATTR_PROTO:
	skb_protocol = *(uint16_t *)datap;
	EVDebug(mod, 4, "u16=PROTO=0x%04x", skb_protocol);
	// This is the skb->protocol field e.g. 0x0800 for IP.
	// Local only packet with have all-zeros smac and dmac.
	// When unused buffers are freed (e.g. in skb_queue_purge())
	// they appear here with PROTO==0. Those we choose to ignore.
	break;
      case NET_DM_ATTR_PAYLOAD:
	EVDebug(mod, 4, "PAYLOAD");
	hdrElem.flowType.header.header_length = datalen;
	hdrElem.flowType.header.header_bytes = datap;
	hdrElem.flowType.header.stripped = 4;
	break;
      case NET_DM_ATTR_PAD:
	EVDebug(mod, 4, "PAD");
	break;
      case NET_DM_ATTR_TRUNC_LEN:
	EVDebug(mod, 4, "u32=TRUNC_LEN=%u", *(uint32_t *)datap);
	trunc_len = *(uint32_t *)datap;
	break;
      case NET_DM_ATTR_ORIG_LEN:
	EVDebug(mod, 4, "u32=ORIG_LEN=%u", *(uint32_t *)datap);
	orig_len = *(uint32_t *)datap;
	break;
      case NET_DM_ATTR_QUEUE_LEN:
	EVDebug(mod, 4, "u32=QUEUE_LEN=%u", *(uint32_t *)datap);
	break;
      case NET_DM_ATTR_STATS:
	EVDebug(mod, 4, "nested=ATTR_STATS");
	break;
      case NET_DM_ATTR_HW_STATS:
	EVDebug(mod, 4, "nested=HW_STATS");
	break;
      case NET_DM_ATTR_ORIGIN:
	EVDebug(mod, 4, "u16=ORIGIN=%u", *(uint16_t *)datap);
	break;
      case NET_DM_ATTR_HW_TRAP_GROUP_NAME:
	EVDebug(mod, 4, "string=TRAP_GROUP_NAME=%s", datap);
	hw_group = (char *)datap;
	break;
      case NET_DM_ATTR_HW_TRAP_NAME:
	EVDebug(mod, 4, "string=TRAP_NAME=%s", datap);
	hw_name = (char *)datap;
	break;
      case NET_DM_ATTR_HW_ENTRIES:
	EVDebug(mod, 4, "nested=HW_ENTRIES");
	break;
      case NET_DM_ATTR_HW_ENTRY:
	EVDebug(mod, 4, "nested=HW_ENTRY");
	break;
      case NET_DM_ATTR_HW_TRAP_COUNT:
	EVDebug(mod, 4, "u32=SW_DROPS=%u", *(uint32_t *)datap);
	break;
      case NET_DM_ATTR_SW_DROPS:
	EVDebug(mod, 4, "flag=SW_DROPS");
	break;
      case NET_DM_ATTR_HW_DROPS:
	EVDebug(mod, 4, "flag=HW_DROPS");
	break;
      case NET_DM_ATTR_REASON:
	EVDebug(mod, 4, "string=REASON=%s", datap);
	reason = (char *)datap;
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

    // cross check: protocol
    if(!hdrElem.flowType.header.header_protocol)
      hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;

    // look up drop point - allowing fallback if muliple attrs were supplied
    HSPDropPoint *dp = NULL;
    if(reason)
      dp = getDropPoint_rn(mod, reason);
    if((dp == NULL
	|| dp->reason == SFLDrop_unknown)
       && hw_name)
      dp = getDropPoint_hw(mod, hw_group, hw_name);
    if((dp == NULL
	|| dp->reason == SFLDrop_unknown)
       && sw_symbol)
      dp = getDropPoint_sw(mod, sw_symbol);
    
    if(dp == NULL
       || dp->reason == -1
       || skb_protocol == 0) {
      // this one not considered a packet-drop, so ignore it.
      EVDebug(mod, 4, "trap not considered a drop. Ignoring.");
      return;
    }
    
    EVDebug(mod, 1, "found dropPoint %s reason_code=%u", dp->dropPoint, dp->reason);

    if(sp->dropmon.hide_regex_str) {
      if(hideDrop(mod, hw_name)
	 || hideDrop(mod, sw_symbol)
	 || hideDrop(mod, reason))
	return;
    }
    
    // fill in discard reason
    discard.reason = dp->reason;

    // apply rate-limit
    if(mdata->quota <= 0) {
      EVDebug(mod, 2, "rate-limit (%u/sec) exceeded. Dropping drop", sp->dropmon.limit);
      mdata->noQuota++;
      sp->telemetry[HSP_TELEMETRY_EVENT_SAMPLES_SUPPRESSED]++;
      return;
    }
    else
      --mdata->quota;

    // expose rate-limiting to collector
    discard.drops = mdata->noQuota;

    // look up notifier
    // We can just use one datasource for this (0:0) - especially since the
    // input and output fields may not be limited stricting to phyical ports
    SFLNotifier *notifier = getSFlowNotifier(mod, 0);

    // enforce notifier limit on header size
    if (hdrElem.flowType.header.header_length > notifier->sFlowEsMaximumHeaderSize)
    hdrElem.flowType.header.header_length = notifier->sFlowEsMaximumHeaderSize;

    SFLADD_ELEMENT(&discard, &hdrElem);

    // include raw strings too.  Helpful for debugging or if the
    // curated sFlow drop code does not capture a new trap.
    if(hw_name) {
      hwElem.flowType.hw_trap.group.str = hw_group;
      hwElem.flowType.hw_trap.group.len = my_strlen(hw_group);
      hwElem.flowType.hw_trap.trap.str = hw_name;
      hwElem.flowType.hw_trap.trap.len = my_strlen(hw_name);
      SFLADD_ELEMENT(&discard, &hwElem);
    }
    if(sw_symbol) {
      fnElem.flowType.function.symbol.str = sw_symbol;
      fnElem.flowType.function.symbol.len = my_strlen(sw_symbol);
      SFLADD_ELEMENT(&discard, &fnElem);
    }
    if(reason) {
      rnElem.flowType.linux_reason.reason.str = reason;
      rnElem.flowType.linux_reason.reason.len = my_strlen(reason);
      SFLADD_ELEMENT(&discard, &rnElem);
    }

    HSPPendingEvtSample es = { .notifier = notifier, .discard = &discard };
    if(mdata->evt_intf_es)
      EVEventTx(mod, mdata->evt_intf_es, &es, sizeof(es));
    if(es.suppress) {
      sp->telemetry[HSP_TELEMETRY_EVENT_SAMPLES_SUPPRESSED]++;
    }
    else {
      sfl_notifier_writeEventSample(notifier, &discard);
      sp->telemetry[HSP_TELEMETRY_EVENT_SAMPLES]++;
    }

    // first successful event confirms we are up and running
    if(mdata->state == HSP_DROPMON_STATE_START)
      setState(mod, HSP_DROPMON_STATE_RUN);
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
      EVDebug(mod, 4, "readNetlink_DROPMON - msg = %d bytes", numbytes);
      struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
      while(NLMSG_OK(nlh, numbytes)){
	if(nlh->nlmsg_type == NLMSG_DONE)
	  break;
	if(nlh->nlmsg_type == NLMSG_ERROR){
	  struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	  if(err_msg->error == 0) {
	    EVDebug(mod, 4, "received Netlink ACK");
	  }
	  else {
	    // TODO: parse NLMSGERR_ATTR_OFFS to get offset?  Might be helpful
	    EVDebug(mod, 4, "state %u: error in netlink message: %d : %s",
		    mdata->state,
		    err_msg->error,
		    strerror(-err_msg->error));
	    if(mdata->state == HSP_DROPMON_STATE_CONFIGURE
	       || mdata->state == HSP_DROPMON_STATE_START)
	      mdata->feedControlErrors++;
	  }
	  break;
	}
	processNetlink(mod, nlh);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }

    // This should have advanced the state past GET_FAMILY
    if(mdata->state == HSP_DROPMON_STATE_GET_FAMILY) {
      EVDebug(mod, 1, "failed to get family details - wait before trying again");
      setState(mod, HSP_DROPMON_STATE_WAIT);
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

    if(mdata->dropmon_disabled)
      return;

    EVDebug(mod, 1, "evt_config_changed configured=%s", mdata->dropmon_configured ? "YES" : "NO");
    
    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    if(sp->sFlowSettings->dropLimit_set) {
      // dynamic override of dropLimit
      sp->dropmon.limit = sp->sFlowSettings->dropLimit;
      if(sp->dropmon.limit > 0) {
	// dropLimit was set to positive integer in SONiC or DNS-SD.
	// This implies that we should activate the feed even if dropmon.start is currently off,
	// but we still assume that hardware DROPMON activation happens elsewhere.
	// TODO: We may have to revisit this if our activation of sw drops here
	// obstructs that activation of hw drops elsewhere.
	EVDebug(mod, 1, "limit set dynamically=%u => start=YES", sp->dropmon.limit);
	sp->dropmon.start = YES;
	sp->dropmon.sw = YES;
	sp->dropmon.rn = YES;
	sp->dropmon.hw_passive = YES;
      }
    }

    if(mdata->dropmon_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    // DROPMON group is set, so open the netfilter socket while we are still root
    mdata->nl_sock = UTNLGeneric_open(mod->id);
    if(mdata->nl_sock > 0) {
      // increase socket receiver buffer size
      UTSocketRcvbuf(mdata->nl_sock, HSP_DROPMON_RCVBUF);
      // and submit for polling
      mdata->nl_evsock = EVBusAddSocket(mod,
					mdata->packetBus,
					mdata->nl_sock,
					readNetlink_DROPMON,
					NULL);
      // kick off with the family lookup request
      getFamily_DROPMON(mod);
    }

    mdata->dropmon_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    stopMonitoring         __________________
    -----------------___________________________------------------
  */

  static void stopMonitoring(EVMod *mod) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->dropmon.start) {
      // turn off the feed - but only if it looks like we were the ones
      // that turned it on in the first place.
      // TODO: may want to confirm that none of the parameters were
      // changed under our feet too?
      if(mdata->feedControlErrors > 0) {
	EVDebug(mod, 1, "detected feed-control errors: %u", mdata->feedControlErrors);
	EVDebug(mod, 1, "assume external control - not stopping feed");
      }
      else {
	EVDebug(mod, 1, "graceful shutdown: turning off feed");
	start_DROPMON(mod, NO, sp->dropmon.sw, sp->dropmon.hw);
      }
    }
    if(mdata->nl_evsock) {
      EVSocketClose(mod, mdata->nl_evsock, YES);
      mdata->nl_evsock = NULL;
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(mdata->dropmon_disabled)
      return;

    // check circuit-breaker threshold
    if(sp->dropmon.max
       && mdata->totalDrops_thisTick > sp->dropmon.max) {
      EVDebug(mod, 0, "threshold exceeded (%u > %u): turning off feed",
	    mdata->totalDrops_thisTick,
	    sp->dropmon.max);
      stopMonitoring(mod);
      mdata->dropmon_disabled = YES;
    }
    // reset for next second
    mdata->totalDrops_thisTick = 0;

    // when rate-limit is below 10 we refresh quota here
    if(sp->dropmon.limit < 10)
      mdata->quota = sp->dropmon.limit;
    
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
    case HSP_DROPMON_STATE_GOT_GROUP:
      // got group id, now join
      // if dropmon.start is off we assume the feed is
      // externally configured and go straight to waiting for data.
      if(joinGroup_DROPMON(mod))
	setState(mod,
		 sp->dropmon.start
		 ? HSP_DROPMON_STATE_JOIN_GROUP
		 : HSP_DROPMON_STATE_RUN);
      else {
	EVDebug(mod, 1, "failed to join group - wait before trying again");
	setState(mod, HSP_DROPMON_STATE_WAIT);
	mdata->retry_countdown = HSP_DROPMON_WAIT_RETRY_S;
      }
      break;
    case HSP_DROPMON_STATE_JOIN_GROUP:
      // joined group, now configure
      configure_DROPMON(mod);
      break;
    case HSP_DROPMON_STATE_CONFIGURE:
      // wating for configure response - which may be a
      // failure if the channel was already configured externally.
      // TODO: should probably wait for answer before ploughing
      // ahead with this start_DROPMON call.
      start_DROPMON(mod, YES, sp->dropmon.sw, sp->dropmon.hw);
      break;
    case HSP_DROPMON_STATE_START:
      // waiting for start response
      break;
    case HSP_DROPMON_STATE_RUN:
      // got at least one sample
      break;
    case HSP_DROPMON_STATE_STOP:
      break;
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_deci               __________________
    -----------------___________________________------------------
  */

  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(mdata->dropmon_disabled)
      return;

    // when rate-limit is above 10 we refresh quota here
    if(sp->dropmon.limit >= 10)
      mdata->quota = sp->dropmon.limit / 10;
  }

  /*_________________---------------------------__________________
    _________________    evt_final              __________________
    -----------------___________________________------------------
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;

    if(mdata->dropmon_disabled)
      return;

    stopMonitoring(mod);
  }
  
  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
    TODO: should we use a separate thread (bus) for this so that it
    can be more indenpendent of the packet sampling?
  */

  void mod_dropmon(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_DROPMON));
    HSP_mod_DROPMON *mdata = (HSP_mod_DROPMON *)mod->data;
    if(sp->dropmon.start)
      retainRootRequest(mod, "need CAP_NET_ADMIN to start drop-monitor netlink feed.");
    mdata->dropPoints_hw = UTHASH_NEW(HSPDropPoint, dropPoint, UTHASH_SKEY);
    mdata->dropPoints_sw = UTHASH_NEW(HSPDropPoint, dropPoint, UTHASH_SKEY);
    mdata->dropPoints_rn = UTHASH_NEW(HSPDropPoint, dropPoint, UTHASH_SKEY);
    mdata->dropPatterns_hw = UTArrayNew(UTARRAY_DFLT);
    mdata->dropPatterns_sw = UTArrayNew(UTARRAY_DFLT);
    mdata->dropPatterns_rn = UTArrayNew(UTARRAY_DFLT);
    mdata->notifiers = UTHASH_NEW(SFLNotifier, dsi, UTHASH_DFLT);
    loadDropPoints(mod);
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_DECI), evt_deci);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, EVEVENT_FINAL), evt_final);
    mdata->evt_intf_es = EVGetEvent(mdata->packetBus, HSPEVENT_INTF_EVENT_SAMPLE);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
