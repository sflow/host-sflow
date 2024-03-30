/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  typedef enum { SFVSSTATE_INIT=0,
		 SFVSSTATE_READCONFIG,
		 SFVSSTATE_READCONFIG_FAILED,
		 SFVSSTATE_SYNC,
		 SFVSSTATE_SYNC_SEARCH,
		 SFVSSTATE_SYNC_FOUND,
		 SFVSSTATE_SYNC_DESTROY,
		 SFVSSTATE_SYNC_FAILED,
		 SFVSSTATE_SYNC_OK,
		 SFVSSTATE_END,
  } EnumSFVSState;

  static const char *SFVSStateNames[] = {
    "INIT",
    "READCONFIG",
    "READCONFIG_FAILED",
    "SYNC",
    "SYNC_SEARCH",
    "SYNC_FOUND",
    "SYNC_DESTROY",
    "SYNC_FAILED",
    "SYNC_OK",
    "END"
  };

#define SFVS_SEPARATORS " \t\r\n="
#define SFVS_QUOTES "'\" \t\r\n"
// SFVS_MAX LINE LEN must be enough to hold the whole list of targets
#define SFVS_MAX_LINELEN 1024
#define SFVS_MAX_COLLECTORS 10

  typedef struct _SFVSCollector {
    char *ip;
    uint16_t port;
    uint16_t priority;
  } SFVSCollector;

  typedef struct _SFVSConfig {
    int error;
    uint32_t sampling_n;
    uint32_t polling_secs;
    uint32_t header_bytes;
    char *agent_ip;
    char *agent_dev;
    uint32_t num_collectors;
    SFVSCollector collectors[SFVS_MAX_COLLECTORS];
    UTStringArray *targets;
    char *targetStr;
  } SFVSConfig;

#define SFVS_OVS_CMD "/usr/bin/ovs-vsctl"
// new sflow id must start with '@'
#define SFVS_NEW_SFLOW_ID "@newsflow"

  typedef struct _HSP_mod_OVS {
    EnumSFVSState state;
    time_t tick;
    SFVSConfig config;
    UTStringArray *cmd;
    UTStringArray *extras;
    char *bridge;
    char *sflowUUID;
    int cmdFailed;
    int useAtVar;
    int usingAtVar;
    int usedAtVarOK;
    int ovs10;
  } HSP_mod_OVS;

  /*_________________---------------------------__________________
    _________________     setState              __________________
    -----------------___________________________------------------
  */

  static void setState(EVMod *mod, EnumSFVSState state) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    EVDebug(mod, 1, "state -> %s", SFVSStateNames[state]);
    mdata->state = state;
  }

  /*_________________---------------------------__________________
    _________________      formatTargets        __________________
    -----------------___________________________------------------
    turn the collectors list into the targets string array and
    formatted targetStr.
  */

  static void formatTargets(EVMod *mod) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    strArrayReset(mdata->config.targets);
    for(int i = 0; i < mdata->config.num_collectors; i++) {
      char target[SFVS_MAX_LINELEN];
      sprintf(target, "%s:%u",
	      mdata->config.collectors[i].ip,
	      mdata->config.collectors[i].port);
      strArrayAdd(mdata->config.targets, target);
    }
    strArraySort(mdata->config.targets);
    if(mdata->config.targetStr) my_free(mdata->config.targetStr);
    mdata->config.targetStr = strArrayStr(mdata->config.targets, "[", "\"", ", ", "]");
  }

  /*_________________---------------------------__________________
    _________________      resetConfig          __________________
    -----------------___________________________------------------
  */

  static void resetConfig(SFVSConfig *cfg) {
    cfg->error = NO;
    cfg->sampling_n = 0;
    cfg->polling_secs = 0;
    cfg->header_bytes = SFL_DEFAULT_HEADER_SIZE;
    setStr(&cfg->agent_ip, NULL);
    setStr(&cfg->agent_dev, NULL);
    cfg->num_collectors = 0;
    strArrayReset(cfg->targets);
    setStr(&cfg->targetStr, NULL);
  }

  /*_________________---------------------------__________________
    _________________      readConfig           __________________
    -----------------___________________________------------------

    used to have to read from /etc/hsflowd.auto here, but now
    we can just extract the essential config in the form we want
    it straight from the main config.
  */

  static bool readConfig(EVMod *mod)  {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    resetConfig(&mdata->config);

    if(sp->sFlowSettings == NULL)
      return NO;

    mdata->config.sampling_n = sp->sFlowSettings->samplingRate;
    mdata->config.polling_secs = sp->actualPollingInterval;
    mdata->config.header_bytes = sp->sFlowSettings->headerBytes;
    char ipbuf[51];
    SFLAddress_print(&sp->agentIP, ipbuf, 50);
    setStr(&mdata->config.agent_ip, ipbuf);
    setStr(&mdata->config.agent_dev, sp->agentDevice);
    for(HSPCollector *coll = sp->sFlowSettings->collectors; coll; coll = coll->nxt) {
      if(mdata->config.num_collectors == SFVS_MAX_COLLECTORS) {
	myLog(LOG_ERR, "OVS: MAX collectors exceeded");
      }
      else {
	uint32_t i = mdata->config.num_collectors++;
	SFLAddress_print(&coll->ipAddr, ipbuf, 50);
	setStr(&mdata->config.collectors[i].ip, ipbuf);
	mdata->config.collectors[i].port = coll->udpPort;
	mdata->config.collectors[i].priority = 0;
      }
    }
    // turn the collectors list into the targets string
    formatTargets(mod);
    return YES;
  }

  /*_________________---------------------------__________________
    _________________     stripQuotes           __________________
    -----------------___________________________------------------
    strip runs of these chars from the beginning and end -
    but don't worry about matching them up one-for-one.  Be
    careful to only do this with stack-allocated strings.
  */

  static char *stripQuotes(char *str, char *quoteChars) {
    if(str) {
      str += strspn(str, quoteChars);
      size_t len = strlen(str);
      while(len > 0 && strchr(quoteChars, str[len-1])) {
	str[--len] = '\0';
      }
    }
    return str;
  }

  /*_________________---------------------------__________________
    _________________     syncOVS - utils       __________________
    -----------------___________________________------------------
  */

  static void addOvsArg(EVMod *mod, char *arg) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    strArrayAdd(mdata->cmd, arg);
  }

  static void addOvsVarEqVal(EVMod *mod, char *ovsvar, char *valstr) {
    uint32_t bytes = strlen(ovsvar) + 1 + strlen(valstr) + 1;
    char *setting = my_calloc(bytes);
    snprintf(setting, bytes, "%s=%s", ovsvar, valstr);
    addOvsArg(mod, setting);
    my_free(setting);
  }

  static void addOvsVarEqVal_int(EVMod *mod, char *ovsvar, uint32_t intval) {
    char valstr[16];
    snprintf(valstr, 16, "%u", intval);
    addOvsVarEqVal(mod, ovsvar, valstr);
  }

  static void addSFlowSetting(EVMod *mod, char *ovsvar, char *valstr) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    addOvsArg(mod, "--");
    addOvsArg(mod, "set");
    addOvsArg(mod, "sflow");
    addOvsArg(mod, mdata->sflowUUID);
    addOvsVarEqVal(mod, ovsvar, valstr);
  }

  static void addSFlowSetting_int(EVMod *mod, char *ovsvar, uint32_t intval) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    addOvsArg(mod, "--");
    addOvsArg(mod, "set");
    addOvsArg(mod, "sflow");
    addOvsArg(mod, mdata->sflowUUID);
    addOvsVarEqVal_int(mod, ovsvar, intval);
  }

  static void addBridgeSetting(EVMod *mod, char *ovsvar, char *valstr) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    addOvsArg(mod, "--");
    addOvsArg(mod, "set");
    addOvsArg(mod, "bridge");
    addOvsArg(mod, mdata->bridge);
    addOvsVarEqVal(mod, ovsvar, valstr);
  }

  static void addDestroySFlow(EVMod *mod, char *uuidStr) {
    addOvsArg(mod, "--");
    addOvsArg(mod, "destroy");
    addOvsArg(mod, "sflow");
    addOvsArg(mod, uuidStr);
  }

  static void addCreateSFlow(EVMod *mod) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    addOvsArg(mod, "--");
    if(mdata->useAtVar) {
      addOvsArg(mod, "--id=" SFVS_NEW_SFLOW_ID);
    }
    mdata->usingAtVar = mdata->useAtVar;
    addOvsArg(mod, "create");
    addOvsArg(mod, "sflow");
    addOvsVarEqVal(mod, "agent", mdata->config.agent_dev);
    addOvsVarEqVal_int(mod, "header", mdata->config.header_bytes);
    addOvsVarEqVal_int(mod, "polling", mdata->config.polling_secs);
    addOvsVarEqVal_int(mod, "sampling", mdata->config.sampling_n);
    addOvsVarEqVal(mod, "targets", mdata->config.targetStr);
  }

  static void logCmd(EVMod *mod) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    char *cmdstr = strArrayStr(mdata->cmd, "<", NULL, " ", ">");
    myLog(LOG_INFO, "cmd: %s\n", cmdstr);
    my_free(cmdstr);
  }

  static void resetCmd(EVMod *mod) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    strArrayReset(mdata->cmd);
    strArrayAdd(mdata->cmd, SFVS_OVS_CMD);

  }

  static void resetExtras(EVMod *mod) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    strArrayReset(mdata->extras);
  }

  /*_________________---------------------------__________________
    _________________     syncOVS - callbacks   __________________
    -----------------___________________________------------------
  */

  int sFlowList(void *magic, char *line)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    // expect lines of form <var> : <val>
    int varlen = strcspn(line, ":");
    if(varlen >= strlen(line)) {
      myLog(LOG_ERR, "expected <var> : <val>, but got <%s>", line);
      return NO;
    }
    line[varlen] = '\0';
    char *var = stripQuotes(line, SFVS_QUOTES);
    char *val = stripQuotes(line + varlen + 1, SFVS_QUOTES);
    EVDebug(mod, 1, "sFlowList> %s=%s", var, val);
    if(strcmp(var, "_uuid") == 0) {
      switch(mdata->state) {
      case SFVSSTATE_SYNC_SEARCH:
	EVDebug(mod, 1, "found sflow uuid %s", val);
	setStr(&mdata->sflowUUID, val);
	setState(mod, SFVSSTATE_SYNC_FOUND);
	break;
      case SFVSSTATE_SYNC_FOUND:
      case SFVSSTATE_SYNC_DESTROY:
	setState(mod, SFVSSTATE_SYNC_DESTROY);
	EVDebug(mod, 1, "found extra sflow uuid %s", val);
	strArrayAdd(mdata->extras, val);
	break;
      default:
	myLog(LOG_ERR, "sFlowList: unexpected state %s", SFVSStateNames[mdata->state]);
	setState(mod, SFVSSTATE_END);
	return NO;
      }
    }
    else if (mdata->state == SFVSSTATE_SYNC_FOUND) {
      // we have adopted an existing sFlow object.  This is the one
      // we will keep. All others will be destroyed. Here we check in
      // case any of the individual parameters need to be changed too.
      if(strcmp(var, "agent") == 0) {
	char quoted[SFVS_MAX_LINELEN];
	snprintf(quoted, SFVS_MAX_LINELEN, "\"%s\"", val);
	if(my_strequal(val, mdata->config.agent_dev) == NO
	   && my_strequal(quoted, mdata->config.agent_dev) == NO) {
	  addSFlowSetting(mod, "agent", mdata->config.agent_dev);
	}
      }
      else if(strcmp(var, "header") == 0) {
	uint32_t n = strtol(val, NULL, 0);
	if(n != mdata->config.header_bytes) {
	  addSFlowSetting_int(mod, "header", mdata->config.header_bytes);
	}
      }
      else if(strcmp(var, "polling") == 0) {
	uint32_t n = strtol(val, NULL, 0);
	if(n != mdata->config.polling_secs) {
	  addSFlowSetting_int(mod, "polling", mdata->config.polling_secs);
	}
      }
      else if(strcmp(var, "sampling") == 0) {
	uint32_t n = strtol(val, NULL, 0);
	if(n != mdata->config.sampling_n) {
	  addSFlowSetting_int(mod, "sampling", mdata->config.sampling_n);
	}
      }
      else if(strcmp(var, "targets") == 0) {
	// the spaces between elements in the array are a nuisance, because they
	// could go away someday and break any scheme that relies on a simple
	// string-compare. So parse it into comma-separated tokens.
	// single-threaded, so we can just use strtok(3)
	UTStringArray *array = strArrayNew();
	val = stripQuotes(val, "[]");
	char *delim = ", ";
	for(char *tok = strtok(val, delim); tok != NULL; tok=strtok(NULL, delim)) {
	  strArrayAdd(array, stripQuotes(tok, SFVS_QUOTES));
	}
	strArraySort(array);
	if(!strArrayEqual(array, mdata->config.targets)) {
	  addSFlowSetting(mod, "targets", mdata->config.targetStr);
	}
	strArrayFree(array);
      }
    }
    return YES;
  }

  int bridgeGetSFlow(void *magic, char *line)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    char *uuid = stripQuotes(line, SFVS_QUOTES);
    if(uuid && strcmp(uuid, mdata->sflowUUID) != 0) {
      // doesn't match
      EVDebug(mod, 1, "setting sflow for bridge %s", mdata->bridge);
      addBridgeSetting(mod, "sflow", mdata->sflowUUID);
    }
    return YES;
  }

  int bridgeList(void *magic, char *line)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    // we're looking for the lines that have "name : <bridge-name>"
    // or specifically the sequence:
    // name
    // <whitespace>
    // :
    // <whitespace>
    // <bridge-name>
    // sscanf with format string "name%*[\t ]:%*[\t ]%s" works, but
    // assumes that the whitespace is not empty.  I don't think we
    // can necessarily assume that (?)
    char bridgeName[SFVS_MAX_LINELEN];
    if(sscanf(line, "name%*[\t ]:%*[\t ]%s", bridgeName) == 1) {
      // copy the bridge name
      char *br = stripQuotes(bridgeName, SFVS_QUOTES);
      EVDebug(mod, 1, "bridgeList> %s", br);
      if(br && (br[0] != '\0')) {
	setStr(&mdata->bridge, br);
	// now run a command to check (and possible change) the bridge sFlow setting
	char *bridge_get_sflow_cmd[] = { SFVS_OVS_CMD, "get", "bridge", br, "sflow", NULL };
	char line[SFVS_MAX_LINELEN];
	if(myExec(mod, bridge_get_sflow_cmd, bridgeGetSFlow, line, SFVS_MAX_LINELEN, NULL) == NO) return NO;
      }
    }
    return YES;
  }

  int submitCreate(void *magic, char *line)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    char *uuid = stripQuotes(line, SFVS_QUOTES);
    if(!uuid)
      return NO;
    if(my_strlen(uuid) < 32)
      return NO;
    char binUUID[16];
    if(parseUUID(uuid, binUUID) == NO)
      return NO;

    setStr(&mdata->sflowUUID, uuid);
    return YES;
  }

  int submitChanges(void *magic, char *line)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    EVDebug(mod, 0, "sumbitChanges: %s", line);
    // if we get anything at all here, then it probably means something didn't work - but
    // return YES anway so we can log the whole error message if it spans multiple
    // lines.  Note that with the --id=@tok settings we do now see the UUID of the newly
    // created sFlow object here.  Hence the change from LOG_ERR to LOG_INFO. It would
    // be a little awkward to change myExec to separate stdout and stderr, so this is the
    // best we can do without making bigger changes.
    mdata->cmdFailed = YES;
    if(mdata->usingAtVar && mdata->ovs10 && mdata->usedAtVarOK == NO) {
      EVDebug(mod, 1, "command with --id=@tok failed and version is 1.0.*, so turn off --id=@tok");
      mdata->useAtVar = NO;
    }
    return YES;
  }

  int readVersion(void *magic, char *line)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    // the compulsory use of --id==@tok appeared between 1.0 and 1.1.0pre1
    // but before that it was not supported at all.  The format of this
    // version string may change at any time,  so the safest way to test
    // this is to assume that we can use --id==@tok unless we see a very
    // specific version string:
    if(memcmp(line, "ovs-vsctl (Open vSwitch) 1.0", 28) == 0) {
      EVDebug(mod, 1, "detected ovs-vsctl version 1.0 - may turn off use of --id=@tok");
      mdata->ovs10 = YES;
    }
    return NO; // only want the first line
  }

  /*_________________---------------------------__________________
    _________________        syncOVS            __________________
    -----------------___________________________------------------
  */

  static int syncOVS(EVMod *mod)
  {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    resetCmd(mod);
    resetExtras(mod);
    char line[SFVS_MAX_LINELEN];

    EVDebug(mod, 1, "==== ovs-vsctl version ====");
    char *version_cmd[] = { SFVS_OVS_CMD, "--version", NULL};
    // don't abort if this fails: readVersion returns NO as an easy way
    // to only see the first line. (Line number should really be supplied to
    // callback from myExec)
    mdata->ovs10 = NO; // assume newer version
    mdata->usingAtVar = NO;
    myExec((void *)mod, version_cmd, readVersion, line, SFVS_MAX_LINELEN, NULL);
    // adapt if OVS is upgraded under our feet
    if(mdata->ovs10 == NO) mdata->useAtVar = YES;
    if(mdata->config.error
       || mdata->config.num_collectors == 0
       || (mdata->config.sampling_n == 0 && mdata->config.polling_secs == 0)) {
      // no config or no targets or no sampling/polling - clear everything
      EVDebug(mod, 1, "no config found: clearing all OVS sFlow config");
      setStr(&mdata->sflowUUID, "[]");
      setState(mod, SFVSSTATE_SYNC_DESTROY);
    }
    else {
      // got config - assume here that we're going to create a new
      // sflow object, but if we find one we'll adopt it
      setStr(&mdata->sflowUUID, SFVS_NEW_SFLOW_ID);
      setState(mod, SFVSSTATE_SYNC_SEARCH);
    }
    EVDebug(mod, 1, "==== list sflow ====");
    char *list_sflow_cmd[] = { SFVS_OVS_CMD, "list", "sflow", NULL };
    if(myExec((void *)mod, list_sflow_cmd, sFlowList, line, SFVS_MAX_LINELEN, NULL) == NO) return NO;

    if(mdata->useAtVar) {
      // we can add the create at the end
    }
    else {
      // create new sFlow object if there were none found (i.e. if
      // the sflowUUID has not changed from the initial setting we
      // gave it.
      if(strcmp(SFVS_NEW_SFLOW_ID, mdata->sflowUUID) == 0) {
	addCreateSFlow(mod);
	logCmd(mod);
	strArrayAdd(mdata->cmd, NULL); // for execve(2)
	if(myExec((void *)mod, strArray(mdata->cmd), submitCreate, line, SFVS_MAX_LINELEN, NULL) == NO) return NO;
	resetCmd(mod);
      }
    }

    // make sure every bridge is using this sFlow entry
    EVDebug(mod, 1, "==== list bridge ====");
    char *list_bridge_cmd[] = { SFVS_OVS_CMD, "list", "bridge", NULL};
    if(myExec((void *)mod, list_bridge_cmd, bridgeList, line, SFVS_MAX_LINELEN, NULL) == NO) return NO;

    // now it's safe to delete any extras that we found
    for(int ex = strArrayN(mdata->extras); --ex >= 0; ) {
      addDestroySFlow(mod, strArrayAt(mdata->extras, ex));
    }

    if(mdata->useAtVar) {
      // create new sFlow object if there were none found (i.e. if
      // the sflowUUID has not changed from the initial setting we
      // gave it.
      if(strcmp(SFVS_NEW_SFLOW_ID, mdata->sflowUUID) == 0) {
	addCreateSFlow(mod);
      }
    }

    // if we decided to make any changes, submit them now
    mdata->cmdFailed = NO;
    if(strArrayN(mdata->cmd) > 1) {
      logCmd(mod);
      strArrayAdd(mdata->cmd, NULL); // for execve(2)
      if(myExec((void *)mod, strArray(mdata->cmd), submitChanges, line, SFVS_MAX_LINELEN, NULL) == NO) return NO;
      if(mdata->usingAtVar && mdata->cmdFailed == NO) {
        // remember that it worked at least once
        mdata->usedAtVarOK = YES;
      }
    }
    return mdata->cmdFailed ? NO : YES;
  }

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    setState(mod, SFVSSTATE_READCONFIG);
  }

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    mdata->tick++;

    if(mdata->tick >= 60 && mdata->state != SFVSSTATE_READCONFIG_FAILED) {
      // a minute has passed, and we are not still waiting for a valid config
      mdata->tick = 0;
      EVDebug(mod, 1, "minute passed - check sync");
      setState(mod, SFVSSTATE_SYNC);
    }

    switch(mdata->state) {

    case SFVSSTATE_READCONFIG:
      if(readConfig(mod)) setState(mod, SFVSSTATE_SYNC);
      else setState(mod, SFVSSTATE_READCONFIG_FAILED);
      break;

    case SFVSSTATE_SYNC:
      {
	if(syncOVS(mod)) setState(mod, SFVSSTATE_SYNC_OK);
	else setState(mod, SFVSSTATE_SYNC_FAILED);
      }
      break;

    case SFVSSTATE_INIT:
    case SFVSSTATE_READCONFIG_FAILED:
    case SFVSSTATE_SYNC_SEARCH:
    case SFVSSTATE_SYNC_FOUND:
    case SFVSSTATE_SYNC_DESTROY:
    case SFVSSTATE_SYNC_FAILED:
    case SFVSSTATE_SYNC_OK:
    case SFVSSTATE_END:
      break;
    }
  }


  /*_________________---------------------------__________________
    _________________    evt_final              __________________
    -----------------___________________________------------------
    Graceful shutdown - turn OVS sFlow off
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;
    EVDebug(mod, 1, "graceful shutdown: turning off OVS sFlow");
    mdata->config.num_collectors = 0;
    syncOVS(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_ovs(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_OVS));
    HSP_mod_OVS *mdata = (HSP_mod_OVS *)mod->data;

    retainRootRequest(mod, "needed by mod_ovs to call ovs_vsctl and connect to OVSDB");

    mdata->cmd = strArrayNew();
    mdata->extras = strArrayNew();
    mdata->config.targets = strArrayNew();
    mdata->ovs10 = NO;
    mdata->useAtVar = YES;
    setState(mod, SFVSSTATE_READCONFIG);

    // register call-backs
    EVBus *pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_FINAL), evt_final);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
