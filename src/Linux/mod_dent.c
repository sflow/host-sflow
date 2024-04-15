/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include "regex.h"
#define HSP_DEFAULT_SWITCHPORT_REGEX "^swp[0-9s]+$"
#define HSP_DENT_TC_PROG  "/sbin/tc"
#define HSP_DENT_TC_QDISC_REGEX "qdisc clsact"
#define HSP_MAX_EXEC_LINELEN 1024

  typedef struct _HSP_mod_DENT {
    EVBus *pollBus;
    regex_t *qdisc_regex;
    uint32_t ingress_grp;
    uint32_t egress_grp;
  } HSP_mod_DENT;

  /*_________________-------------------------------__________________
    _________________       noQDdisc                __________________
    -----------------_______________________________------------------
  */

  static int execOutputNoQDisc(void *magic, char *line) {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_DENT *mdata = (HSP_mod_DENT *)mod->data;
    EVDebug(mod, 1, "execOutputNoQDisc: %s", line);
    if(regexec(mdata->qdisc_regex, line, 0, NULL, 0) == 0) {
      EVDebug(mod, 1, "qdisc detected: %s", line);
      return NO; // stop reading (signal that we found it)
    }
    return YES; // keep looking
  }

  static bool noQDisc(EVMod *mod, SFLAdaptor *adaptor) {
    // examples:
    // tc qdisc show dev eth0
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_DENT_TC_PROG);
    strArrayAdd(cmdline, "qdisc");
    strArrayAdd(cmdline, "show");
    strArrayAdd(cmdline, "dev");
    strArrayAdd(cmdline, adaptor->deviceName);

    char outputLine[HSP_MAX_EXEC_LINELEN];
    int status=0;
    bool missing = myExec(mod, strArray(cmdline), execOutputNoQDisc, outputLine, HSP_MAX_EXEC_LINELEN, &status);
    if(WEXITSTATUS(status) != 0) {
      myLog(LOG_ERR, "noQDisc(%s) exitStatus=%d",
	    HSP_DENT_TC_PROG,
	    WEXITSTATUS(status));
    }
    strArrayFree(cmdline);
    return missing;
  }

  /*_________________-------------------------------__________________
    _________________       addQDdisc               __________________
    -----------------_______________________________------------------
  */

  static int execOutputAddQDisc(void *magic, char *line) {
    EVMod *mod = (EVMod *)magic;
    EVDebug(mod, 1, "execOutputAddQDisc: %s", line);
    return YES;
  }

  static bool addQDisc(EVMod *mod, SFLAdaptor *adaptor) {
    // examples:
    // tc qdisc add dev eth0 clsact
    bool added_ok = NO;
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_DENT_TC_PROG);
    strArrayAdd(cmdline, "qdisc");
    strArrayAdd(cmdline, "add");
    strArrayAdd(cmdline, "dev");
    strArrayAdd(cmdline, adaptor->deviceName);
    strArrayAdd(cmdline, "clsact");

    if(EVDebug(mod, 1, NULL)) {
      char *cmd = strArrayStr(cmdline, "<", NULL, " ", ">");
      EVDebug(mod, 1, "addQDisc(%s) cmdLine: %s", adaptor->deviceName, cmd);
      my_free(cmd);
    }

    char outputLine[HSP_MAX_EXEC_LINELEN];
    int status=0;
    if(myExec(mod, strArray(cmdline), execOutputAddQDisc, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
      if(WEXITSTATUS(status) != 0) {
	myLog(LOG_ERR, "addQDisc(%s) exitStatus=%d",
	      HSP_DENT_TC_PROG,
	      WEXITSTATUS(status));
      }
      else {
	EVDebug(mod, 1, "addQDisc(%s) succeeded", adaptor->deviceName);
	added_ok = YES;
      }
    }
    else {
      myLog(LOG_ERR, "addQDisc() calling %s failed (adaptor=%s)",
	    strArrayAt(cmdline, 0),
	    adaptor->deviceName);
    }
    strArrayFree(cmdline);
    return added_ok;
  }


  /*_________________-------------------------------__________________
    _________________      deleteFilter             __________________
    -----------------_______________________________------------------
  */

  static int execOutputDeleteFilter(void *magic, char *line) {
    EVMod *mod = (EVMod *)magic;
    EVDebug(mod, 1, "execOutputDeleteFilter: %s", line);
    return YES;
  }

  static bool deleteFilter(EVMod *mod, SFLAdaptor *adaptor, bool egress) {
    // examples:
    // tc filter del dev eth0 ingress
    bool deleted_ok = NO;
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_DENT_TC_PROG);
    strArrayAdd(cmdline, "filter");
    strArrayAdd(cmdline, "delete");
    strArrayAdd(cmdline, "dev");
    strArrayAdd(cmdline, adaptor->deviceName);
    strArrayAdd(cmdline, egress ? "egress" : "ingress");
    char outputLine[HSP_MAX_EXEC_LINELEN];
    int status=0;
    if(myExec(mod, strArray(cmdline), execOutputDeleteFilter, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
      if(WEXITSTATUS(status) != 0) {
	myLog(LOG_ERR, "deleteFilter(%s) exitStatus=%d",
	      HSP_DENT_TC_PROG,
	      WEXITSTATUS(status));
      }
      else {
	EVDebug(mod, 1, "deleteFilter(%s) succeeded", adaptor->deviceName);
	deleted_ok = YES;
      }
    }
    else {
      myLog(LOG_ERR, "deleteFilter() calling %s failed (adaptor=%s)",
	    strArrayAt(cmdline, 0),
	    adaptor->deviceName);
    }
    strArrayFree(cmdline);
    return deleted_ok;
  }


  /*_________________-------------------------------__________________
    _________________          setRate              __________________
    -----------------_______________________________------------------
    return YES = hardware/kernel sampling configured OK
  */

  static int execOutputSetRate(void *magic, char *line) {
    EVMod *mod = (EVMod *)magic;
    EVDebug(mod, 1, "execOutputSetRate: %s", line);
    return YES;
  }

  static bool setRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t logGroup, uint32_t sampling_n, bool egress) {
    // examples:
    // tc qdisc add dev eth0 clsact
    // tc filter add dev eth0 ingress pref 1 matchall skip_sw action sample rate 1000 group 1 trunc 128
    HSP *sp = (HSP *)EVROOTDATA(mod);
    bool sampling_ok = NO;
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_DENT_TC_PROG);
    strArrayAdd(cmdline, "filter");
    strArrayAdd(cmdline, "add");
    strArrayAdd(cmdline, "dev");
    strArrayAdd(cmdline, adaptor->deviceName);
    strArrayAdd(cmdline, egress ? "egress" : "ingress");
    if(!egress) {
      // On ingress, sampling should happen before ACLs, so ask for preference/priority 1.
      // (On egress any ACLs should apply first, so allow the sampling step to be added
      // in the default manner at the end of the chain).
      strArrayAdd(cmdline, "pref");
      strArrayAdd(cmdline, "1");
    }
    strArrayAdd(cmdline, "matchall");
    if(sp->dent.sw == NO)
      strArrayAdd(cmdline, "skip_sw");
    strArrayAdd(cmdline, "action");
    strArrayAdd(cmdline, "sample");
    strArrayAdd(cmdline, "rate");
#define HSP_MAX_TOK_LEN 16
    char srate[HSP_MAX_TOK_LEN];
    snprintf(srate, HSP_MAX_TOK_LEN, "%u", sampling_n);
    strArrayAdd(cmdline, srate);
    strArrayAdd(cmdline, "group");
    char loggrp[HSP_MAX_TOK_LEN];
    snprintf(loggrp, HSP_MAX_TOK_LEN, "%u", logGroup);
    strArrayAdd(cmdline, loggrp);
    strArrayAdd(cmdline, "trunc");
    char hdrBytes[HSP_MAX_TOK_LEN];
    snprintf(hdrBytes, HSP_MAX_TOK_LEN, "%u", sp->sFlowSettings_file->headerBytes);
    strArrayAdd(cmdline, hdrBytes);
    // TODO: not sure what the optional "index" option does here
    if(EVDebug(mod, 1, NULL)) {
      char *cmd = strArrayStr(cmdline, "<", NULL, " ", ">");
      EVDebug(mod, 1, "setRate(%s) cmdLine: %s", adaptor->deviceName, cmd);
      my_free(cmd);
    }
    strArrayAdd(cmdline, "continue");
    char outputLine[HSP_MAX_EXEC_LINELEN];
    int status=0;
    if(myExec(mod, strArray(cmdline), execOutputSetRate, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
      if(WEXITSTATUS(status) != 0) {
	myLog(LOG_ERR, "setRate(%s) prog=%s exitStatus=%d",
	      adaptor->deviceName,
	      HSP_DENT_TC_PROG,
	      WEXITSTATUS(status));
      }
      else {
	EVDebug(mod, 1, "setRate(%s) succeeded", adaptor->deviceName);
	// hardware/kernel sampling was successfully configured
	sampling_ok = YES;
      }
    }
    else {
      myLog(LOG_ERR, "setRate(%s) myExec %s failed",
	    adaptor->deviceName,
	    HSP_DENT_TC_PROG);
    }
    strArrayFree(cmdline);
    return sampling_ok;
  }

  /*_________________-------------------------------__________________
    _________________       setSamplingRate         __________________
    -----------------_______________________________------------------
    return YES = hardware/kernel sampling configured OK
  */

  static bool setSamplingRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t logGroup, uint32_t sampling_n, bool egress) {
    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
    if(niostate->switchPort == NO
       || niostate->loopback
       || niostate->bond_master)
      return NO;

    bool sampling_ok = NO;
    niostate->sampling_n = sampling_n;
    if(sampling_n == 0)
      deleteFilter(mod, adaptor, egress);
    else {
      // make sure the parent qdisc is available - creating if necessary
      EVDebug(mod, 1, "setSamplingRate(%s %s) %u -> %u",
	      adaptor->deviceName,
	      egress ? "egress" : "ingress",
	      niostate->sampling_n_set,
	      sampling_n);
      if(noQDisc(mod, adaptor))
	addQDisc(mod, adaptor);
      if(setRate(mod, adaptor, logGroup, sampling_n, egress)) {
	niostate->sampling_n_set = sampling_n;
	sampling_ok = YES;
      }
    }
    return sampling_ok;
  }

  /*_________________---------------------------__________________
    _________________   markSwitchPorts         __________________
    -----------------___________________________------------------
  */

  static void markSwitchPorts(EVMod *mod)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->dent.swp_regex_str == NULL) {
      // pattern not specified in config, so use the default
      sp->dent.swp_regex_str = HSP_DEFAULT_SWITCHPORT_REGEX;
    }
    
    if(!sp->dent.swp_regex) {
      sp->dent.swp_regex = UTRegexCompile(sp->dent.swp_regex_str);
      if(!sp->dent.swp_regex) {
	myLog(LOG_ERR, "switchport regex compilation failed: %s", sp->dent.swp_regex_str);
	exit(EXIT_FAILURE);
      }
    }
    // use pattern to mark the switch ports
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(!niostate->switchPort) {
	if(regexec(sp->dent.swp_regex, adaptor->deviceName, 0, NULL, 0) == 0) {
	  EVDebug(mod, 1, "new switchport detected: %s", adaptor->deviceName);
	  niostate->switchPort = YES;
	}
      }
    }
  }
    
  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DENT *mdata = (HSP_mod_DENT *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    markSwitchPorts(mod);

    // if egress sampling is enabled, mod_psample expects it to be
    // on the next group channel up.  Capture that convention here
    // and remember the group numbers so we can back out the settings
    // on graceful exit.
    if(sp->psample.ingress)
      mdata->ingress_grp = sp->psample.group;
    if(sp->psample.egress)
      mdata->egress_grp = sp->psample.group + 1;

    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      uint32_t sampling_n = lookupPacketSamplingRate(adaptor, sp->sFlowSettings);
      if(sampling_n != niostate->sampling_n_set) {
	if(mdata->ingress_grp
	   && setSamplingRate(mod, adaptor, mdata->ingress_grp, sampling_n, NO))
	  sp->hardwareSampling = YES;
	if(mdata->egress_grp
	   && setSamplingRate(mod, adaptor, mdata->egress_grp, sampling_n, YES))
	  sp->hardwareSampling = YES;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    evt_config_changed(mod, evt, data, dataLen);
  }

  /*_________________---------------------------__________________
    _________________        evt_final          __________________
    -----------------___________________________------------------
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DENT *mdata = (HSP_mod_DENT *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL)
      return;
    // turn off any hardware sampling that we enabled
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(niostate->switchPort
	 && niostate->sampling_n_set != 0) {
	if(mdata->ingress_grp)
	  setSamplingRate(mod, adaptor, mdata->ingress_grp, 0, NO);
	if(mdata->egress_grp)
	  setSamplingRate(mod, adaptor, mdata->egress_grp, 0, YES);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_dent(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_DENT));
    HSP_mod_DENT *mdata = (HSP_mod_DENT *)mod->data;

    // ask to retain root privileges
    retainRootRequest(mod, "needed to set Dent switch-port sampling rates with tc");

    // we know there are no 32-bit counters
    sp->nio_polling_secs = 0;

    // TODO: should we try to cluster the counters a little?
    // sp->syncPollingInterval = 5;

    mdata->qdisc_regex = UTRegexCompile(HSP_DENT_TC_QDISC_REGEX);

    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed); 
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_FINAL), evt_final);
 }

#if defined(__cplusplus)
} /* extern "C" */
#endif
