/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include "regex.h" // for switchport detection
#define HSP_DEFAULT_SWITCHPORT_REGEX "^swp[0-9s]+$"
#define HSP_DENT_TC_PROG  "/sbin/tc"

  typedef struct _HSP_mod_DENT {
    EVBus *pollBus;
  } HSP_mod_DENT;

  /*_________________-------------------------------__________________
    _________________   setSwitchPortSamplingRates  __________________
    -----------------_______________________________------------------
    return YES = hardware/kernel sampling configured OK
  */

  static int execOutputLine(void *magic, char *line) {
    myDebug(1, "execOutputLine: %s", line);
    return YES;
  }

  static bool setSamplingRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t logGroup, uint32_t sampling_n, int sampling_dirn) {
    // examples:
    // tc filter add dev eth0 ingress matchall skip_sw action sample rate 1000 group 1
    // tc filter del dev eth0 ingress
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
    if(niostate->switchPort == NO
       || niostate->loopback
       || niostate->bond_master)
      return NO;

    bool sampling_ok = NO;
    niostate->sampling_n = sampling_n;
    if(sampling_n != niostate->sampling_n_set) {
      UTStringArray *cmdline = strArrayNew();
      strArrayAdd(cmdline, HSP_DENT_TC_PROG);
#define HSP_MAX_TOK_LEN 16
      strArrayAdd(cmdline, "filter");
      strArrayAdd(cmdline, sampling_n == 0 ? "del" : "add");
      strArrayAdd(cmdline, "dev");
      strArrayAdd(cmdline, adaptor->deviceName);
      // there doesn't seem to be an "egress" option, so its
      // either "ingress" or we get both.
      if(sampling_dirn == HSP_DIRN_IN)
	strArrayAdd(cmdline, "ingress");
      if(sampling_n > 0) {
	strArrayAdd(cmdline, "matchall");
	if(sp->dent.sw == NO)
	  strArrayAdd(cmdline, "skip_sw");
	strArrayAdd(cmdline, "action");
	strArrayAdd(cmdline, "sample");
	strArrayAdd(cmdline, "rate");
	char srate[HSP_MAX_TOK_LEN];
	snprintf(srate, HSP_MAX_TOK_LEN, "%u", sampling_n);
	strArrayAdd(cmdline, srate);
	strArrayAdd(cmdline, "group");
	char loggrp[HSP_MAX_TOK_LEN];
	snprintf(loggrp, HSP_MAX_TOK_LEN, "%u", sp->psample.group);
	strArrayAdd(cmdline, loggrp);
      }
      myDebug(1, "setSamplingRate(%s) %u -> %u",
	      adaptor->deviceName,
	      niostate->sampling_n_set,
	      sampling_n);
#define HSP_MAX_EXEC_LINELEN 1024
      char outputLine[HSP_MAX_EXEC_LINELEN];
      int status;
      if(myExec(NULL, strArray(cmdline), execOutputLine, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
	if(WEXITSTATUS(status) != 0) {
	  myLog(LOG_ERR, "myExec(%s) exitStatus=%d",
		HSP_DENT_TC_PROG,
		WEXITSTATUS(status));
	}
	else {
	  myDebug(1, "setSamplingRate(%s) succeeded", adaptor->deviceName);
	  // hardware or kernel sampling was successfully configured (or cleared)
	  niostate->sampling_n_set = sampling_n;
	  sampling_ok = YES;
	}
      }
      else {
	myLog(LOG_ERR, "myExec() calling %s failed (adaptor=%s)",
	      strArrayAt(cmdline, 0),
	      adaptor->deviceName);
      }
      strArrayFree(cmdline);
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
	  myDebug(1, "new switchport detected: %s", adaptor->deviceName);
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
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    markSwitchPorts(mod);
    uint32_t channel = sp->psample.group;
    int sampling_dirn = sp->sFlowSettings->samplingDirection;

    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      uint32_t sampling_n = lookupPacketSamplingRate(adaptor, sp->sFlowSettings);
      if(setSamplingRate(mod, adaptor, channel, sampling_n, sampling_dirn))
	sp->hardwareSampling = YES;
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
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL)
      return;
    // turn off any hardware sampling that we enabled
    uint32_t channel = sp->psample.group;
    int sampling_dirn = sp->sFlowSettings->samplingDirection;
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(niostate->switchPort
	 && niostate->sampling_n_set != 0)
	setSamplingRate(mod, adaptor, channel, 0, sampling_dirn);
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

    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed); 
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_FINAL), evt_final);
 }

#if defined(__cplusplus)
} /* extern "C" */
#endif
