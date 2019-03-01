/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include "regex.h" // for switchport detection
#define HSP_DEFAULT_SWITCHPORT_REGEX "^swp[0-9s]+$"
#define HSP_CUMULUS_SWITCHPORT_CONFIG_PROG  "/usr/lib/cumulus/portsamp"

  typedef struct _HSP_mod_CUMULUS {
    EVBus *pollBus;
    SFLCounters_sample_element bcmElem;
  } HSP_mod_CUMULUS;

  /*_________________---------------------------__________________
    _________________    readOneIntFile         __________________
    -----------------___________________________------------------
    function to read an ASCII integer from a file
  */

  static int readOneIntFile(char *path, uint64_t *p_ans) {
    int found = 0;
    FILE *intFile = fopen(path, "r");
    if(intFile) {
      found = fscanf(intFile, "%"SCNu64, p_ans);
      fclose(intFile);
    }
    return found;
  }

  /*_________________---------------------------__________________
    _________________    readBroadcomCounters   __________________
    -----------------___________________________------------------
    Called to get latest counters
  */

  int readBroadcomCounters(HSP *sp, SFLBCM_tables *bcm) {
    uint64_t scratch64;
    uint64_t mode;

#define HSP_BCM_FILES "/cumulus/switchd/run/"

    struct stat statBuf;
    if(stat(HSP_BCM_FILES, &statBuf) == -1) {
      // don't include this structure at all if none of the data is there,
      // which happens on "VX" virtual switches.
      return NO;
    }

    // hosts
    if(readOneIntFile(HSP_BCM_FILES "route_info/host/count", &scratch64)) bcm->bcm_host_entries = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "route_info/host/max", &scratch64)) bcm->bcm_host_entries_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "route_info/host/count_v4", &scratch64)) bcm->bcm_ipv4_neighbors = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "route_info/host/count_v6", &scratch64)) bcm->bcm_ipv6_neighbors = scratch64;

    // routing tables
    if(!readOneIntFile(HSP_BCM_FILES "route_info/route/mode", &mode)) {
      myDebug(1, "cannot read route-table mode");
    }
    if(mode == 1) {
      // (v4-v6, long-v6)
      if(readOneIntFile(HSP_BCM_FILES "route_info/route/count_0", &scratch64)) bcm->bcm_ipv4_ipv6_entries = scratch64;
      if(readOneIntFile(HSP_BCM_FILES "route_info/route/max_0", &scratch64)) bcm->bcm_ipv4_ipv6_entries_max = scratch64;

      if(readOneIntFile(HSP_BCM_FILES "route_info/route/count_1", &scratch64)) bcm->bcm_long_ipv6_entries = scratch64;
      if(readOneIntFile(HSP_BCM_FILES "route_info/route/max_1", &scratch64)) bcm->bcm_long_ipv6_entries_max = scratch64;
    }
    else if(mode == 2) {
      // (v4, v6)
      if(readOneIntFile(HSP_BCM_FILES "route_info/route/count_0", &scratch64)) bcm->bcm_ipv4_entries = scratch64;
      if(readOneIntFile(HSP_BCM_FILES "route_info/route/max_0", &scratch64)) bcm->bcm_ipv4_entries_max = scratch64;

      if(readOneIntFile(HSP_BCM_FILES "route_info/route/count_1", &scratch64)) bcm->bcm_ipv6_entries = scratch64;
      if(readOneIntFile(HSP_BCM_FILES "route_info/route/max_1", &scratch64)) bcm->bcm_ipv6_entries_max = scratch64;
    }

    // total routes
    if(readOneIntFile(HSP_BCM_FILES "route_info/route/count_total", &scratch64)) bcm->bcm_total_routes = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "route_info/route/max_total", &scratch64)) bcm->bcm_total_routes_max = scratch64;

    // ECMP nexthops
    if(readOneIntFile(HSP_BCM_FILES "route_info/ecmp_nh/count", &scratch64)) bcm->bcm_ecmp_nexthops = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "route_info/ecmp_nh/max", &scratch64)) bcm->bcm_ecmp_nexthops_max = scratch64;

    // MACs
    if(readOneIntFile(HSP_BCM_FILES "route_info/mac/count", &scratch64)) bcm->bcm_mac_entries = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "route_info/mac/max", &scratch64)) bcm->bcm_mac_entries_max = scratch64;

    // ACL ingress (entries, counters, meters, slices)
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/entries", &scratch64)) bcm->bcm_acl_ingress_entries = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/entries_total", &scratch64)) bcm->bcm_acl_ingress_entries_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/counters", &scratch64)) bcm->bcm_acl_ingress_counters = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/counters_total", &scratch64)) bcm->bcm_acl_ingress_counters_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/meters", &scratch64)) bcm->bcm_acl_ingress_meters = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/meters_total", &scratch64)) bcm->bcm_acl_ingress_meters_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/slices", &scratch64)) bcm->bcm_acl_ingress_slices = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/ingress/slices_total", &scratch64)) bcm->bcm_acl_ingress_slices_max = scratch64;

    // ACL egress (entries, counters, meters, slices)
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/entries", &scratch64)) bcm->bcm_acl_egress_entries = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/entries_total", &scratch64)) bcm->bcm_acl_egress_entries_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/counters", &scratch64)) bcm->bcm_acl_egress_counters = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/counters_total", &scratch64)) bcm->bcm_acl_egress_counters_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/meters", &scratch64)) bcm->bcm_acl_egress_meters = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/meters_total", &scratch64)) bcm->bcm_acl_egress_meters_max = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/slices", &scratch64)) bcm->bcm_acl_egress_slices = scratch64;
    if(readOneIntFile(HSP_BCM_FILES "acl_info/egress/slices_total", &scratch64)) bcm->bcm_acl_egress_slices_max = scratch64;

    return YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_host_cs            __________________
    -----------------___________________________------------------
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_CUMULUS *mdata = (HSP_mod_CUMULUS *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    memset(&mdata->bcmElem, 0, sizeof(mdata->bcmElem));
    mdata->bcmElem.tag = SFLCOUNTERS_BCM_TABLES;
    if(readBroadcomCounters(sp, &mdata->bcmElem.counterBlock.bcm_tables)) {
      SFLADD_ELEMENT(cs, &mdata->bcmElem);
    }
  }

  /*_________________-------------------------------__________________
    _________________   setSwitchPortSamplingRates  __________________
    -----------------_______________________________------------------
    return YES = hardware/kernel sampling configured OK
    return NO  = hardware/kernel sampling not set - assume 1:1 on PSAMPLE/NFLOG/ULOG
  */

  static int execOutputLine(void *magic, char *line) {
    myDebug(1, "execOutputLine: %s", line);
    return YES;
  }

  static bool setSamplingRate(EVMod *mod, SFLAdaptor *adaptor, uint32_t logGroup, uint32_t sampling_n, int sampling_dirn) {
    HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
    if(niostate->switchPort == NO
       || niostate->loopback
       || niostate->bond_master)
      return NO;

    bool hw_sampling = NO;
    niostate->sampling_n = sampling_n;
    if(niostate->sampling_n != niostate->sampling_n_set) {
      UTStringArray *cmdline = strArrayNew();
      strArrayAdd(cmdline, HSP_CUMULUS_SWITCHPORT_CONFIG_PROG);
      // usage:  <prog> <interface> <ingress-rate> <egress-rate> <logGroup>
#define HSP_MAX_TOK_LEN 16
      strArrayAdd(cmdline, NULL); // placeholder for port name in slot 1
      strArrayAdd(cmdline, "0");  // placeholder for ingress sampling
      strArrayAdd(cmdline, "0");  // placeholder for egress sampling
      char loggrp[HSP_MAX_TOK_LEN];
      snprintf(loggrp, HSP_MAX_TOK_LEN, "%u", logGroup);
      strArrayAdd(cmdline, loggrp);
#define HSP_MAX_EXEC_LINELEN 1024
      char outputLine[HSP_MAX_EXEC_LINELEN];
      myDebug(1, "setSamplingRate(%s) %u -> %u",
	      adaptor->deviceName,
	      niostate->sampling_n_set,
	      niostate->sampling_n);
      strArrayInsert(cmdline, 1, adaptor->deviceName);
      char srate[HSP_MAX_TOK_LEN];
      snprintf(srate, HSP_MAX_TOK_LEN, "%u", niostate->sampling_n);
      if(sampling_dirn & HSP_DIRN_IN)
	strArrayInsert(cmdline, 2, srate); // ingress
      if(sampling_dirn & HSP_DIRN_OUT)
	strArrayInsert(cmdline, 3, srate); // egress
      int status;
      if(myExec(NULL, strArray(cmdline), execOutputLine, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
	if(WEXITSTATUS(status) != 0) {
	  myLog(LOG_ERR, "myExec(%s) exitStatus=%d so assuming PSAMPLE/NFLOG/ULOG is 1:1",
		HSP_CUMULUS_SWITCHPORT_CONFIG_PROG,
		WEXITSTATUS(status));
	}
	else {
	  myDebug(1, "setSamplingRate(%s) succeeded", adaptor->deviceName);
	  // hardware or kernel sampling was successfully configured
	  niostate->sampling_n_set = niostate->sampling_n;
	  hw_sampling = YES;
	}
      }
      else {
	myLog(LOG_ERR, "myExec() calling %s failed (adaptor=%s)",
	      strArrayAt(cmdline, 0),
	      strArrayAt(cmdline, 1));
      }
      strArrayFree(cmdline);
    }

    return hw_sampling;
  }

  /*_________________---------------------------__________________
    _________________   markSwitchPorts         __________________
    -----------------___________________________------------------
  */

  static void markSwitchPorts(EVMod *mod)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->cumulus.swp_regex_str == NULL) {
      // pattern not specified in config, so compile the default
      sp->cumulus.swp_regex_str = HSP_DEFAULT_SWITCHPORT_REGEX;
      sp->cumulus.swp_regex = UTRegexCompile(HSP_DEFAULT_SWITCHPORT_REGEX);
      assert(sp->cumulus.swp_regex);
    }

    // use pattern to mark the switch ports
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(!niostate->switchPort) {
	if(regexec(sp->cumulus.swp_regex, adaptor->deviceName, 0, NULL, 0) == 0) {
	  myDebug(1, "new switchport detected: %s", adaptor->deviceName);
	  niostate->switchPort = YES;
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    sampling_channel       __________________
    -----------------___________________________------------------
  */

  static uint32_t sampling_channel(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    EVMod *psampleMod = EVGetModule(mod, "mod_psample");
    EVMod *nflogMod = EVGetModule(mod, "mod_nflog");


    if (psampleMod && psampleMod->libHandle)
      return sp->psample.group;
    else if (nflogMod && nflogMod->libHandle)
      return sp->nflog.group
    else
      return sp->ulog.group;
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
    uint32_t channel = sampling_channel(mod);
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
    uint32_t channel = sampling_channel(mod);
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

  void mod_cumulus(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_CUMULUS));
    HSP_mod_CUMULUS *mdata = (HSP_mod_CUMULUS *)mod->data;

    // ask to retain root privileges
    retainRootRequest(mod, "needed to set Cumulus switch-port sampling rates");

    // we know there are no 32-bit counters
    sp->nio_polling_secs = 0;

    // TODO: should we try to cluster the counters a little?
    // sp->syncPollingInterval = 5;

    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed); 
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_FINAL), evt_final);
 }

#if defined(__cplusplus)
} /* extern "C" */
#endif
