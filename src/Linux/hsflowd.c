/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#define HSP_TELEMETRY_NAMES 1
#include "hsflowd.h"

#include "cpu_utils.h"
#include "cJSON.h"

#if (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 13)
#include "malloc.h" // for malloc_info()
#endif

#ifdef GPROF
#include "gperftools/profiler.h"
#include "gperftools/heap-profiler.h"
#endif

  // globals - easier for signal handler
  HSP HSPSamplingProbe;
  int exitStatus = EXIT_SUCCESS;
  FILE *f_crash = NULL;

  static void openCollectorSockets(HSP *sp, HSPSFlowSettings *settings);
  static bool installSFlowSettings(HSP *sp, HSPSFlowSettings *settings);
  static bool updatePollingInterval(HSP *sp);
  static void openLogFile(HSP *sp);
  
  /*_________________---------------------------__________________
    _________________     agent callbacks       __________________
    -----------------___________________________------------------
  */

  static void *agentCB_alloc(void *magic, SFLAgent *agent, size_t bytes)  {
    return my_calloc(bytes);
  }

  static int agentCB_free(void *magic, SFLAgent *agent, void *obj)  {
    my_free(obj);
    return 0;
  }

  static void agentCB_error(void *magic, SFLAgent *agent, char *msg)  {
    myLog(LOG_ERR, "sflow agent error: %s", msg);
  }

  /*_________________---------------------------__________________
    _________________ sFlow datagram callbacks  __________________
    -----------------___________________________------------------
  */
  
  static uint64_t sfdgCB_now_mS(void *magic) {
    return EVBusRunningTime_mS(EVCurrentBus());
  }

  static int sfdgCB_hook_counter_sample(void *magic, SFDBuf *dbuf) {
    SFLReceiver *receiver = (SFLReceiver *)magic;
    SFLAgent *agent = receiver->agent;
    HSP *sp = (HSP *)agent->magic;
    // copy to the packetBus
    // Note that this requires sizeof(SFDBuf) < PIPE_BUF, or it will not be sent by evbus:eventTxPipe()
    EVEventTx(sp->rootModule, EVGetEvent(sp->packetBus, HSPEVENT_XDR_SAMPLE), dbuf, sizeof(SFDBuf));
    // That copies it into the pipe, so consume it completely here.
    SFDSampleFree(receiver->sfdg, dbuf);
    return 1;
  }

  static void sfdgCB_send(void *magic, struct iovec *iov, int iovcnt)  {
    SFLReceiver *receiver = (SFLReceiver *)magic;
    SFLAgent *agent = receiver->agent;
    HSP *sp = (HSP *)agent->magic;
    // note that we are relying on any new settings being installed atomically from the DNS-SD
    // thread (it's just a pointer move,  so it should be atomic).  Otherwise we would want to
    // grab sp->sync whenever we call sfl_sampler_writeFlowSample(),  because that can
    // bring us here where we read the list of collectors.
    
    if(sp->suppress_sendPkt_agentAddress
       || sp->suppress_sendPkt_waitConfig)
      return;

    if(sp->sFlowSettings == NULL)
      return;

    sp->telemetry[HSP_TELEMETRY_DATAGRAMS]++;

    for(HSPCollector *coll = sp->sFlowSettings->collectors; coll; coll=coll->nxt) {
      if(coll->socklen && coll->socket > 0) {
	struct msghdr msg = {
	  .msg_name = (struct sockaddr *)&coll->sendSocketAddr,
	  .msg_namelen = coll->socklen,
	  .msg_iov = iov,
	  .msg_iovlen = iovcnt
	};
	int result = sendmsg(coll->socket, &msg, 0);
	if(result == -1 && errno != EINTR) {
	  EVLog(60, LOG_ERR, "socket sendto error: %s", strerror(errno));
	  // We have the agent semaphore lock here, so it's safe
	  // to close and clear the socket, then set a countdown
	  // to try opening it again.
	  close(coll->socket);
	  coll->socket = 0;
	  sp->reopenCollectorSocketCountdown = HSP_RETRY_COLLECTOR_SOCKET;
	}
	else if(result == 0) {
	  EVLog(60, LOG_ERR, "socket sendto returned 0: %s", strerror(errno));
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   adaptor utils           __________________
    -----------------___________________________------------------
  */

  SFLAdaptor *nioAdaptorNew(EVMod *mod, char *dev, u_char *macBytes, uint32_t ifIndex) {
    SFLAdaptor *adaptor = adaptorNew(dev, macBytes, sizeof(HSPAdaptorNIO), ifIndex);
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    // set defaults
    nio->vlan = HSP_VLAN_ALL;
    nio->ethtool_GDRVINFO = YES;
    nio->ethtool_GLINKSETTINGS = YES;
    nio->ethtool_GSET = YES;
    nio->ethtool_GSTATS = YES;
    nio->procNetDev = YES;
    adaptor->marked = mod->id;
    return adaptor;
  }

  void adaptorAddOrReplace(UTHash *ht, SFLAdaptor *ad, char *htname) {
    SFLAdaptor *replaced = UTHashAdd(ht, ad);
    if(replaced && replaced != ad) {
      char buf1[256], buf2[256];
      myDebug(1, "adaptorAddOrReplace: %s: replacing adaptor [%s] with [%s]",
	      htname,
	      adaptorStr(replaced, buf1, 256),
	      adaptorStr(ad, buf2, 256));
      // This can happen quite commonly when two interfaces share the
      // same MAC addresses and the adaptorsByMAC hash table detects
      // the clash,  so don't free the one that was replaced.  It's
      // probably still referenced in adaptorsByIndex and adaptorsByName.
    }
  }

  SFLAdaptor *adaptorByName(HSP *sp, char *dev) {
    SFLAdaptor ad = { .deviceName = dev };
    return UTHashGet(sp->adaptorsByName, &ad);
  }

  SFLAdaptor *adaptorByMac(HSP *sp, SFLMacAddress *mac) {
    SFLAdaptor ad = { .macs[0] = (*mac) };
    return UTHashGet(sp->adaptorsByMac, &ad);
  }

  SFLAdaptor *adaptorByIndex(HSP *sp, uint32_t ifIndex) {
    SFLAdaptor ad = { .ifIndex = ifIndex };
    return UTHashGet(sp->adaptorsByIndex, &ad);
  }

  SFLAdaptor *adaptorByPeerIndex(HSP *sp, uint32_t ifIndex) {
    SFLAdaptor ad = { .peer_ifIndex = ifIndex };
    return UTHashGet(sp->adaptorsByPeerIndex, &ad);
  }

  SFLAdaptor *adaptorByIP(HSP *sp, SFLAddress *ip) {
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      if(SFLAddress_equal(ip, &adaptorNIO->ipAddr))
	return adaptor;
    }
    return NULL;
  }

  SFLAdaptor *adaptorByAlias(HSP *sp, char *alias) {
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      if(my_strequal(alias, adaptorNIO->deviceAlias))
	return adaptor;
    }
    return NULL;
  }

  static void deleteAdaptorFromHT(UTHash *ht, SFLAdaptor *ad, char *htname) {
    char buf[256];
    if(UTHashDel(ht, ad) != ad) {
      myDebug(1, "WARNING: adaptor not deleted from %s : %s", htname, adaptorStr(ad, buf, 256));
      if(debug(1))
	 adaptorHTPrint(ht, htname);
    }
  }

  void deleteAdaptor(HSP *sp, SFLAdaptor *ad, int freeFlag) {
    if(sp->allowDeleteAdaptor == NO)
      return;
    deleteAdaptorFromHT(sp->adaptorsByName, ad, "byName");
    deleteAdaptorFromHT(sp->adaptorsByIndex, ad, "byIndex");
    deleteAdaptorFromHT(sp->adaptorsByMac, ad, "byMac");
    if(ad->peer_ifIndex)
      deleteAdaptorFromHT(sp->adaptorsByPeerIndex, ad, "byPeerIndex");
    if(freeFlag) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(ad);
      if(nio->sampler)
	myDebug(1, "deleteAdaptor: adaptor %s has sFlow sampler", ad->deviceName);
      if(nio->poller)
	myDebug(1, "deleteAdaptor: adaptor %s has sFlow poller", ad->deviceName);
      if(nio->deviceAlias)
	myDebug(1, "deleteAdaptor: adaptor %s has deviceAlias", ad->deviceName);
      adaptorFree(ad);
    }
  }

  int deleteMarkedAdaptors(HSP *sp, UTHash *adaptorHT, int freeFlag) {
    int found = 0;
    SFLAdaptor *ad;
    UTHASH_WALK(adaptorHT, ad) {
      if(adaptorIsMarked(ad)) {
	deleteAdaptor(sp, ad, freeFlag);
	found++;
      }
    }
    return found;
  }

  int markAdaptors_adaptorList(EVMod *mod, SFLAdaptorList *adList) {
    int found = 0;
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(adList, ad)
      if(ad->marked == mod->id) {
	markAdaptor(ad);
	found++;
      }
    return found;
  }

  int deleteMarkedAdaptors_adaptorList(EVMod *mod, SFLAdaptorList *adList) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    int found = 0;
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(adList, ad)
      if(adaptorIsMarked(ad)) {
	deleteAdaptor(sp, ad, NO);
	found++;
      }
    return found;
  }

  char *adaptorStr(SFLAdaptor *ad, char *buf, int bufLen) {
    u_char macstr[13];
    macstr[0] = '\0';
    if(ad->num_macs) printHex(ad->macs[0].mac, 6, macstr, 13, NO);
    snprintf(buf, bufLen, "ifindex: %u peer: %u nmacs: %u mac0: %s name: %s",
	  ad->ifIndex,
	  ad->peer_ifIndex,
	  ad->num_macs,
	  macstr,
	  ad->deviceName);
    return buf;
  }

  void adaptorHTPrint(UTHash *ht, char *prefix) {
    char buf[256];
    SFLAdaptor *ad;
    UTHASH_WALK(ht, ad)
      myLog(LOG_INFO, "%s: %s", prefix, adaptorStr(ad, buf, 256));
  }

  static SFLAdaptorList *host_adaptors(HSP *sp, SFLAdaptorList *myAdaptors, int capacity)
  {
    // build the list of adaptors that are up and have non-empty MACs,
    // and are not veth connectors to peers inside containers,
    // and have not been claimed as switchPorts or VM or Container ports,
    // but stop if we hit the capacity
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      if(adaptor->peer_ifIndex == 0) {
	HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
	if(niostate->up
	   && (niostate->switchPort == NO)
	   && (niostate->vm_or_container == NO)
	   && adaptor->num_macs
	   && !isZeroMAC(&adaptor->macs[0])) {
	  if(myAdaptors->num_adaptors >= capacity) break;
	  myAdaptors->adaptors[myAdaptors->num_adaptors++] = adaptor;
	}
      }
    }
    return myAdaptors;
  }

  bool setAdaptorSpeed(HSP *sp, SFLAdaptor *adaptor, uint64_t speed, char *method)
  {
    bool changed = (speed != adaptor->ifSpeed);
    if(changed) {
      myDebug(1, "setAdaptorSpeed(%s): %s ifSpeed %"PRIu64" -> %"PRIu64,
	      method,
	      adaptor->deviceName,
	      adaptor->ifSpeed,
	      speed);
      adaptor->ifSpeed = speed;
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      nio->changed_speed = nio->changed_external = YES;
      if(sp->rootModule)
	EVEventTxAll(sp->rootModule, HSPEVENT_INTF_SPEED, &adaptor, sizeof(adaptor));
    }
    return changed;
  }

  bool setAdaptorAlias(HSP *sp, SFLAdaptor *adaptor, char *alias, char *method)
  {
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    bool changed = !my_strequal(nio->deviceAlias, alias);
    if(changed) {
      myDebug(1, "setAdaptorAlias(%s): %s alias %s -> %s",
	      method,
	      adaptor->deviceName,
	      nio->deviceAlias ?: "NULL",
	      alias ?: "NULL");
      setStr(&nio->deviceAlias, alias);
      nio->changed_alias = nio->changed_external = YES;
    }
    return changed;
  }
  
  bool setAdaptorSelectionPriority(HSP *sp, SFLAdaptor *adaptor, uint32_t priority, char *method)
  {
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    bool changed = (nio->selectionPriority != priority);
    if(changed) {
      myDebug(1, "setAdaptorSelectionPriority(%s): %s %u -> %u (changed=%s)",
	      method,
	      adaptor->deviceName,
	      nio->selectionPriority,
	      priority);
      nio->selectionPriority = priority;
    }
    return changed;
  }

  /*_________________---------------------------__________________
    _________________        local IPs          __________________
    -----------------___________________________------------------
  */

  static __thread int th_n_localIPs = 0;

  HSPLocalIP *localIPNew(SFLAddress *ipAddr, char *dev) {
    HSPLocalIP *lip = my_calloc(sizeof(HSPLocalIP));
    lip->ipAddr = *ipAddr;
    lip->devs = strArrayNew();
    th_n_localIPs++;
    return lip;
  }

  void localIPFree(HSPLocalIP *lip) {
    strArrayFree(lip->devs);
    my_free(lip);
    th_n_localIPs--;
  }

  int localIPInstances(void) {
    return th_n_localIPs;
  }

  /*_________________---------------------------__________________
    _________________   agentCB_getCounters     __________________
    -----------------___________________________------------------
  */

  static void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;

    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    if(readHidCounters(sp,
		       &hidElem.counterBlock.host_hid,
		       sp->hostname,
		       SFL_MAX_HOSTNAME_CHARS,
		       sp->os_release,
		       SFL_MAX_OSRELEASE_CHARS)) {
      SFLADD_ELEMENT(cs, &hidElem);
    }

    // host Net I/O
    SFLCounters_sample_element nioElem = { 0 };
    nioElem.tag = SFLCOUNTERS_HOST_NIO;
    if(readNioCounters(sp, &nioElem.counterBlock.host_nio, NULL, NULL)) {
      SFLADD_ELEMENT(cs, &nioElem);
    }

    // host cpu counters
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_CPU;
    if(readCpuCounters(&cpuElem.counterBlock.host_cpu)) {
      // remember speed and nprocs for other purposes
      sp->cpu_cores = cpuElem.counterBlock.host_cpu.cpu_num;
      sp->cpu_mhz = cpuElem.counterBlock.host_cpu.cpu_speed;
      SFLADD_ELEMENT(cs, &cpuElem);
    }

    // host memory counters
    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_MEM;
    if(readMemoryCounters(&memElem.counterBlock.host_mem)) {
      // remember mem_total and mem_free for other purposes
      sp->mem_total = memElem.counterBlock.host_mem.mem_total;
      sp->mem_free = memElem.counterBlock.host_mem.mem_free;
      SFLADD_ELEMENT(cs, &memElem);
    }

    // host I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_DSK;
    if(readDiskCounters(sp, &dskElem.counterBlock.host_dsk)) {
      SFLADD_ELEMENT(cs, &dskElem);
    }

    // host TCP/IP counters
    SFLCounters_sample_element ipElem = { 0 }, icmpElem = { 0 }, tcpElem = { 0 }, udpElem = { 0 };
    ipElem.tag = SFLCOUNTERS_HOST_IP;
    icmpElem.tag = SFLCOUNTERS_HOST_ICMP;
    tcpElem.tag = SFLCOUNTERS_HOST_TCP;
    udpElem.tag = SFLCOUNTERS_HOST_UDP;
    if(readTcpipCounters(sp,
			 &ipElem.counterBlock.host_ip,
			 &icmpElem.counterBlock.host_icmp,
			 &tcpElem.counterBlock.host_tcp,
			 &udpElem.counterBlock.host_udp)) {
      SFLADD_ELEMENT(cs, &ipElem);
      SFLADD_ELEMENT(cs, &icmpElem);
      SFLADD_ELEMENT(cs, &tcpElem);
      SFLADD_ELEMENT(cs, &udpElem);
    }

    SFLCounters_sample_element adaptorsElem = { 0 };
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    // collect list of host adaptors that are up, and have non-zero MACs, and
    // have not been claimed by xen, kvm or docker.
    SFLAdaptorList myAdaptors;
    SFLAdaptor *adaptors[HSP_MAX_PHYSICAL_ADAPTORS];
    myAdaptors.adaptors = adaptors;
    myAdaptors.capacity = HSP_MAX_PHYSICAL_ADAPTORS;
    myAdaptors.num_adaptors = 0;
    adaptorsElem.counterBlock.adaptors = host_adaptors(sp, &myAdaptors, HSP_MAX_PHYSICAL_ADAPTORS);
    SFLADD_ELEMENT(cs, &adaptorsElem);

    // Send the cs out to be annotated by other modules such as docker, xen, vrt and NVML
    // Note that we could use an HSPPendingCSample for this (as we do for HSP_EVENT_COUNTER_SAMPLE)
    // but so far no one seems to need a pointer to the poller object so it's not needed.
    EVEvent *evt_host_cs = EVGetEvent(sp->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE);
    EVEventTx(sp->rootModule, evt_host_cs, &cs, sizeof(cs));
    sfl_poller_writeCountersSample(poller, cs);
    sp->counterSampleQueued = YES;
    sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES]++;
  }

  /*_________________-----------------------------------__________________
    _________________   agentCB_getCounters_interface   __________________
    -----------------___________________________________------------------
  */

  void sendInterfaceCounterSample(EVMod *mod, SFLPoller *poller, SFLAdaptor *adaptor, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
    // see if we were able to discern multicast and broadcast counters
    // by polling for ethtool stats.  Be careful to use unsigned 32-bit
    // arithmetic here:
#define UNSUPPORTED_SFLOW_COUNTER32 (uint32_t)-1
    uint32_t pkts_in = adaptorNIO->nio.pkts_in;
    uint32_t pkts_out = adaptorNIO->nio.pkts_out;
    uint32_t mcasts_in =  UNSUPPORTED_SFLOW_COUNTER32;
    uint32_t mcasts_out =  UNSUPPORTED_SFLOW_COUNTER32;
    uint32_t bcasts_in =  UNSUPPORTED_SFLOW_COUNTER32;
    uint32_t bcasts_out =  UNSUPPORTED_SFLOW_COUNTER32;
    uint32_t unknown_in =  UNSUPPORTED_SFLOW_COUNTER32;
    uint32_t ifStatus = adaptorNIO->up ? (SFLSTATUS_ADMIN_UP | SFLSTATUS_OPER_UP) : 0;
    
    // more detailed counters may have been found via ethtool or equivalent:
    if(adaptorNIO->et_found & HSP_ETCTR_MC_IN) {
      mcasts_in = (uint32_t)adaptorNIO->et_total.mcasts_in;
      if(adaptorNIO->procNetDev)
	pkts_in -= mcasts_in;
    }
    if(adaptorNIO->et_found & HSP_ETCTR_BC_IN) {
      bcasts_in = (uint32_t)adaptorNIO->et_total.bcasts_in;
      if(adaptorNIO->procNetDev)
	pkts_in -= bcasts_in;
    }
    if(adaptorNIO->et_found & HSP_ETCTR_MC_OUT) {
      mcasts_out = (uint32_t)adaptorNIO->et_total.mcasts_out;
      if(adaptorNIO->procNetDev)
	pkts_out -= mcasts_out;
    }
    if(adaptorNIO->et_found & HSP_ETCTR_BC_OUT) {
      bcasts_out = (uint32_t)adaptorNIO->et_total.bcasts_out;
      if(adaptorNIO->procNetDev)
	pkts_out -= bcasts_out;
    }
    if(adaptorNIO->et_found & HSP_ETCTR_UNKN) {
      unknown_in = (uint32_t)adaptorNIO->et_total.unknown_in;
    }
    if((adaptorNIO->et_found & HSP_ETCTR_ADMIN)
       && (adaptorNIO->et_found & HSP_ETCTR_OPER)) {
      ifStatus = 0;
      if((adaptorNIO->et_last.adminStatus & 1)) ifStatus |= SFLSTATUS_ADMIN_UP;
      if((adaptorNIO->et_last.operStatus & 1)) ifStatus |= SFLSTATUS_OPER_UP;
    }
    
    if(adaptorNIO->bond_master
       || adaptorNIO->bond_master_2) {
      EVDebug(mod, 1, "bond interface status: %s=%u (ifSpeed=%"PRIu64" dirn=%u et_found=%u up=%u)",
	      adaptor->deviceName,
	      ifStatus,
	      adaptor->ifSpeed,
	      adaptor->ifDirection,
	      adaptorNIO->et_found,
	      adaptorNIO->up);
    }
    
    // generic interface counters
    SFLCounters_sample_element elem = { 0 };
    elem.tag = SFLCOUNTERS_GENERIC;
    elem.counterBlock.generic.ifIndex = poller->dsi.ds_index;
    elem.counterBlock.generic.ifType = 6; // assume ethernet
    elem.counterBlock.generic.ifSpeed = adaptor->ifSpeed;
    elem.counterBlock.generic.ifDirection = adaptor->ifDirection;
    elem.counterBlock.generic.ifStatus = ifStatus;
    elem.counterBlock.generic.ifPromiscuousMode = adaptor->promiscuous;
    elem.counterBlock.generic.ifInOctets = adaptorNIO->nio.bytes_in;
    elem.counterBlock.generic.ifInUcastPkts = pkts_in;
    elem.counterBlock.generic.ifInMulticastPkts = mcasts_in;
    elem.counterBlock.generic.ifInBroadcastPkts = bcasts_in;
    elem.counterBlock.generic.ifInDiscards = adaptorNIO->nio.drops_in;
    elem.counterBlock.generic.ifInErrors = adaptorNIO->nio.errs_in;
    elem.counterBlock.generic.ifInUnknownProtos = unknown_in;
    elem.counterBlock.generic.ifOutOctets = adaptorNIO->nio.bytes_out;
    elem.counterBlock.generic.ifOutUcastPkts = pkts_out;
    elem.counterBlock.generic.ifOutMulticastPkts = mcasts_out;
    elem.counterBlock.generic.ifOutBroadcastPkts = bcasts_out;
    elem.counterBlock.generic.ifOutDiscards = adaptorNIO->nio.drops_out;
    elem.counterBlock.generic.ifOutErrors = adaptorNIO->nio.errs_out;
    SFLADD_ELEMENT(cs, &elem);
    
    if(adaptorNIO->vm_or_container) {
#define HSP_DIRECTION_SWAP(g,f) do {				\
	uint32_t _tmp = g.ifIn ## f;				\
	g.ifIn ## f = g.ifOut ## f;				\
	g.ifOut ## f = _tmp; } while(0)
      HSP_DIRECTION_SWAP(elem.counterBlock.generic, UcastPkts);
      HSP_DIRECTION_SWAP(elem.counterBlock.generic, MulticastPkts);
      HSP_DIRECTION_SWAP(elem.counterBlock.generic, BroadcastPkts);
      HSP_DIRECTION_SWAP(elem.counterBlock.generic, Discards);
      HSP_DIRECTION_SWAP(elem.counterBlock.generic, Errors);
    }
    
    // add optional interface name struct
    SFLCounters_sample_element pn_elem = { 0 };
    pn_elem.tag = SFLCOUNTERS_PORTNAME;
    char *sFlowPortName = adaptor->deviceName;
    // It might be more elegant to splice in an alternative PORTNAME element
    // later in mod_sonic evt_cntr_sample() but there is an IFLA_IFALIAS
    // that we might someday discover via netlink and want to export as
    // the portName even on other platforms, so allow the policy to to be
    // a global flag that we test here.  For now the flag is
    // sp->sonic.setIfName but it could end up as something like "sp->portNameUseAlias".
    if(sp->sonic.setIfName
       && adaptorNIO->deviceAlias)
      sFlowPortName = adaptorNIO->deviceAlias;
    pn_elem.counterBlock.portName.portName.len = my_strlen(sFlowPortName);
    pn_elem.counterBlock.portName.portName.str = sFlowPortName;
    SFLADD_ELEMENT(cs, &pn_elem);
    
    // possibly include LACP struct for bond slave
    // (used to send for bond-master too,  but that
    // was a mis-reading of the standard).
    SFLCounters_sample_element lacp_elem = { 0 };
    if(adaptorNIO->bond_slave
       || adaptorNIO->bond_slave_2) {
      updateBondCounters(sp, adaptor);
      lacp_elem.tag = SFLCOUNTERS_LACP;
      lacp_elem.counterBlock.lacp = adaptorNIO->lacp; // struct copy
      SFLADD_ELEMENT(cs, &lacp_elem);
    }
    
    // possibly include SFP struct with optical gauges
    SFLCounters_sample_element sfp_elem = { 0 };
    if(adaptorNIO->sfp.num_lanes) {
      sfp_elem.tag = SFLCOUNTERS_SFP;
      sfp_elem.counterBlock.sfp = adaptorNIO->sfp; // struct copy - picks up lasers list
      SFLADD_ELEMENT(cs, &sfp_elem);
    }
    
    // circulate the cs to be annotated by other modules before it is sent out.
    // This differs from the packet-sample treatment in that everything is
    // on the stack.  If we ever wanted to delay counter samples until additional
    // lookups were performed then this would all have to shift onto the heap.
    // Note that this differs from HSPEVENT_HOST_COUNTER_SAMPLE in that we
    // wrap it in an HSPPendingCSample so we can supply the poller pointer too.
    HSPPendingCSample ps = { .poller = poller, .cs = cs };
    EVEvent *evt_intf_cs = EVGetEvent(sp->pollBus, HSPEVENT_INTF_COUNTER_SAMPLE);
    EVEventTx(sp->rootModule, evt_intf_cs, &ps, sizeof(ps));
    if(ps.suppress) {
      sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES_SUPPRESSED]++;
    }
    else {
      sfl_poller_writeCountersSample(poller, cs);
      sp->counterSampleQueued = YES;
      sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES]++;
    }
  }

  /*_________________-----------------------------------__________________
    _________________   agentCB_getCounters_interface   __________________
    -----------------___________________________________------------------
  */

  static void agentCB_getCounters_interface(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;
    EVMod *mod = sp->rootModule;

    assert(EVCurrentBus() == sp->pollBus);

    // device name was copied as userData
    char *devName = (char *)poller->userData;
    if(devName) {
      // look up the adaptor objects
      SFLAdaptor *adaptor = adaptorByName(sp, devName);
      if(adaptor) {
	// make sure the counters are up to the second
	updateNioCounters(sp, adaptor);
	sendInterfaceCounterSample(mod, poller, adaptor, cs);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   evt_request_poller      __________________
    -----------------___________________________------------------
  */

  static void evt_request_poller(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    assert(dataLen == sizeof(uint32_t));
    uint32_t ifIndex = *(uint32_t *)data;
    SFLAdaptor *adaptor = adaptorByIndex(sp, ifIndex);
    if(adaptor) {
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
      if(adaptorNIO->poller == NULL) {
	SFLDataSource_instance dsi;
	SFL_DS_SET(dsi, 0, ifIndex, 0); // ds_class,ds_index,ds_instance
	adaptorNIO->poller = sfl_agent_addPoller(sp->poll_agent, &dsi, sp, agentCB_getCounters_interface);
	sfl_poller_set_sFlowCpInterval(adaptorNIO->poller, sp->actualPollingInterval);
	sfl_poller_set_sFlowCpReceiver(adaptorNIO->poller, HSP_SFLOW_RECEIVER_INDEX);
	// remember the device name to make the lookups easier later.
	// Don't want to point directly to the SFLAdaptor or SFLAdaptorNIO object
	// in case it gets freed at some point.  The device name is enough.
	adaptorNIO->poller->userData = (void *)my_strdup(adaptor->deviceName);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    persistent dsIndex     __________________
    -----------------___________________________------------------
  */

  static uint32_t assignVM_dsIndex(HSP *sp, HSPVMState *state) {

    // make sure we are never called from a different thread
    assert(EVCurrentBus() == sp->pollBus);

    uint32_t first = HSP_DEFAULT_LOGICAL_DSINDEX_START;
    uint32_t last = HSP_DEFAULT_APP_DSINDEX_START - 1;
    uint32_t range = last - first + 1;

    if(UTHashN(sp->vmsByDsIndex) >= range) {
      // table is full
      state->dsIndex = 0;
      return NO;
    }

    uint32_t hash = hashUUID(state->uuid);
    uint32_t preferred = first + (hash % range);
    state->dsIndex = preferred;
    for(;;) {
      HSPVMState *probe = UTHashGet(sp->vmsByDsIndex, state);
      if(probe == NULL) {
	// claim this one
	UTHashAdd(sp->vmsByDsIndex, state);
	break;
      }
      if(probe == state) {
	// why did we assign again?
	break;
      }
      // collision - keep searching
      state->dsIndex++;
      if(state->dsIndex > last)
	state->dsIndex = first;
      if(state->dsIndex == preferred) {
	// full wrap - shouldn't happen if the table
	// is not full, but detect it anyway just in
	// case we change something later.
	state->dsIndex = 0;
	return NO;
      }
    }
    return YES;
  }

  /*_________________---------------------------__________________
    _________________   VM/Container state      __________________
    -----------------___________________________------------------
  */
  HSPVMState *getVM(EVMod *mod, char *uuid, bool create, size_t objSize, EnumVMType vmType, getCountersFn_t getCountersFn) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // make sure we are never called from a different thread
    assert(EVCurrentBus() == sp->pollBus);
    assert(objSize >= sizeof(HSPVMState));
    HSPVMState search;
    memcpy(search.uuid, uuid, 16);
    HSPVMState *state = UTHashGet(sp->vmsByUUID, &search);
    if(state == NULL
       && create) {
      state = (HSPVMState *)my_calloc(objSize);
      memcpy(state->uuid, uuid, 16);
      UTHashAdd(sp->vmsByUUID, state);
      if(assignVM_dsIndex(sp,state) == NO) {
	my_free(state);
	state = NULL;
      }
      else {
	state->created = YES;
	state->vmType = vmType;
	state->volumes = strArrayNew();
	state->disks = strArrayNew();
	state->interfaces = adaptorListNew();
	state->gpus = UTArrayNew(UTARRAY_DFLT);
	sp->refreshAdaptorList = YES;
	SFLDataSource_instance dsi;
	// ds_class = <virtualEntity>, ds_index = offset + <assigned>, ds_instance = 0
	SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, state->dsIndex, 0);
	state->poller = sfl_agent_addPoller(sp->poll_agent, &dsi, mod, getCountersFn);
	state->poller->userData = state;
	sfl_poller_set_sFlowCpInterval(state->poller, sp->actualPollingInterval);
	sfl_poller_set_sFlowCpReceiver(state->poller, HSP_SFLOW_RECEIVER_INDEX);
      }
    }
    return state;
  }

  HSPVMState *getVM_byDS(EVMod *mod, uint32_t dsIndex) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPVMState search = { .dsIndex = dsIndex };
    return (HSPVMState *)UTHashGet(sp->vmsByDsIndex, &search);
  }

  void removeAndFreeVM(EVMod *mod, HSPVMState *state) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // make sure we are never called from a different thread
    assert(EVCurrentBus() == sp->pollBus);
    UTHashDel(sp->vmsByDsIndex, state);
    UTHashDel(sp->vmsByUUID, state);
    if(state->disks) strArrayFree(state->disks);
    if(state->volumes) strArrayFree(state->volumes);
    if(state->interfaces) {
      markAdaptors_adaptorList(mod, state->interfaces);
      // delete any hash-table references to these adaptors
      deleteMarkedAdaptors_adaptorList(mod, state->interfaces);
      // then free them along with the adaptorList itself
      adaptorListFree(state->interfaces);
    }
    if(state->poller) {
      state->poller->userData = NULL;
      sfl_agent_removePoller(sp->poll_agent, &state->poller->dsi);
    }
    my_free(state);
    sp->refreshAdaptorList = YES;
  }

  /*_________________---------------------------__________________
    _________________    syncOutputFile         __________________
    -----------------___________________________------------------
  */

  static void syncOutputFile(HSP *sp) {
    // The current settings will usually be found in sp->sFlowSettings, but there
    // is a case where those have not been determined yet and we start with the
    // file settings:
    HSPSFlowSettings *settings = sp->sFlowSettings ?: sp->sFlowSettings_file;

    myDebug(1, "syncOutputFile");
    rewind(sp->f_out);
    fprintf(sp->f_out, "# WARNING: Do not edit this file. It is generated automatically by hsflowd.\n");

    // revision appears both at the beginning and at the end
    fprintf(sp->f_out, "rev_start=%u\n", sp->revisionNo);

    // don't write out the settings if we are suppressing output at the moment
    if(sp->sFlowSettings_str
       && sp->suppress_sendPkt_waitConfig == NO
       && sp->suppress_sendPkt_agentAddress == NO) {

      fputs(sp->sFlowSettings_str, sp->f_out);

      // If agentIP or agentDevice was overridden then we just wrote that out with the sFlowSettings_str,
      // but otherwise add the election-chosen ones here, so others can know what selection was made:
      if(!settings->agentIP.type) {
	char ipbuf[51];
	fprintf(sp->f_out, "agentIP=%s\n", SFLAddress_print(&sp->agentIP, ipbuf, 50));
      }
      if(!settings->agentDevice
	 && sp->agentDevice)
	fprintf(sp->f_out, "agent=%s\n", sp->agentDevice);
    
      // jsonPort always comes from local config file, but include it here so that
      // others know where to send their JSON application/rtmetric/rtflow messages
      if(sp->json.port)
	fprintf(sp->f_out, "jsonPort=%u\n", sp->json.port);
      
      // Others may need to know our ds_index too
      fprintf(sp->f_out, "ds_index=%u\n", HSP_DEFAULT_PHYSICAL_DSINDEX);
    }

    // repeat the revision number. The reader knows that if the revison number
    // has not changed under his feet then he has a consistent config.
    fprintf(sp->f_out, "rev_end=%u\n", sp->revisionNo);
    fflush(sp->f_out);
    // chop off anything that may be lingering from before
    UTTruncateOpenFile(sp->f_out);
  }

  /*_________________---------------------------------__________________
    _________________ refreshAdaptorsAndAgentAddress  __________________
    -----------------_________________________________------------------
  */

  static void refreshAdaptorsAndAgentAddress(HSP *sp) {
    EVMod *mod = sp->rootModule;
    bool suppress = NO;
    uint32_t ad_added=0, ad_removed=0, ad_cameup=0, ad_wentdown=0, ad_changed=0;
    if(readInterfaces(sp, YES, &ad_added, &ad_removed, &ad_cameup, &ad_wentdown, &ad_changed) == 0) {
      myLog(LOG_ERR, "failed to re-read interfaces\n");
    }
    else {
      EVDebug(mod, 1, "interfaces added: %u removed: %u cameup: %u wentdown: %u changed: %u",
	      ad_added, ad_removed, ad_cameup, ad_wentdown, ad_changed);
    }

    bool agentAddressChanged=NO;
    bool agentDeviceMismatch=NO;
    if(selectAgentAddress(sp, &agentAddressChanged, &agentDeviceMismatch) == NO) {
      myLog(LOG_ERR, "failed to re-select agent address - suppress output");
      // make sure we don't send anything with an invalid agent address (such
      // as one that was just removed under our feet).  Hopefully a new address
      // will be added and we can recover in due course.
      suppress = YES;
    }
    if(agentDeviceMismatch
       && sp->agentDeviceStrict) {
      EVDebug(mod, 1, "agent device mismatch and agentDeviceStrict is set - suppress output");
      // this can happen if the interface referred to has not come up yet, or if the config
      // is using an alias name for it and the alias has not be learned yet (e.g. mod_sonic).
      // If the agentDeviceStrict flag is set then we treat this as a showstopper.
      suppress = YES;
    }
    
    if(suppress
       && sp->suppress_sendPkt_agentAddress == NO) {
      // impose the restriction on sending with a bad agent-address right away
      EVDebug(mod, 1, "imposing suppress_sendPkt_agentAddress");
      sp->suppress_sendPkt_agentAddress = YES;
    }
    
    EVDebug(mod, 1, "agentAddressChanged=%s", agentAddressChanged ? "YES" : "NO");
    if(agentAddressChanged) {
      sfl_agent_set_address(sp->agent, &sp->agentIP);
      sfl_agent_set_address(sp->poll_agent, &sp->agentIP);
      // this incs the revision No so it causes the
      // output file to be rewritten below too.
      installSFlowSettings(sp, sp->sFlowSettings);
    }

    EVDebug(mod, 1, "instances: adaptors=%d, localIP=%d",
	    adaptorInstances(),
	    localIPInstances());
    
    if(ad_added || ad_removed || ad_cameup || ad_wentdown || ad_changed) {
      // test for switch ports
      configSwitchPorts(sp); // in readPackets.c
      // announce (e.g. to adjust sampling rates if ifSpeeds changed)
      EVEventTxAll(sp->rootModule, HSPEVENT_INTFS_CHANGED, NULL, 0);
    }

    if(suppress == NO
       && sp->suppress_sendPkt_agentAddress) {
      EVDebug(mod, 1, "lifting suppress_sendPkt_agentAddress");
      // on the other hand, if we are lifting the restriction then defer it to here.
      sp->suppress_sendPkt_agentAddress = NO;
    }
  }

  /*_________________---------------------------__________________
    _________________    readDebugActions       __________________
    -----------------___________________________------------------
  */

  static void readDebugActions(HSP *sp, char *path) {
    FILE *f_actions = fopen(path, "r");
    if(f_actions) {
      char line[HSP_MAX_DEBUG_LINELEN];
      int truncated;
      int lineNo=0;
      while(my_readline(f_actions, line, HSP_MAX_DEBUG_LINELEN, &truncated) != EOF) {
	if(truncated
	   || ++lineNo >= HSP_MAX_DEBUG_ACTIONS) {
	  myDebug(1, "debug-action overload");
	  break;
	}
	char *varval = (char *)line;
	char keyBuf[HSP_MAX_DEBUG_LINELEN];
	char valBuf[HSP_MAX_DEBUG_LINELEN];
	if(parseNextTok(&varval, "=", YES, '"', YES, keyBuf, HSP_MAX_DEBUG_LINELEN)
	   && parseNextTok(&varval, "=", YES, '"', YES, valBuf, HSP_MAX_DEBUG_LINELEN)) {
	  // for now, accept only <mod>=<level>
	  int debugLevel = strtol(valBuf, NULL, 0);
	  EVMod *mod = EVGetModule(sp->rootModule, keyBuf);
	  if(mod) {
	    mod->debugLevel = debugLevel;
	    myDebug(1, "setting mod=%s debugLevel=%u", mod->name, debugLevel);
	    EVDebug(mod, 1, "debugLevel=%u", debugLevel);
	  }
	  else {
	    myDebug(1, "debug action ignored: %s", line);
	  }
	}
      }
      fclose(f_actions);
    }
  }

  static void checkForDebugActions(HSP *sp) {
    // see if there are debug actions to process
    if(sp->debugFile) {
      struct stat statBuf = {};
      if(stat(sp->debugFile, &statBuf) == 0) {
	time_t mtim = statBuf.st_mtim.tv_sec;
	if(sp->debugFileModTime != mtim) {
	  sp->debugFileModTime = mtim;
	  readDebugActions(sp, sp->debugFile);
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */

  static void evt_pkt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->suppress_sendPkt_waitConfig) {
      EVDebug(mod, 1, "hsflowd: evt_pkt_tick() waitConfig");
      return;
    }

    time_t clk = evt->bus->now.tv_sec;

    // TODO: *** can we stop callig this now?
    sfl_agent_set_now(sp->poll_agent, clk, evt->bus->now.tv_nsec);
    
    // only run the poller_tick()s and notifier_tick()s here,  not the
    // full agent_tick(). We'll call receiver_flush at the end of this
    // tick/tock cycle, and skip the sampler_tick() altogether.
    // sfl_agent_tick(sp->agent, clk);
    for(SFLPoller *pl = sp->agent->pollers; pl; pl = pl->nxt)
      sfl_poller_tick(pl, clk);
    for(SFLNotifier *nf = sp->agent->notifiers; nf; nf = nf->nxt)
      sfl_notifier_tick(nf, clk);
  }

  static void evt_poll_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    
    if(sp->suppress_sendPkt_waitConfig) {
      EVDebug(mod, 1, "hsflowd: evt_poll_tick() waitConfig");
      return;
    }

    time_t clk = evt->bus->now.tv_sec;

    // send a tick to the sFlow agent. This will be passed on
    // to the samplers, pollers and receiver.  If the poller is
    // ready to poll counters it will pull it's callback, but
    // we are using that just to populate the poll actions list.
    // That way we can relinquish the sync semaphore quickly.
    // It is up to the poller's getCounters Fn to grab it again
    // if and when it is required.  Same goes for the
    // sync_receiver lock,  which is needed when the final
    // counter sample is submitted for XDR serialization.

    // update agent 'now' (also updated by packet samples):
    // TODO: *** can we stop callig this now?
    sfl_agent_set_now(sp->poll_agent, clk, evt->bus->now.tv_nsec);
      
    // only run the poller_tick()s here,  not the full agent_tick()
    // we'll call receiver_flush at the end of this tick/tock cycle,
    // and skip the sampler_tick() and notifier_tick altogether.
    // sfl_agent_tick(sp->poll_agent, clk);
    for(SFLPoller *pl = sp->poll_agent->pollers; pl; pl = pl->nxt)
      sfl_poller_tick(pl, clk);
    
    // If a collector socket failed, we will attempt to reopen it
    // here after a suitable cooling off period. One scenario for
    // this is if the interface VRF is changed under our feet. That
    // results in the sentto() failing with "No Such Device".
    // Reopening here while we have the agent semaphore means that
    // another thread will not try to send something while the
    // socket is half opened. For consistency we could choose to
    // hold the same semaphore in the more common "installSFlowSettings"
    // path, but there the collector sockets are deliberately opened
    // before the settings "go live" so it is not necessary.
    if(sp->reopenCollectorSocketCountdown) {
      if(--sp->reopenCollectorSocketCountdown == 0) {
	EVDebug(mod, 1, "Reopening collector socket(s) after error");
	openCollectorSockets(sp, sp->sFlowSettings);
      }
    }

    // possibly poll the nio counters to avoid 32-bit rollover
    if(sp->nio_polling_secs &&
       clk >= sp->next_nio_poll) {
      updateNioCounters(sp, NULL);
      sp->next_nio_poll = clk + sp->nio_polling_secs;
    }

    // check for interface changes (relatively frequently)
    // and request a full refresh if we find anything
    if(clk >= sp->next_checkAdaptorList) {
      sp->next_checkAdaptorList = clk + sp->checkAdaptorListSecs;
      if(detectInterfaceChange(sp))
	sp->refreshAdaptorList = YES;
    }

    // refresh the interface list periodically or on request
    if(sp->refreshAdaptorList
       || clk >= sp->next_refreshAdaptorList) {
      sp->refreshAdaptorList = NO;
      sp->next_refreshAdaptorList = clk + sp->refreshAdaptorListSecs;
      refreshAdaptorsAndAgentAddress(sp);
    }

    // rewrite the output if the config has changed
    if(sp->outputRevisionNo != sp->revisionNo) {
      syncOutputFile(sp);
      sp->outputRevisionNo = sp->revisionNo;
    }

    // see if there are debug actions to process
    checkForDebugActions(sp);
  }

  /*_________________---------------------------__________________
    _________________     tock - all buses      __________________
    -----------------___________________________------------------
    this fn called on tock by all buses (all threads) so be careful!
  */

  static void evt_all_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // we registered for this event after the other modules were loaded,  so
    // unless they delay their registration for some reason we can assume
    // that this is the last tock() action.  (Could add another event to the
    // cycle in evbus.c if we really need to be sure).  Delaying the flush to
    // here makes it more likely that counters will be flushed out promptly
    // when they are freshly read.

    // note - this used to happen inside sfl_agent_tick(), but we
    // disaggregated that call so the pollers get their ticks first
    // and the receiver flush happens at the end.
    
    if(EVCurrentBus() == sp->packetBus)
      sfl_receiver_flush(sp->agent->receivers);

    if(EVCurrentBus() == sp->pollBus) {
      sfl_receiver_flush(sp->poll_agent->receivers);
      sp->counterSampleQueued = NO;
    }

#ifdef UTHEAP
    // check for heap cleanup
    UTHeapGC();
#endif

    if(sp->memLimitBytes > 0) {
      struct rusage usage;
      getrusage(RUSAGE_SELF, &usage);
      if(usage.ru_maxrss > (long)sp->memLimitBytes) {
	myLog(LOG_ERR, "Configured memory limit of %u exceeded (rss=%u)", sp->memLimitBytes, usage.ru_maxrss);
	exit(EXIT_FAILURE);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________  evt_pkt_xdr_sample       __________________
    -----------------___________________________------------------
  */

  static void evt_pkt_xdr_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLReceiver *receiver = sp->agent->receivers;
    if(data
       && dataLen
       && receiver
       && receiver->sfdg) {
      // have to copy here because it might not be sent immediately
      // and incoming data is not allocated on the heap.  This way of
      // submitting counter samples is inefficient, but it allows the
      // fast-path (packet-samples) to proceed lock-free. We could have
      // sweated over some other mechanism (e.g. shared memory ringbuffer)
      // but EVBus messaging is convenient, works with select()
      // and fast enough.
      SFDBuf *dbuf = sfl_receiver_get_SFDBuf(receiver);
      SFDSampleCopy(dbuf, (SFDBuf *)data);
      sfl_receiver_write_SFDBuf(receiver, dbuf);
    }
  }

  /*_________________---------------------------__________________
    _________________         initAgent         __________________
    -----------------___________________________------------------
  */

  static SFLAgent *initAgent(HSP *sp, SFLAddress *agentIP, uint32_t subId) {
    myDebug(1,"creating sfl agent");
    SFLAgent *agent = (SFLAgent *)my_calloc(sizeof(SFLAgent));
    sfl_agent_init(agent,
		   agentIP,
		   subId,
		   0,
		   0,
		   sp,
		   agentCB_alloc,
		   agentCB_free,
		   agentCB_error,
		   NULL /*agentCB_sendPkt*/);
    
    // override datagram-builder callback default that was
    // there to help with backwards compatibility. This way
    // can be more efficient by removing a copy.
    sfl_agent_init_sfdg_sendFn(agent, sfdgCB_send);

    // and adopt the new scheme where the datagram-builder
    // calls back to get "now" in milliseconds.  We no
    // longer need to call sfl_agent_set_now().
    sfl_agent_init_sfdg_nowFn(agent, sfdgCB_now_mS);

    // just one receiver - we are serious about making this lightweight for now
    SFLReceiver *receiver = sfl_agent_addReceiver(agent);

    // max datagram size might have been tweaked in the config file
    if(sp->sFlowSettings_file->datagramBytes) {
      sfl_receiver_set_sFlowRcvrMaximumDatagramSize(receiver, sp->sFlowSettings_file->datagramBytes);
    }

    // claim the receiver slot
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Virtual Switch sFlow Probe");

    // set the timeout to infinity
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);

    return agent;
  }

  /*_________________---------------------------__________________
    _________________     setDefaults           __________________
    -----------------___________________________------------------
  */

  static void setDefaults(HSP *sp)
  {
    sp->configFile = HSP_DEFAULT_CONFIGFILE;
    sp->outputFile = HSP_DEFAULT_OUTPUTFILE;
    sp->pidFile = HSP_DEFAULT_PIDFILE;
    sp->crashFile = NULL;
    sp->dropPriv = YES;
    sp->refreshAdaptorListSecs = HSP_REFRESH_ADAPTORS;
    sp->checkAdaptorListSecs = HSP_CHECK_ADAPTORS;
    sp->refreshVMListSecs = HSP_REFRESH_VMS;
    sp->forgetVMSecs = HSP_FORGET_VMS;
    sp->modulesPath = STRINGIFY_DEF(HSP_MOD_DIR);
    sp->logBytes = HSP_DEFAULT_LOGBYTES;
    sp->memLimit = HSP_DEFAULT_MEMLIMIT;
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-dvP] [-p PIDFile] [-u UUID] [-m machine_id] [-f CONFIGFile] [-l MODULESDir] [-D LOGFile] [-L LOGBytes]\n", command);
    fprintf(stderr,"\n\
             -d:  do not daemonize, and log to stdout/LOGFile (repeat for more debug details)\n\
     -D LOGFile:  debug logging goes to this file\n\
    -L LOGBytes:  max bytes in LOGFile (default is " HSP_DEFAULT_LOGBYTES ")\n\
   -F debugCtrl:  debug logging control file (lines with <mod>=<level>)\n\
             -v:  print version number and exit\n\
             -P:  do not drop privileges (run as root)\n\
     -p PIDFile:  set PID file (default is " HSP_DEFAULT_PIDFILE ")\n\
        -u UUID:  set UUID as unique ID for this host\n\
  -f CONFIGFile:  config file (default is " HSP_DEFAULT_CONFIGFILE ")\n\
  -l MODULESDir:  modules directory (default is " STRINGIFY_DEF(HSP_MOD_DIR) ")\n\
   -c CRASHFile:  file to write crash info to (default is stderr)\n\
    -M MEMLimit:  max memory footprint in bytes for this process\n");
  fprintf(stderr, "=============== More Information =============================\n");
  fprintf(stderr, "| sFlow standard        - https://www.sflow.org               |\n");
  fprintf(stderr, "| host-sFlow            - https://sflow.net                   |\n");
  fprintf(stderr, "| sflowtool             - https://github.com/sflow/sflowtool  |\n");
  fprintf(stderr, "| sFlow-RT              - https://sflow-rt.com                |\n");
  fprintf(stderr, "==============================================================\n");
  exit(EXIT_FAILURE);
  }

  /*_________________---------------------------__________________
    _________________   processCommandLine      __________________
    -----------------___________________________------------------
  */

  static void processCommandLine(HSP *sp, int argc, char *argv[])
  {
    int in;
    while ((in = getopt(argc, argv, "dvPp:f:F:l:o:u:m:?hc:D:L:M:")) != -1) {
      switch(in) {
      case 'v':
	printf("%s version %s\n", argv[0], STRINGIFY_DEF(HSP_VERSION));
	exit(EXIT_SUCCESS);
	break;
      case 'd':
	// first 'd' just turns off daemonize, second increments debug
	if(!getDaemon())
	  setDebug(getDebug() + 1);
	setDaemon(NO);
	break;
      case 'P': sp->dropPriv = NO; break;
      case 'p': sp->pidFile = optarg; break;
      case 'f': sp->configFile = optarg; break;
      case 'F': sp->debugFile = optarg; break;
      case 'l': sp->modulesPath = my_strlen(optarg) ? optarg : NULL; break;
      case 'o': sp->outputFile = optarg; break;
      case 'c': sp->crashFile = optarg; break;
      case 'D': sp->logFile = optarg; break;
      case 'L': sp->logBytes = optarg; break;
      case 'M': sp->memLimit = optarg; break;
      case 'u':
	if(parseUUID(optarg, sp->uuid) == NO) {
	  fprintf(stderr, "bad UUID format: %s\n", optarg);
	  instructions(*argv);
	}
	break;
      case 'm':
	if(parseUUID(optarg, sp->machine_id) == NO) {
	  fprintf(stderr, "bad UUID (machine-id) format: %s\n", optarg);
	  instructions(*argv);
	}
	break;
      case '?':
      case 'h':
      default: instructions(*argv);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    log_backtrace          __________________
    -----------------___________________________------------------
  */

  void log_backtrace(int sig, siginfo_t *info, FILE *out) {
#ifdef HAVE_BACKTRACE
#define HSP_NUM_BACKTRACE_PTRS 50
    static void *backtracePtrs[HSP_NUM_BACKTRACE_PTRS];

    // ask for the backtrace pointers
    size_t siz = backtrace(backtracePtrs, HSP_NUM_BACKTRACE_PTRS);

    FILE *outFile = out ?: stderr;

    // do this first in case everything else is compromised
    backtrace_symbols_fd(backtracePtrs, siz, fileno(outFile));
    fflush(outFile);

    // Do something useful with siginfo_t
    if (sig == SIGSEGV)
      fprintf(out, "SIGSEGV, faulty address is %p\n", info->si_addr);

    // thread info
    EVBus *bus = EVCurrentBus();
    fprintf(outFile, "current bus: %s\n", (bus ? bus->name : "<none>"));
#endif
  }

  void log_telemetry(HSP *sp, FILE *out) {
    FILE *outFile = out ?: stderr;
    for(int ii = 0; ii < HSP_TELEMETRY_NUM_COUNTERS; ii++) {
      fprintf(outFile, "%s=%"PRIu64"\n", HSPTelemetryNames[ii], sp->telemetry[ii]);
    }
  }
  
  /*_________________---------------------------__________________
    _________________     signal_handler        __________________
    -----------------___________________________------------------
  */

  static void signal_handler(int sig, siginfo_t *info, void *secret) {
    HSP *sp = &HSPSamplingProbe;

    switch(sig) {
    case SIGTERM:
      myLog(LOG_INFO,"Received SIGTERM");
      // graceful
      EVStop(sp->rootModule);
      break;
    case SIGHUP:
      myLog(LOG_INFO,"Received SIGHUP");
      // reopen log files (this signal may have been from logrotate)
      openLogFile(sp);
      break;
    case SIGINT:
      myLog(LOG_INFO,"Received SIGINT");
      // abrupt
      exit(sig);
      break;
    case SIGUSR1:
      myLog(LOG_INFO,"Received SIGUSR1");
      // telemtry, backtrace and memory stats only - then keep going
      log_telemetry(sp, getDebugOut());
      log_backtrace(sig, info, getDebugOut());
#if (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 13)
      malloc_info(0, getDebugOut());
#endif
      break;
    case SIGUSR2:
      myLog(LOG_INFO,"Received SIGUSR2");
      // increase debug log level
      setDebug(getDebug() + 1);
      fprintf(getDebugOut(),"SIGUSR2: increased debug log level to %u (logBytes=%ld, limit=%ld)\n",
	      getDebug(),
	      ftell(getDebugOut()),
	      getDebugLimit());
      break;
    default:
      myLog(LOG_INFO,"Received signal %d", sig);
      // first try to make sure we can't go in a loop
      signal(SIGSEGV, SIG_DFL);
      signal(SIGFPE, SIG_DFL);
      signal(SIGILL, SIG_DFL);
      signal(SIGBUS, SIG_DFL);
      signal(SIGXFSZ, SIG_DFL);
      // backtrace to stderr
      log_backtrace(sig, info, stderr);
      // backtrace to debug too
      log_backtrace(sig, info, getDebugOut());
      // and bail out
      exit(sig);
      break;
    }
  }

  /*_________________---------------------------__________________
    _________________   pre_config_first        __________________
    -----------------___________________________------------------
  */

  static void pre_config_first(HSP *sp) {
    // make sure we are ready for someone to call getSampler/getPoller
    updatePollingInterval(sp);

    // before we do anything else,  read the interfaces again - this time with a full discovery
    // so that modules can weigh in if required,  and, for example, sampling-rates can be set
    // correctly.
    readInterfaces(sp, YES, NULL, NULL, NULL, NULL, NULL);

    // add a <physicalEntity> poller to represent the whole physical host
    SFLDataSource_instance dsi;
    // ds_class = <physicalEntity>, ds_index = <my physical>, ds_instance = 0
    SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, HSP_DEFAULT_PHYSICAL_DSINDEX, 0);
    sp->poller = sfl_agent_addPoller(sp->poll_agent, &dsi, sp, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(sp->poller, sp->actualPollingInterval);
    sfl_poller_set_sFlowCpReceiver(sp->poller, HSP_SFLOW_RECEIVER_INDEX);
  }


  /*_________________---------------------------__________________
    _________________   bindCollectorToDevice   __________________
    -----------------___________________________------------------
  */

#ifdef IP_UNICAST_IF

  static bool bindCollectorToDevice(HSPCollector *coll, bool v6) {
    myDebug(1, "bindCollectorToDevice: device=%s", coll->deviceName);
    if(coll->deviceIfIndex==0) {
      myLog(LOG_ERR, "bindCollectorToDevice : no ifIndex for device=%s", coll->deviceName);
      return NO;
    }
    // optarg is int, but set to value of ifIndex in 32-bit network-byte-order representation
    int ifIndex = htonl(coll->deviceIfIndex);
    if(setsockopt(coll->socket,
		  v6 ? SOL_IPV6 : SOL_IP,
		  v6 ? IPV6_UNICAST_IF : IP_UNICAST_IF,
		  &ifIndex,
		  sizeof(ifIndex)) == -1) {
      myLog(LOG_ERR, "bindCollectorToDevice : device=%s ifIndex=%d setsockopt (v6=%u) failed : %s",
	    coll->deviceName,
	    coll->deviceIfIndex,
	    v6,
	    strerror(errno));
      return NO;
    }
    return YES;
  }
#endif

  /*_________________---------------------------__________________
    _________________   openCollectorSockets    __________________
    -----------------___________________________------------------
  */

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) || (__GLIBC__ <= 2 && __GLIBC_MINOR__ < 14))
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
#endif

#define MY_SETNS(fd, nstype) syscall(__NR_setns, fd, nstype)
#else
#define MY_SETNS(fd, nstype) setns(fd, nstype)
#endif

#define HSP_MAX_NETNS_PATH 256

  static void *openCollectorSocket(void *magic) {
    HSPCollector *coll = (HSPCollector *)magic;

    if(coll->namespace) {
      // switch namespace now
      // (1) open /var/run/netns/<namespace>
      char topath[HSP_MAX_NETNS_PATH];
      snprintf(topath, HSP_MAX_NETNS_PATH, VARFS_STR "/run/netns/%s", coll->namespace);
      int nsfd = open(topath, O_RDONLY | O_CLOEXEC);
      if(nsfd < 0) {
	myLog(LOG_ERR, "cannot open %s : %s", topath, strerror(errno));
	exit(EXIT_FAILURE); // consider making this non-fatal
      }
      // (2) call setns
      if(MY_SETNS(nsfd, CLONE_NEWNET) < 0) {
	myLog(LOG_ERR, "seting network namespace failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      // (3) call unshare
      if(unshare(CLONE_NEWNS) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      // still here? celebrate...
      myDebug(1, "thread sucessfully switched network namespace to %s", coll->namespace);

      // tested this using the following steps:
      // create two namespaces:
      //  % ip netns add red
      //  % ip netns add blue
      // connect them with a veth pair:
      //  % ip link add vethred type veth peer name vethblue
      //  % ip link set vethred netns red
      //  % ip link set vethblue netns blue
      // and give each end an IP:
      //  % ip netns exec red ifconfig vethred 172.16.100.1/24 up
      //  % ip netns exec blue ifconfig vethblue 172.16.100.2/24 up
      // test connectivity:
      //  % ip netns exec blue ping 172.16.100.1
      //  % ip netns exec red  ping 172.16.100.2
      // now tell hsflowd to send to the blue IP via the red namespace:
      //   collector { ip=172.16.100.2 udpport=7777 namespace=red }
      // and listen for output on the blue side:
      //  % ip netns exec blue sflowtool -p 7777
    }

    switch(coll->ipAddr.type) {
    case SFLADDRESSTYPE_UNDEFINED:
      // skip over it if the forward lookup failed
      break;
    case SFLADDRESSTYPE_IP_V4:
      {
	coll->socklen = sizeof(struct sockaddr_in);
	struct sockaddr_in *sa = (struct sockaddr_in *)&(coll->sendSocketAddr);
	sa->sin_family = AF_INET;
	sa->sin_port = htons(coll->udpPort);
	if((coll->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	  myLog(LOG_ERR, "IPv4 send socket open failed : %s", strerror(errno));
	}
#ifdef IP_UNICAST_IF
	else if (coll->deviceName)
	  bindCollectorToDevice(coll, NO);
#endif
      }
      break;
    case SFLADDRESSTYPE_IP_V6:
      {
	coll->socklen = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&(coll->sendSocketAddr);
	sa6->sin6_family = AF_INET6;
	sa6->sin6_port = htons(coll->udpPort);
	if((coll->socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	  myLog(LOG_ERR, "IPv6 send socket open failed : %s", strerror(errno));
	}
#ifdef IP_UNICAST_IF
	else if (coll->deviceName)
	  bindCollectorToDevice(coll, YES);
#endif
      }
      break;
    }
    if(coll->socket > 0) {
      // increase tx buffer size
      uint32_t sndbuf = HSP_SFLOW_SND_BUF;
      if(setsockopt(coll->socket, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
	myLog(LOG_ERR, "setsockopt(SO_SNDBUF=%d) failed(v4): %s", HSP_SFLOW_SND_BUF, strerror(errno));
      }
    }
    return NULL;
  }

  static void openCollectorSockets(HSP *sp, HSPSFlowSettings *settings) {
    // open the collector sockets if not open already
    for(HSPCollector *coll = settings->collectors; coll; coll=coll->nxt) {
      if(coll->socket <= 0) {
	if(coll->deviceName) {
	  // get ifIndex for device
	  SFLAdaptor *ad = adaptorByName(sp, coll->deviceName);
	  if(ad)
	    coll->deviceIfIndex = ad->ifIndex;
	}
	if(coll->namespace) {
	  // fork a new thread that can switch to the namespace before opening the socket
	  pthread_attr_t attr;
	  pthread_attr_init(&attr);
	  pthread_attr_setstacksize(&attr, EV_BUS_STACKSIZE);
	  pthread_t *thread = my_calloc(sizeof(pthread_t));
	  int err = pthread_create(thread, &attr, openCollectorSocket, coll);
	  if(err) {
	    myLog(LOG_ERR, "openCollectorSockets(): pthread_create() failed: %s\n", strerror(err));
	    abort();
	  }
	  else {
	    pthread_join(*thread, NULL);
	    my_free(thread);
	  }
	}
	else {
	  // open in default namespace
	  openCollectorSocket(coll);
	}
      }
    }
  }

  static void closeCollectorSockets(HSP *sp, HSPSFlowSettings *settings) {
    for(HSPCollector *coll = settings->collectors; coll; coll=coll->nxt) {
      if(coll->socket > 0) {
	close(coll->socket);
	coll->socket = 0;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   installSFlowSettings    __________________
    -----------------___________________________------------------

    Always increment the revision number whenever we change the sFlowSettings pointer
  */

  static bool installSFlowSettings(HSP *sp, HSPSFlowSettings *settings)
  {
    char *settingsStr = sFlowSettingsString(sp, settings);
    myDebug(3, "mS=%u installSFlowSettings: <%s>",
	    EVBusRunningTime_mS(EVCurrentBus()),
	    settingsStr);
    if(my_strequal(sp->sFlowSettings_str, settingsStr)) {
      // no change - don't increment the revision number
      // (which will mean that the file is not rewritten either)
      if(settingsStr)
	my_free(settingsStr);
      return NO;
    }

    // new config
    myDebug(1, "installSFlowSettings: detected new config");
    // keep pointers to old settings so we can free them below
    char *prev_settings_str = sp->sFlowSettings_str;
    HSPSFlowSettings *prev_settings = sp->sFlowSettings;

    // install new settings
    sp->sFlowSettings_str = settingsStr;
    sp->revisionNo++;
    if(settings) {
      // open collector sockets before this goes live
      openCollectorSockets(sp, settings);
    }
    // atomic pointer-switch.  No need for lock.  At least
    // not on the  platforms we expect to run on.
    sp->sFlowSettings = settings;

    // announce the change
    if(prev_settings_str == NULL) {
      // firstConfig
      // make sure certain things are in place before we proceed. This
      // could be done with an event such as CONFIG_PRE, but then
      // we would have to handshake before raising CONFIG_FIRST
      pre_config_first(sp);
      // now offer it to the modules
      EVEventTxAll(sp->rootModule, HSPEVENT_CONFIG_FIRST, NULL, 0);
    }

    myDebug(3, "installSFlowSettings: announcing config change");
    EVEventTxAll(sp->rootModule, HSPEVENT_CONFIG_CHANGED, NULL, 0);
    // delay the config-done event until every thread has processed the
    // config change.  This is especially important the first time because
    // we are about to drop priviledges.  If we plow on and do that here
    // we will drop them before another module on another bus gets to
    // complete a privileged action, such as opening a pcap socket.
    // Use the handshake mechanism to get every bus to reply.
    // Then we know we can proceed.
    sp->config_shake_countdown = EVBusCount(sp->rootModule);
    EVEventTxAll(sp->rootModule, EVEVENT_HANDSHAKE, HSPEVENT_CONFIG_SHAKE, strlen(HSPEVENT_CONFIG_SHAKE));
    // this now happens in evt_config_shake below...
    // EVEventTxAll(sp->rootModule, HSPEVENT_CONFIG_DONE, NULL, 0);

    // cleanup
    if(prev_settings_str
       && prev_settings_str != sp->sFlowSettings_str)
      my_free(prev_settings_str);
    if(prev_settings
       && prev_settings != sp->sFlowSettings_file
       && prev_settings != sp->sFlowSettings) {
      closeCollectorSockets(sp, prev_settings);
      freeSFlowSettings(prev_settings);
    }
    return YES;
  }

  /*_________________------------------------__________________
    _________________   evt_config_shake     __________________
    -----------------________________________------------------
  */

  static void evt_config_shake(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    myDebug(1, "evt_config_shake: reply from %s", (char *)data);
    if(--sp->config_shake_countdown == 0) {
      myDebug(1, "evt_config_shake: sync complete");
      EVEventTxAll(sp->rootModule, HSPEVENT_CONFIG_DONE, NULL, 0);
    }
  }

  /*_________________---------------------------__________________
    _________________  new config line-by-line  __________________
    -----------------___________________________------------------
    These events passed in from DNS-SD module to submit new SRV and TXT record config,
    or from EAPI module for tracking EOS sFlow config.
    The config could probably fit in one PIPE_BUF msg but it's safer to pass it in one
    name-value pair at a time to make sure we never hit that limit.  The sequence is
    HSPEVENT_CONFIG_START
    HSPEVENT_CONFIG_LINE (repeat)
    HSPEVENT_CONFIG_END
  */

  static void evt_config_start(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    sp->sFlowSettings_dyn = newSFlowSettings();
  }

  static void evt_config_line(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPSFlowSettings *st = sp->sFlowSettings_dyn;
    if(st == NULL) {
      myLog(LOG_ERR, "dynamic config: no current settings object");
      return;
    }
    dynamic_config_line(st, data);
  }

  static void evt_config_end(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // initiate server-discovery
    HSP *sp = (HSP *)EVROOTDATA(mod);
    assert(dataLen == sizeof(int));
    int num_servers = *(int *)data;

    // three cases here:
    // A) if(num_servers == -1) (i.e. query failed) then keep the current config
    // B) if(num_servers == 0) then stop monitoring
    // C) if(num_servers > 0) then install the new config

    myDebug(1, "num_servers == %d", num_servers);

    if(num_servers < 0) {
      // A: query failed: keep the current config.
    }
    else if(num_servers == 0) {
      // B: turn off monitoring.   TODO: test this!
      installSFlowSettings(sp, NULL);
    }
    else {
      // C: make this new one the running config.
      if(installSFlowSettings(sp, sp->sFlowSettings_dyn)) {
	// accepted: clear pointer so we don't free these settings immediately below
	sp->sFlowSettings_dyn = NULL;
	// make sure any agentIP related changes take effect immediately
	refreshAdaptorsAndAgentAddress(sp);
	// and open the tap if it was closed
	sp->suppress_sendPkt_waitConfig = NO;
      }
    }
    // if we didn't use the new settings for any reason then make
    // sure we recover the space and avoid dangling the pointer.
    if(sp->sFlowSettings_dyn) {
      freeSFlowSettings(sp->sFlowSettings_dyn);
      sp->sFlowSettings_dyn = NULL;
    }
  }

  /*_________________---------------------------__________________
    _________________  evt_all_poll_interval    __________________
    -----------------___________________________------------------
  */

  static void evt_all_poll_interval(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLPoller *pollers=NULL;
    if(EVCurrentBus() == sp->packetBus)
      pollers = sp->agent->pollers;
    if(EVCurrentBus() == sp->pollBus)
      pollers = sp->poll_agent->pollers;
    for(SFLPoller *pl = pollers; pl; pl = pl->nxt) {
      // This will spread the polling times out randomly over the
      // new interval. Those can be re-aligned into clusters using
      // configSwitchPorts().
      sfl_poller_set_sFlowCpInterval(pl, sp->actualPollingInterval);
    }
  }

  /*_________________---------------------------__________________
    _________________  updatePollingInterval    __________________
    -----------------___________________________------------------
  */

  
  static bool updatePollingInterval(HSP *sp) {
    if(sp->sFlowSettings == NULL) {
      // don't set actualPollingInterval until we have a config
      // -- e.g. in case it is set to 0 rather than the default.
      return NO;
    }

    // pick up the configured polling interval
    uint32_t pollingInterval = sp->sFlowSettings->pollingInterval;

    // apply constraints
    if(pollingInterval > 0
       && pollingInterval < sp->minPollingInterval) {
      pollingInterval = sp->minPollingInterval;
      myDebug(1, "override polling interval to min: %u", pollingInterval);
    }

    if(pollingInterval != sp->actualPollingInterval) {
      // store for all to use
      sp->actualPollingInterval = pollingInterval;
      // make sure any existing pollers get the memo, in any thread
      EVEventTxAll(sp->rootModule, HSPEVENT_POLL_INTERVAL, NULL, 0);
      return YES;
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________  evt_all_header_bytes     __________________
    -----------------___________________________------------------
  */

  static void evt_all_header_bytes(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(dataLen == sizeof(uint32_t)) {
      uint32_t headerBytes = *(uint32_t *)data;
      SFLSampler *samplers=NULL;
      if(EVCurrentBus() == sp->packetBus)
	samplers = sp->agent->samplers;
      if(EVCurrentBus() == sp->pollBus)
	samplers = sp->poll_agent->samplers;
      for(SFLSampler *sm = samplers; sm; sm = sm->nxt) {
	sfl_sampler_set_sFlowFsMaximumHeaderSize(sm, headerBytes);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________  updateHeaderBytes        __________________
    -----------------___________________________------------------
  */

  static void updateHeaderBytes(HSP *sp) {
    if(sp->sFlowSettings) {
      // pick up the configured headerBytes
      uint32_t headerBytes = sp->sFlowSettings->headerBytes;
      // apply constraints
      if(headerBytes > HSP_MAX_HEADER_BYTES) {
	headerBytes = HSP_MAX_HEADER_BYTES;
	myDebug(1, "limiting headerBytes to max: %u", headerBytes);
      }
      // make sure any existing samplers get the memo, in any thread
      EVEventTxAll(sp->rootModule, HSPEVENT_HEADER_BYTES, &headerBytes, sizeof(headerBytes));
    }
  }

  /*_________________---------------------------__________________
    _________________     evt_config_first      __________________
    -----------------___________________________------------------
  */

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // assert(sp->sFlowSettings);
    myDebug(1, "evt_config_first: first valid configuration");

    if(sp->sFlowSettings == NULL
       || sp->sFlowSettings->collectors == NULL) {
      if(sp->DNSSD.DNSSD == NO
	 && sp->eapi.eapi == NO
	 && sp->sonic.sonic == NO) {
	myLog(LOG_ERR, "evt_config_first: no collectors defined");
	abort();
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     evt_config_changed    __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    myDebug(1, "main: evt_config_changed()");
    // Used to check for agent-address override here and call sfl_agent_set_address(),
    // but that is done in refreshAdaptorsAndAgentAddress() which is called from
    // installSFlowSettings() during evt_config_end(), so any dynamic
    // change to the agent address has already been handled before we get here.
  }

  /*_________________---------------------------__________________
    _________________   synthesizeBondCounters  __________________
    -----------------___________________________------------------
  */

  void setSynthesizeBondCounters(EVMod *mod, bool val) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    myDebug(1, "setSynthesizeBondCounters =  %s", val ? "YES" : "NO");
    sp->synthesizeBondCounters = val;
    // assune this happens at startup,  otherwise we should probably
    // reset sequence numbers on all bond pollers here to signal a
    // discontinuity.
  }

  /*_________________---------------------------__________________
    _________________     VNode Role            __________________
    -----------------___________________________------------------
    A simple mechanism to decide which module should supply the
    sFlow VNode structure -- in case more than one is active.
  */

  void requestVNodeRole(EVMod *mod, EnumVNodePriority vnp) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(vnp > sp->vnodePriority)
      sp->vnodePriority = vnp;
  }

  bool hasVNodeRole(EVMod *mod, EnumVNodePriority vnp) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    return (vnp == sp->vnodePriority);
  }

  /*_________________---------------------------__________________
    _________________ agent device strictness   __________________
    -----------------___________________________------------------
    A simple mechanism to decide if we will tolerate an
    agent=<deviceName> directive if it does not actually
    match an existing interface name or alias.
  */

  void agentDeviceStrictRequest(EVMod *mod, char *reason) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    sp->agentDeviceStrict = YES;
    myDebug(1, "mod %s requires strict interpretation of agentDevice setting (%s)",
	    mod->name,
	    reason);
  }

  /*_________________---------------------------__________________
    _________________         drop_privileges   __________________
    -----------------___________________________------------------
  */

  void retainRootRequest(EVMod *mod, char *reason) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(!sp->retainRootReasons)
      sp->retainRootReasons = strArrayNew();
    strArrayAdd(sp->retainRootReasons, reason);
  }

  static bool retainRoot(HSP *sp) {
    if(sp->retainRootReasons
       && strArrayN(sp->retainRootReasons)) {
      if(debug(1)) {
	for(int ss = 0; ss < strArrayN(sp->retainRootReasons); ss++) {
	  char *reason = strArrayAt(sp->retainRootReasons, ss);
	  myLog(LOG_INFO, "retaining root privileges because: %s", reason);
	}
      }
      return YES;
    }
    return NO;
  }


  static int getMyLimit(int resource, char *resourceName) {
    struct rlimit rlim = {0};
    if(getrlimit(resource, &rlim) != 0) {
      myLog(LOG_ERR, "getrlimit(%s) failed : %s", resourceName, strerror(errno));
    }
    else {
      myLog(LOG_INFO, "getrlimit(%s) = %u (max=%u)", resourceName, rlim.rlim_cur, rlim.rlim_max);
    }
    return rlim.rlim_cur;
  }

  static int setMyLimit(int resource, char *resourceName, int request) {
    struct rlimit rlim = {0};
    rlim.rlim_cur = rlim.rlim_max = request;
    if(setrlimit(resource, &rlim) != 0) {
      myLog(LOG_ERR, "setrlimit(%s)=%d failed : %s", resourceName, request, strerror(errno));
      return NO;
    }
    myDebug(1, "setrlimit(%s)=%u", resourceName, request);
    return YES;
  }

#define GETMYLIMIT(L) getMyLimit((L), STRINGIFY(L))
#define SETMYLIMIT(L,V) setMyLimit((L), STRINGIFY(L), (V))

  static void drop_privileges(HSP *sp, int requestMemLockBytes) {
    myDebug(1, "drop_priviliges: getuid=%d", getuid());

    if(getuid() != 0) return;

    if(requestMemLockBytes) {
      // Request to lock this process in memory so that we don't get
      // swapped out. It's probably less than 100KB,  and this way
      // we don't consume extra resources swapping in and out
      // every 20 seconds.  The default limit is just 32K on most
      // systems,  so for this to be useful we have to increase it
      // somewhat first.
#ifdef RLIMIT_MEMLOCK
      SETMYLIMIT(RLIMIT_MEMLOCK, requestMemLockBytes);
#endif
      // Because we are dropping privileges we can get away with
      // using the MLC_FUTURE option to mlockall without fear.  We
      // won't be allowed to lock more than the limit we just set
      // above.
      if(mlockall(MCL_FUTURE) == -1) {
	myLog(LOG_ERR, "mlockall(MCL_FUTURE) failed : %s", strerror(errno));
      }

      // We can also use this as an upper limit on the data segment so that we fail
      // if there is a memory leak,  rather than grow forever and cause problems.
#ifdef RLIMIT_DATA
      SETMYLIMIT(RLIMIT_DATA, requestMemLockBytes);
#endif

    }

    if(retainRoot(sp)) {
      myDebug(1, "not relinquishing root privileges");
    }
    else {
      // set the real and effective group-id to 'nobody'
      // (Might have to make this configurable so we can become a user
      // that has been set up with the right permissions, e.g. for Docker)
      struct passwd *nobody = getpwnam("nobody");
      if(nobody == NULL) {
	myLog(LOG_ERR, "drop_privileges: user 'nobody' not found");
	exit(EXIT_FAILURE);
      }
      if(setgid(nobody->pw_gid) != 0) {
	myLog(LOG_ERR, "drop_privileges: setgid(%d) failed : %s", nobody->pw_gid, strerror(errno));
	exit(EXIT_FAILURE);
      }

      // It doesn't seem like this part is necessary(?)
      // if(initgroups("nobody", nobody->pw_gid) != 0) {
      //  myLog(LOG_ERR, "drop_privileges: initgroups failed : %s", strerror(errno));
      //  exit(EXIT_FAILURE);
      // }
      // endpwent();
      // endgrent();

      // now change user
      if(setuid(nobody->pw_uid) != 0) {
	myLog(LOG_ERR, "drop_privileges: setuid(%d) failed : %s", nobody->pw_uid, strerror(errno));
	exit(EXIT_FAILURE);
      }
    }

    if(getDebug()) {
      GETMYLIMIT(RLIMIT_MEMLOCK);
      GETMYLIMIT(RLIMIT_NPROC);
      GETMYLIMIT(RLIMIT_STACK);
      GETMYLIMIT(RLIMIT_CORE);
      GETMYLIMIT(RLIMIT_CPU);
      GETMYLIMIT(RLIMIT_DATA);
      GETMYLIMIT(RLIMIT_FSIZE);
      GETMYLIMIT(RLIMIT_RSS);
      GETMYLIMIT(RLIMIT_NOFILE);
      GETMYLIMIT(RLIMIT_AS);
      GETMYLIMIT(RLIMIT_LOCKS);
    }
  }

  /*_________________------------------------__________________
    _________________   evt_config_done      __________________
    -----------------________________________------------------
  */

  static void evt_config_done(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->dropPriv) {
      // don't need to be root any more - we held on to root privileges
      // to make sure we could write the pid file,  and open the output
      // file, and open the Xen handles, and delay the opening of the
      // ULOG socket until we knew the group-number, and on Debian and
      // Fedora 14 we needed to fork the DNSSD thread before dropping root
      // priviliges (something to do with mlockall()). Anway, from now on
      // we just don't want the responsibility...
      drop_privileges(sp, HSP_RLIMIT_MEMLOCK);
    }

    // did the polling interval change?
    updatePollingInterval(sp);

    // now that interfaces have been fully discovered (in evt_config_first)
    // and sflow agent is initialized, check to see if we should be exporting
    // individual counter data for switch port interfaces.  This may also
    // adjust the polling schedule to respect constraints.  (This is also called
    // if the interfaces change)
    configSwitchPorts(sp); // in readPackets.c

    // did the headerBytes setting change?
    updateHeaderBytes(sp);
  }

  /*_________________---------------------------__________________
    _________________     readSystemUUID        __________________
    -----------------___________________________------------------
  */

#define HSP_DMIDECODE_CMD "/usr/sbin/dmidecode"
#define HSP_DMIDECODE_LINELEN 1024

  static int readSystemUUIDLine(void *magic, char *line) {
    HSP *sp = (HSP *)magic;
    char *p = line;
    char *sep = " \t=:";
    char buf[HSP_DMIDECODE_LINELEN];
    char *tag = parseNextTok(&p, sep, NO, 0, YES, buf, HSP_DMIDECODE_LINELEN);
    if(my_strequal(tag, "UUID")) {
      char *uuid = parseNextTok(&p, sep, NO, 0, YES, buf, HSP_DMIDECODE_LINELEN);
      if(parseUUID(uuid, sp->system_uuid)) {
	myDebug(1, "readSystemUUID: <%s>", uuid);
	return NO; // got it - stop reading
      }
    }
    return YES; // keep reading
  }

  static int readSystemUUID(HSP *sp) {
    UTStringArray *cmd = strArrayNew();
    strArrayAdd(cmd, HSP_DMIDECODE_CMD);
    strArrayAdd(cmd,  NULL);
    char lineBuf[HSP_DMIDECODE_LINELEN];
    int status=-1;
    myExec(sp, strArray(cmd), readSystemUUIDLine, lineBuf, HSP_DMIDECODE_LINELEN, &status);
    strArrayFree(cmd);
    return status;
  }


  /*_________________---------------------------__________________
    _________________    chooseUUID             __________________
    -----------------___________________________------------------
  */
  static void chooseUUID(HSP *sp) {
    // select a UUID to use: preference is for:
    // (1) UUID specified on command line by -u <uuid>
    // (2) UUID found via readSystemUUID()
    // (3) UUID derived from machine id
    if(!isZeroUUID(sp->uuid)) {
      myDebug(1, "Using UUID passed on command line");
      return;
    }

    if(!isZeroUUID(sp->system_uuid)) {
      memcpy(sp->uuid, sp->system_uuid, 16);
      myDebug(1, "Using UUID read from BIOS (dmidecode)");
      return;
    }

    // Ideally we would generate a type-5 UUID (rfc 4122)
    // with the machine_id as the namespace UUID,  like this:
    // uuidgen_type5(sp->machine_id, "hsflowd");
    // but don't want to add dependency on libcrypto
    // here just to cover an unlikely fallback position,
    // so just make a type-5 UUID using the hash
    // function we already have...
    uint32_t mid_hash1 = my_binhash(sp->machine_id, 8);
    uint32_t mid_hash2 = my_binhash(sp->machine_id+8, 8);
    uint32_t *quads = (uint32_t *)sp->uuid;
    quads[0] = quads[2] = mid_hash1;
    quads[1] = quads[3] = mid_hash2;
    sp->uuid[6] &= 0x0F;
    sp->uuid[6] |= 0x50;
    sp->uuid[8] &= 0x3F;
    sp->uuid[8] |= 0x80;
  }


  /*_________________---------------------------__________________
    _________________      openLogFile          __________________
    -----------------___________________________------------------
  */

  static void openLogFile(HSP *sp) {
    FILE *f_dbg = getDebugOut();
    if(f_dbg
       && f_dbg != stdout
       && f_dbg != stderr) {
      // this may be a SIGHUP log rotation
      setDebugOut(NULL);
      fclose(f_dbg);
    }
    if(sp->logFile) {
      // logFile specified. Open it for logging.  May want to add, e.g. -ddd to increase
      // debug level,  or use "kill -USR2" to increase debug for already-running process.
      if((f_dbg = fopen(sp->logFile, "a")) == NULL) {
	myLog(LOG_ERR, "Failed to open debugLog %s : %s", sp->logFile, strerror(errno));
      }
      else {
	chmod(sp->logFile, 0666); // so we can reopen after privilege drop
	setlinebuf(f_dbg);
	setDebugOut(f_dbg);
	setDebugLimit(strtol(sp->logBytes, NULL, 0));
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    setMemoryLimit         __________________
    -----------------___________________________------------------
  */
  
  static void setMemoryLimit(HSP *sp) {
    if(sp->memLimit) {
      sp->memLimitBytes = strtol(sp->memLimit, NULL, 0);
    }
  }

  /*_________________---------------------------__________________
    _________________         main              __________________
    -----------------___________________________------------------
  */

  int main(int argc, char *argv[])
  {
    HSP *sp = &HSPSamplingProbe;

#ifdef UTHEAP
    UTHeapInit();
#endif
    
    // open syslog
    openlog(HSP_DAEMON_NAME, LOG_CONS, LOG_USER);
    setlogmask(LOG_UPTO(LOG_DEBUG));

    // register signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGXFSZ, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    // TODO: SIGPIPE? SIGCHLD?

    // init
    setDefaults(sp);

    // read the command line
    processCommandLine(sp, argc, argv);

    // log file may have been specified
    openLogFile(sp);

    // memory limit may have been specified
    setMemoryLimit(sp);

    // try to get the UUID from the BIOS because it is usually the most persistent,
    // and because hypervisors seem to set it up with the UUID that they know the VM by.
    // Used to do this as part of the startup script,  but moved it here so it would
    // work even when invoking hsflowd manually (without specifying -u <uuid>).  This
    // also helps to simplify the systemd unit file and avoids the need to add some
    // other script to the package.
    readSystemUUID(sp);

    // don't run if we think another one is already running
    // (unless we are obviously debugging manually with -ddd or above)
    if(getDebug() < 2
       && UTFileExists(sp->pidFile)) {
      myLog(LOG_ERR,"Another %s is already running. If this is an error, remove %s", argv[0], sp->pidFile);
      exit(EXIT_FAILURE);
    }

#ifdef GPROF
    myDebug(1, "GPROF ProfilerStart()");
    ProfilerStart("gperftools_cpu_profile");
    HeapProfilerStart("gperftools_heap_profile");
#endif

    if(getDaemon()) {
      // fork to daemonize
      pid_t pid = fork();
      if(pid < 0) {
	myLog(LOG_ERR,"Cannot fork child");
	exit(EXIT_FAILURE);
      }

      if(pid > 0) {
	// in parent - write pid file and exit
	FILE *f;
	if(!(f = fopen(sp->pidFile,"w"))) {
	  myLog(LOG_ERR,"Could not open the pid file %s for writing : %s", sp->pidFile, strerror(errno));
	  exit(EXIT_FAILURE);
	}
	fprintf(f,"%"PRIu64"\n",(uint64_t)pid);
	if(fclose(f) == -1) {
	  myLog(LOG_ERR,"Could not close pid file %s : %s", sp->pidFile, strerror(errno));
	  exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
      }
      else {
	// in child

	// make sure the output file we write cannot then be written by some other non-root user
	umask(S_IWGRP | S_IWOTH);

	// new session - with me as process group leader
	pid_t sid = setsid();
	if(sid < 0) {
	  myLog(LOG_ERR,"setsid failed");
	  exit(EXIT_FAILURE);
	}

	// close all file descriptors
	int i;
	for(i=getdtablesize(); i >= 0; --i) close(i);
	// create stdin/out/err
	// stdin
	if((i = open("/dev/null",O_RDWR)) == -1) {
	  myLog(LOG_ERR,"open /dev/null failed: %s", strerror(errno));
	  exit(EXIT_FAILURE);
	}
	// stdout
	if(dup(i) == -1) {
	  myLog(LOG_ERR,"dup() failed: %s", strerror(errno));
	  exit(EXIT_FAILURE);
	}
	// stderr
	if(dup(i) == -1) {
	  myLog(LOG_ERR,"dup() failed: %s", strerror(errno));
	  exit(EXIT_FAILURE);
	}
      }
    }

    // open the output file while we still have root priviliges.
    // use mode "w+" because we intend to write it and rewrite it.
    if((sp->f_out = fopen(sp->outputFile, "w+")) == NULL) {
      myLog(LOG_ERR, "cannot open output file %s : %s", sp->outputFile, strerror(errno));
      exit(EXIT_FAILURE);
    }

    // open a file we can use to write a crash dump (if necessary)
    if(sp->crashFile) {
      // the file pointer needs to be a global so it is accessible
      // to the signal handler
      if((f_crash = fopen(sp->crashFile, "w")) == NULL) {
	myLog(LOG_ERR, "cannot open output file %s : %s", sp->crashFile, strerror(errno));
	exit(EXIT_FAILURE);
      }
    }

    // force load of cJson lib here - even though it's currently
    // only used by dynamic-loaded modules.  (Could have let the modules
    // link to it themselves,  but it is not compiled with -fPIC and
    // I don't know how portable that option is.)
    cJSON_Hooks hooks;
    hooks.malloc_fn = my_calloc;
    hooks.free_fn = my_free;
    cJSON_InitHooks(&hooks);

    // allocate device tables - these ones need sync
    sp->adaptorsByName = UTHASH_NEW(SFLAdaptor, deviceName, UTHASH_SYNC | UTHASH_SKEY);
    sp->adaptorsByIndex = UTHASH_NEW(SFLAdaptor, ifIndex, UTHASH_SYNC);
    sp->adaptorsByPeerIndex = UTHASH_NEW(SFLAdaptor, peer_ifIndex, UTHASH_SYNC);
    sp->adaptorsByMac = UTHASH_NEW(SFLAdaptor, macs[0], UTHASH_SYNC);
    // sometimes need to suppress the deleting of adaptors for test purposes.
    sp->allowDeleteAdaptor = YES;

    // these ones do not need sync - always accessed from same thread
    sp->vmsByUUID = UTHASH_NEW(HSPVMState, uuid, UTHASH_DFLT);
    sp->vmsByDsIndex = UTHASH_NEW(HSPVMState, dsIndex, UTHASH_DFLT);

    // IPv4 addresses can represent themselves directly
    sp->localIP =  UTHASH_NEW(SFLAddress, address.ip_v4, UTHASH_DFLT);
    sp->localIP6 = UTHASH_NEW(SFLAddress, address.ip_v6, UTHASH_DFLT);

    // initialize event bus - moved this earlier so that sp->rootModule
    // is available for calls to EVDebug(mod,...) for all functions that
    // might expect it to be there.
    sp->rootModule = EVInit(sp);

    // read the host-id info up front, so we can include it in hsflowd.auto
    // (we'll read it again each time we send the counters)
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    readHidCounters(sp,
		    &hidElem.counterBlock.host_hid,
		    sp->hostname,
		    SFL_MAX_HOSTNAME_CHARS,
		    sp->os_release,
		    SFL_MAX_OSRELEASE_CHARS);

    // Helpful for version to be in every debug log.
    myLog(LOG_INFO, "%s version %s", argv[0], STRINGIFY_DEF(HSP_VERSION));
    
    // some modules can be triggered to load even if they are not
    // explicitly in the config file - but do this before we read
    // the config so that overrides are possible.
#ifdef HSP_LOAD_CUMULUS
    myLog(LOG_INFO, "autoload CUMULUS, NFLOG, PSAMPLE, SYSTEMD and DROPMON modules");
    sp->cumulus.cumulus = YES;
    sp->systemd.systemd = YES;
    // force the hardwareSampling flag on, to ensure that sampling-rate is handled correctly.
    // We used to only set this if and when mod_cumulus was able to call out to the script
    // to set the samplingRate, but that resulted in a race where software sampling was
    // configured and not subsequently retracted.  Now that sampling on Cumulus is configured
    // via tc(1) and handled via mod_psample the distinction is no longer needed anyway.
    sp->hardwareSampling = YES;
    // Cumulus Linux 2.5 or earlier used ULOG group 1
    // Cumulus Linux 3.0 or later used NFLOG group 1
    sp->nflog.nflog = YES;
    sp->nflog.group = 1;
    sp->nflog.ds_options = HSP_SAMPLEOPT_IF_SAMPLER
      | HSP_SAMPLEOPT_IF_POLLER
      | HSP_SAMPLEOPT_BRIDGE
      | HSP_SAMPLEOPT_DIRN_HOOK
      | HSP_SAMPLEOPT_NFLOG;
    // Cumulus Linux 4.0 or later uses PSAMPLE group 1
    // Note that the DIRN_HOOK is no longer available
    // and we assume ingress-only sampling
    sp->psample.psample = YES;
    sp->psample.ingress = YES;
    sp->psample.egress = NO;
    sp->psample.group = 1;
    // assume netlink drop-monitor is configured externally
    sp->dropmon.dropmon = YES;
    sp->dropmon.start = NO;
    sp->dropmon.limit = 1000;
    sp->dropmon.sw = NO;
    sp->dropmon.rn = NO;
    sp->dropmon.hw = YES;
#endif /* HSP_LOAD_CUMULUS */

#ifdef HSP_LOAD_DENT
    myLog(LOG_INFO, "autoload DENT, PSAMPLE modules");
    sp->dent.dent = YES;
    // force the hardwareSampling flag on, to ensure that sampling-rate is handled correctly.
    sp->hardwareSampling = YES;
    // default to PSAMPLE group 1, ingress only
    sp->psample.psample = YES;
    sp->psample.ingress = YES;
    sp->psample.egress = NO;
    sp->psample.group = 1;
#endif /* HSP_LOAD_DENT */

#ifdef HSP_LOAD_OPX
    // OPX should be compiled with "make deb FEATURES="OPX DBUS"
    myLog(LOG_INFO, "autoload OPX and DBUS modules");
    sp->opx.opx = YES;
    sp->dbus.dbus = YES;
#endif /* HSP_LOAD_OPX */

#ifdef HSP_LOAD_SONIC
    // SONIC should be compiled with "make deb FEATURES="SONIC"
    myLog(LOG_INFO, "autoload SONIC, PSAMPLE, DROPMON and NLROUTE modules");
    sp->sonic.sonic = YES;
    sp->sonic.unixsock = YES;
    sp->sonic.setIfAlias = YES;
    sp->sonic.setIfName = YES;
    sp->sonic.waitReady = HSP_SONIC_DEFAULT_WAITREADY_SECS;
    sp->sonic.suppressOther = YES;
    sp->psample.psample = YES;
    sp->psample.ingress = YES;
    sp->psample.egress = YES;
    sp->psample.group = 1; // Ingress PSAMPLE group number. Expects egress on (group+1).
    // include dropmon but only in passive mode, so that events will be sent but only if
    // DROPMON netlink channel is configured elsewhere. However if dropLimit is set in
    // redis then mod_sonic will request activation and these settings will be overridden
    // in mod_dropmon.c:evt_config_changed().
    sp->dropmon.dropmon = YES;
    sp->dropmon.start = NO;
    sp->dropmon.limit = HSP_DEFAULT_DROPLIMIT;;
    sp->dropmon.sw = NO;
    sp->dropmon.sw_passive = YES;
    sp->dropmon.rn = YES;
    sp->dropmon.hw = NO;
    sp->dropmon.hw_passive = YES;
#endif /* HSP_LOAD_SONIC */

#ifdef HSP_LOAD_XEN
    myLog(LOG_INFO, "autoload XEN and OVS modules");
    sp->xen.xen = YES;
    sp->ovs.ovs = YES;
#endif /* HSP_LOAD_XEN */

#ifdef HSP_LOAD_EOS
    myLog(LOG_INFO, "autoload EAPI module");
    sp->eapi.eapi = YES;
#endif /* HSP_LOAD_EOS */

    // a sucessful read of the config file is required
    if(HSPReadConfigFile(sp) == NO) {
      myLog(LOG_ERR, "failed to read config file");
      exit(EXIT_FAILURE);
    }

    if(sp->eapi.eapi && sp->DNSSD.DNSSD) {
      myLog(LOG_ERR, "cannot run eapi and dns-sd modules together");
      exit(EXIT_FAILURE);
    }

    if(sp->sonic.sonic && sp->DNSSD.DNSSD) {
      myLog(LOG_ERR, "cannot run sonic and dns-sd modules together");
      exit(EXIT_FAILURE);
    }

    if(sp->DNSSD.DNSSD
       || sp->sonic.sonic) {
      myDebug(1, "waitConfig: postpone readInterfaces and selectAgentAddress");
    }
    else {
      // must be able to read interfaces. Minimal discovery this time.
      // Just enough to decide on an agent address.  No ethtool probing.
      if(readInterfaces(sp, NO, NULL, NULL, NULL, NULL, NULL) == 0) {
	myLog(LOG_ERR, "failed to read interfaces");
	exit(EXIT_FAILURE);
      }
      
      // must be able to choose an agent address
      if(selectAgentAddress(sp, NULL, NULL) == NO) {
	myLog(LOG_ERR, "failed to select agent address");
	exit(EXIT_FAILURE);
      }
    }
    
    // seed the random number generator with the low order bits of the monotonic clock.
    // We used to use the agent address but this way it can be chosen later in the startup
    // sequence.
    struct timespec tsnow;
    EVClockMono(&tsnow);
    sfl_random_init(tsnow.tv_nsec);

    // Resolve which UUID we are going to use to represent this host
    chooseUUID(sp);

    // initialize the faster polling of NIO counters
    // to avoid undetected 32-bit wraps
    sp->nio_polling_secs = HSP_NIO_POLLING_SECS_32BIT;

    // convenience ptr to the poll-bus
    sp->pollBus = EVGetBus(sp->rootModule, HSPBUS_POLL, YES);

    // Events are going to be exchanged through this bus even before we start it running,
    // so have to make sure EVCurrentBus() is correct. Otherwise all events will be queued
    // as inter-thread events (changing the execution sequence).  For example, it is
    // important that HSPEVENT_INTF_READ propagates fully to all receivers on the poll-bus
    // before read_ethtool_info() is called on the next line in readInterfaces.c.
    EVCurrentBusSet(sp->pollBus);

    // set up the sFlow agent (with no pollers or samplers yet)
    sp->agent = initAgent(sp, &sp->agentIP, sp->subAgentId);
    sp->poll_agent = initAgent(sp, &sp->agentIP, sp->subAgentId+1);

    // register for events that we are going to handle here in the main pollBus thread.  The
    // events that form the config sequence are requested here before the modules are loaded
    // so that these functions are called first for each event. For example, a module callback
    // for HSPEVENT_CONFIG_FIRST will be called after evt_config_first() here,  but before
    // evt_config_done().

    // Events to feed lines of configuration in one line at a time
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_START), evt_config_start);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_LINE), evt_config_line);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_END), evt_config_end);

    // An event that is called once,  after the config is settled and
    // interfaces have been fully discovered, but before privileges are dropped
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_FIRST), evt_config_first);

    // An event that is called for every config change.
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);

    // A handshake event for sync across threads - to make sure CONFIG_FIRST and CONFIG_CHANGED
    // have been processed to completion by all threads (all buses) before CONFIG_DONE is sent.
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_SHAKE), evt_config_shake);
    // CONFIG_DONE is where privileges are dropped (the first time).
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_DONE), evt_config_done);

    // An event to request that a poller be started on the given interface
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_REQUEST_POLLER), evt_request_poller);

    // load modules (except DNSSD - loaded below).
    // The module init functions can assume that the
    // config is loaded,  but they can't assume anything
    // else.  Not even an agent-address. So all they should
    // really do at this stage is interpret config and
    // register for bus events.
    if(sp->json.json)
      EVLoadModule(sp->rootModule, "mod_json", sp->modulesPath);
    if(sp->kvm.kvm)
      EVLoadModule(sp->rootModule, "mod_kvm", sp->modulesPath);
    if(sp->xen.xen)
      EVLoadModule(sp->rootModule, "mod_xen", sp->modulesPath);
    if(sp->docker.docker)
      EVLoadModule(sp->rootModule, "mod_docker", sp->modulesPath);
    if(sp->containerd.containerd)
      EVLoadModule(sp->rootModule, "mod_containerd", sp->modulesPath);
    if(sp->k8s.k8s)
      EVLoadModule(sp->rootModule, "mod_k8s", sp->modulesPath);
    if(sp->pcap.pcap)
      EVLoadModule(sp->rootModule, "mod_pcap", sp->modulesPath);
    if(sp->tcp.tcp)
      EVLoadModule(sp->rootModule, "mod_tcp", sp->modulesPath);
    if(sp->ulog.ulog)
      EVLoadModule(sp->rootModule, "mod_ulog", sp->modulesPath);
    if(sp->nflog.nflog)
      EVLoadModule(sp->rootModule, "mod_nflog", sp->modulesPath);
    if(sp->psample.psample)
      EVLoadModule(sp->rootModule, "mod_psample", sp->modulesPath);
    if(sp->dropmon.dropmon)
      EVLoadModule(sp->rootModule, "mod_dropmon", sp->modulesPath);
    if(sp->nvml.nvml)
      EVLoadModule(sp->rootModule, "mod_nvml", sp->modulesPath);
    if(sp->ovs.ovs)
      EVLoadModule(sp->rootModule, "mod_ovs", sp->modulesPath);
    if(sp->cumulus.cumulus)
      EVLoadModule(sp->rootModule, "mod_cumulus", sp->modulesPath);
    if(sp->dent.dent)
      EVLoadModule(sp->rootModule, "mod_dent", sp->modulesPath);
    if(sp->opx.opx)
      EVLoadModule(sp->rootModule, "mod_opx", sp->modulesPath);
    if(sp->sonic.sonic)
      EVLoadModule(sp->rootModule, "mod_sonic", sp->modulesPath);
    if(sp->dbus.dbus)
      EVLoadModule(sp->rootModule, "mod_dbus", sp->modulesPath);
    if(sp->systemd.systemd)
      EVLoadModule(sp->rootModule, "mod_systemd", sp->modulesPath);
    if(sp->eapi.eapi)
      EVLoadModule(sp->rootModule, "mod_eapi", sp->modulesPath);
    if(sp->nlroute.nlroute)
      EVLoadModule(sp->rootModule, "mod_nlroute", sp->modulesPath);
    if(sp->vpp.vpp)
      EVLoadModule(sp->rootModule, "mod_vpp", sp->modulesPath);

    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, EVEVENT_TICK), evt_poll_tick);

    // set the packetBus pointer if anyone requested it (will be NULL for counters-only config)
    sp->packetBus = EVGetBus(sp->rootModule, HSPBUS_PACKET, NO);
    if(sp->packetBus) {
      // intercept XDR-encoded counter samples, so that instead of sending them
      // out via the poll_agent we copy them across to the packetBus agent to be
      // spliced into the outgoing sFlow feed.
      sfl_agent_init_sfdg_hookFn(sp->poll_agent, sfdgCB_hook_counter_sample);
      EVEventRx(sp->rootModule, EVGetEvent(sp->packetBus, HSPEVENT_XDR_SAMPLE), evt_pkt_xdr_sample);
      // and the packet bus needs it's own tick()
      EVEventRx(sp->rootModule, EVGetEvent(sp->packetBus, EVEVENT_TICK), evt_pkt_tick);
    }
    // make sure every thread is notified on a change to the actual polling interval
    EVEventRxAll(sp->rootModule, HSPEVENT_POLL_INTERVAL, evt_all_poll_interval);
    // make sure every thread is notified on a change to the header bytes setting
    EVEventRxAll(sp->rootModule, HSPEVENT_HEADER_BYTES, evt_all_header_bytes);
      
    if(sp->DNSSD.DNSSD) {
      EVLoadModule(sp->rootModule, "mod_dnssd", sp->modulesPath);
      // DNS-SD will run in HSPBUS_CONFIG thread.  It will be responsible for
      // the sFlowSettings,  and the program will stay in a holding
      // pattern until the first valid config comes in.

      // Mechanism: configBus will send ticks to mod_dnssd module,
      // which will use them to make periodic DNS requests for SRV and TXT
      // records.  Those records will be passed back line-by-line using events on
      // the pollBus (which means they will come in via the pollBus pipe for
      // synchronization).  The main thread handles these HSPEVENT_CONFIG_*
      // events and assembles the new config.  When it is complete it sends
      // HSPEVENT_CONFIG_CHANGED to both the pollBus and the packetBus.
      // So a sequence of:
      //   config_start
      //     config_line
      //     config_line
      //      ...
      //   config_end
      // then triggers a sequence of:
      //   config_first (if it was the first time)
      //   config_changed
      //   config_shake
      //   config_done
    }

    // may decide to make this the default at some point,  but that
    // might be a breaking change in some places where the agent=xxx
    // setting is wrong.
    // sp->agentDeviceStrict = YES;

    // check for module debug actions early
    checkForDebugActions(sp);

    if(sp->DNSSD.DNSSD
       || sp->sonic.sonic) {
      // mod_dnssd and mod_sonic should start with a blank config.
      // Sending should be suppressed until the config (especially agentIP)
      // are fully established.
      // TODO: should this apply to EAPI too?
      sp->suppress_sendPkt_waitConfig = YES;
    }
    else {
      // For all other cases we just push in the config from the file.
      // This will trigger a HSPEVENT_CONFIG_CHANGED right away.
      installSFlowSettings(sp, sp->sFlowSettings_file);
    }

    // have every thread call in every second
    EVEventRxAll(sp->rootModule, EVEVENT_TOCK, evt_all_tock);

    // start all buses, with pollBus in this thread
    EVRun(sp->pollBus);

    // get here if a signal kicks EVStop() and we break out of the loop above.
    // The modules can get final/end events if they need to clean up.

    closelog();
    myLog(LOG_INFO,"stopped");

    if(getDebug() == 0) {
      // shouldn't need to be root again to remove the pidFile
      // (i.e. we should still have execute permission on /var/run)
      remove(sp->pidFile);
    }

#ifdef GPROF
    myDebug(1, "GPROF ProfilerStop()");
    ProfilerFlush();
    ProfilerStop();
    HeapProfilerDump("hsflowd exit");
    HeapProfilerStop();
#endif
    
    exit(exitStatus);
  } /* main() */

#if defined(__cplusplus)
} /* extern "C" */
#endif
