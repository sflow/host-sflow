/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#define HSFLOWD_MAIN

#include "hsflowd.h"
#include "cpu_utils.h"

#ifdef HSF_PCAP
  // includes for setsockopt(SO_ATTACH_FILTER)
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#endif
  
  // globals - easier for signal handler
  HSP HSPSamplingProbe;
  int exitStatus = EXIT_SUCCESS;
  extern int debug;
  FILE *f_crash;
  extern int daemonize;

  static void installSFlowSettings(HSPSFlow *sf, HSPSFlowSettings *settings);
  static void setPacketSamplingRates(HSPSFlow *sf, HSPSFlowSettings *settings);

  /*_________________---------------------------__________________
    _________________     agent callbacks       __________________
    -----------------___________________________------------------
  */
  
  static void *agentCB_alloc(void *magic, SFLAgent *agent, size_t bytes)
  {
    return my_calloc(bytes);
  }

  static int agentCB_free(void *magic, SFLAgent *agent, void *obj)
  {
    my_free(obj);
    return 0;
  }

  static void agentCB_error(void *magic, SFLAgent *agent, char *msg)
  {
    myLog(LOG_ERR, "sflow agent error: %s", msg);
  }

  
  static void agentCB_sendPkt(void *magic, SFLAgent *agent, SFLReceiver *receiver, u_char *pkt, uint32_t pktLen)
  {
    HSP *sp = (HSP *)magic;
    size_t socklen = 0;
    int fd = 0;

    // note that we are relying on any new settings being installed atomically from the DNS-SD
    // thread (it's just a pointer move,  so it should be atomic).  Otherwise we would want to
    // grab sf->config_mut whenever we call sfl_sampler_writeFlowSample(),  because that can
    // bring us here where we read the list of collectors.

    for(HSPCollector *coll = sp->sFlow->sFlowSettings->collectors; coll; coll=coll->nxt) {
	
      switch(coll->ipAddr.type) {
      case SFLADDRESSTYPE_UNDEFINED:
	// skip over it if the forward lookup failed
	break;
      case SFLADDRESSTYPE_IP_V4:
	{
	  struct sockaddr_in *sa = (struct sockaddr_in *)&(coll->sendSocketAddr);
	  socklen = sizeof(struct sockaddr_in);
	  sa->sin_family = AF_INET;
	  sa->sin_port = htons(coll->udpPort);
	  fd = sp->socket4;
	}
	break;
      case SFLADDRESSTYPE_IP_V6:
	{
	  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&(coll->sendSocketAddr);
	  socklen = sizeof(struct sockaddr_in6);
	  sa6->sin6_family = AF_INET6;
	  sa6->sin6_port = htons(coll->udpPort);
	  fd = sp->socket6;
	}
	break;
      }
	
      if(socklen && fd > 0) {
	int result = sendto(fd,
			    pkt,
			    pktLen,
			    0,
			    (struct sockaddr *)&coll->sendSocketAddr,
			    socklen);
	if(result == -1 && errno != EINTR) {
	  myLog(LOG_ERR, "socket sendto error: %s", strerror(errno));
	}
	if(result == 0) {
	  myLog(LOG_ERR, "socket sendto returned 0: %s", strerror(errno));
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   adaptor utils           __________________
    -----------------___________________________------------------
  */

  SFLAdaptor *nioAdaptorNew(char *dev, u_char *macBytes, uint32_t ifIndex) {
    return adaptorNew(dev, macBytes, sizeof(HSPAdaptorNIO), ifIndex);
  }
			    
  SFLAdaptor *adaptorByName(HSP *sp, char *dev) {
    SFLAdaptor ad = { .deviceName = trimWhitespace(dev) };
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

  void deleteAdaptor(HSP *sp, SFLAdaptor *ad, int freeFlag) {
    UTHashDel(sp->adaptorsByName, ad);
    UTHashDel(sp->adaptorsByIndex, ad);
    UTHashDel(sp->adaptorsByPeerIndex, ad);
    UTHashDel(sp->adaptorsByMac, ad);
    if(freeFlag) adaptorFree(ad);
  }
    
  int deleteMarkedAdaptors(HSP *sp, UTHash *adaptorHT, int freeFlag) {
    int found = 0;
    SFLAdaptor *ad;
    UTHASH_WALK(adaptorHT, ad) if(ad->marked) {
      deleteAdaptor(sp, ad, freeFlag);
      found++;
    }
    return found;
  }

  int deleteMarkedAdaptors_adaptorList(HSP *sp, SFLAdaptorList *adList) {
    int found = 0;
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(adList, ad) if(ad->marked) {
      deleteAdaptor(sp, ad, NO);
      found++;
    }
    return found;
  }

  void adaptorHTPrint(UTHash *ht, char *prefix) {
    SFLAdaptor *ad;
    UTHASH_WALK(ht, ad) {
      u_char macstr[13];
      macstr[0] = '\0';
      if(ad->num_macs) printHex(ad->macs[0].mac, 6, macstr, 13, NO);
      myLog(LOG_INFO, "%s: ifindex: %u peer: %u nmacs: %u mac0: %s name: %s",
	    prefix,
	    ad->ifIndex,
	    ad->peer_ifIndex,
	    ad->num_macs,
	    macstr,
	    ad->deviceName);
    }
  }

#ifdef HSP_SWITCHPORT_REGEX
  static int compile_swp_regex(HSP *sp) {
    int err = regcomp(&sp->swp_regex, HSP_SWITCHPORT_REGEX, REG_EXTENDED | REG_NOSUB | REG_NEWLINE);
    if(err) {
      char errbuf[101];
      myLog(LOG_ERR, "regcomp(%s) failed: %s", HSP_SWITCHPORT_REGEX, regerror(err, &sp->swp_regex, errbuf, 100));
      return NO;
    }
    return YES;
  }
#endif

#ifndef HSF_XEN
  static SFLAdaptorList *host_adaptors(HSP *sp, SFLAdaptorList *myAdaptors, int capacity)
  {
    // build the list of adaptors that are up and have non-empty MACs,
    // and are not veth connectors to peers inside containers,
    // but stop if we hit the capacity
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      if(adaptor->peer_ifIndex == 0) {
	HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
	if(niostate->up
	   && (niostate->switchPort == NO)
	   && adaptor->num_macs
	   && !isZeroMAC(&adaptor->macs[0])) {
	  if(myAdaptors->num_adaptors >= capacity) break;
	  myAdaptors->adaptors[myAdaptors->num_adaptors++] = adaptor;
	}
      }
    }
    return myAdaptors;
  }
#endif

  void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
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

#ifdef HSF_NVML
    SFLCounters_sample_element nvmlElem = { 0 };
    nvmlElem.tag = SFLCOUNTERS_HOST_GPU_NVML;
    if(readNvmlCounters(sp, &nvmlElem.counterBlock.host_gpu_nvml)) {
      SFLADD_ELEMENT(cs, &nvmlElem);
    }
#endif

#ifdef HSF_CUMULUS
    SFLCounters_sample_element bcmElem = { 0 };
    bcmElem.tag = SFLCOUNTERS_BCM_TABLES;
    if(readBroadcomCounters(sp, &bcmElem.counterBlock.bcm_tables)) {
      SFLADD_ELEMENT(cs, &bcmElem);
    }
#endif

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

#ifdef HSF_CUMULUS
    // don't send L4 stats from switches.  Save the space for other things.
#else
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
#endif

    // include the adaptor list
    SFLCounters_sample_element adaptorsElem = { 0 };
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
#ifdef HSF_XEN
    // collect list of host adaptors that do not belong to VMs
    SFLAdaptorList myAdaptors;
    SFLAdaptor *adaptors[HSP_MAX_VIFS];
    myAdaptors.adaptors = adaptors;
    myAdaptors.capacity = HSP_MAX_VIFS;
    myAdaptors.num_adaptors = 0;
    adaptorsElem.counterBlock.adaptors = xenstat_adaptors(sp, XEN_DOMID_PHYSICAL, &myAdaptors, HSP_MAX_VIFS);
#else
    // collect list of host adaptors that are up, and have non-zero MACs.  This
    // also leaves out interfaces that have a peer (type=veth),  so it works for
    // KVM/libvirt and Docker too.
    SFLAdaptorList myAdaptors;
    SFLAdaptor *adaptors[HSP_MAX_PHYSICAL_ADAPTORS];
    myAdaptors.adaptors = adaptors;
    myAdaptors.capacity = HSP_MAX_PHYSICAL_ADAPTORS;
    myAdaptors.num_adaptors = 0;
    adaptorsElem.counterBlock.adaptors = host_adaptors(sp, &myAdaptors, HSP_MAX_PHYSICAL_ADAPTORS);
#endif
    SFLADD_ELEMENT(cs, &adaptorsElem);

    // hypervisor node stats
#if defined(HSF_XEN) || defined(HSF_DOCKER) || defined(HSF_VRT)
    SFLCounters_sample_element vnodeElem = { 0 };
    vnodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
#if defined(HSF_XEN)
    if(readXenVNodeCounters(sp, &vnodeElem.counterBlock.host_vrt_node)) {
      SFLADD_ELEMENT(cs, &vnodeElem);
    }
#else
    // Populate the vnode struct with metrics for the
    // physical host that we kept from above.
    vnodeElem.counterBlock.host_vrt_node.mhz = sp->cpu_mhz;
    vnodeElem.counterBlock.host_vrt_node.cpus = sp->cpu_cores;
    vnodeElem.counterBlock.host_vrt_node.num_domains = sp->num_domains;
    vnodeElem.counterBlock.host_vrt_node.memory = sp->mem_total;
    vnodeElem.counterBlock.host_vrt_node.memory_free = sp->mem_free;
    SFLADD_ELEMENT(cs, &vnodeElem);
#endif /* HSF_XEN */
#endif /* HSF_XEN || HSF_DOCKER || HSF_VRT */

    sfl_poller_writeCountersSample(poller, cs);
  }
  
  /*_________________---------------------------__________________
    _________________    persistent dsIndex     __________________
    -----------------___________________________------------------
  */

#if defined(HSF_XEN) || defined(HSF_VRT) || defined(HSF_DOCKER)


  uint32_t assignVM_dsIndex(HSP *sp, HSPVMState *state) {
    uint32_t first = HSP_DEFAULT_LOGICAL_DSINDEX_START;
    uint32_t last = HSP_DEFAULT_APP_DSINDEX_START - 1;
    uint32_t range = last - first + 1;

    if(sp->vmsByDsIndex->entries >= range) {
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
	UTHashAdd(sp->vmsByDsIndex, state, YES);
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
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  HSPVMState *getVM(HSP *sp, char *uuid, EnumVMType vmType, getCountersFn_t getCountersFn) {
    HSPVMState search;
    memset(&search, 0, sizeof(search));
    memcpy(search.uuid, uuid, 16);
    HSPVMState *vm = UTHashGet(sp->vmsByUUID, &search);
    if(vm == NULL) {
      // new vm or container
      vm = (HSPVMState *)my_calloc(sizeof(HSPVMState));
      memcpy(vm->uuid, uuid, 16);
      UTHashAdd(sp->vmsByUUID, vm, NO);
      vm->created = YES;
      vm->vmType = vmType;
      vm->volumes = strArrayNew();
      vm->disks = strArrayNew();
      vm->interfaces = adaptorListNew();
      sp->refreshAdaptorList = YES;
      if(assignVM_dsIndex(sp, vm)) {
	SFLDataSource_instance dsi;
	// ds_class = <virtualEntity>, ds_index = offset + <assigned>, ds_instance = 0
	SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, vm->dsIndex, 0);
	vm->poller = sfl_agent_addPoller(sp->sFlow->agent, &dsi, sp, getCountersFn);
	vm->poller->userData = vm;
	sfl_poller_set_sFlowCpInterval(vm->poller, sp->sFlow->sFlowSettings->pollingInterval);
	sfl_poller_set_sFlowCpReceiver(vm->poller, HSP_SFLOW_RECEIVER_INDEX);
      }
    }
    return vm;
  }


  static void removeAndFreeVM(HSP *sp, HSPVMState *vm) {
    if(debug) {
      myLog(LOG_INFO, "removeAndFreeVM: removing vm with dsIndex=%u (domId=%u)",
	    vm->dsIndex,
	    vm->domId);
    }
    UTHashDel(sp->vmsByUUID, vm);
    UTHashDel(sp->vmsByDsIndex, vm);
    if(vm->disks) strArrayFree(vm->disks);
    if(vm->volumes) strArrayFree(vm->volumes);
    if(vm->interfaces) {
      adaptorListMarkAll(vm->interfaces);
      // delete any hash-table references to these adaptors
      deleteMarkedAdaptors_adaptorList(sp, vm->interfaces);
      // then free them along with the adaptorList itself
      adaptorListFree(vm->interfaces);
    }
    if(vm->poller) {
      vm->poller->userData = NULL;
      sfl_agent_removePoller(sp->sFlow->agent, &vm->poller->dsi);
    }
    my_free(vm);
    sp->refreshAdaptorList = YES;
  }

  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */
  
  static void configVMs(HSP *sp) {
    if(debug) myLog(LOG_INFO, "configVMs");
    // mark and sweep
    // 1. mark all the current virtual pollers
    HSPVMState *state;
    UTHASH_WALK(sp->vmsByUUID, state) {
      state->marked = YES;
    }
    
    // 2. create new VM pollers, or clear the mark on existing ones
#ifdef HSF_XEN
    configVMs_XEN(sp);
#endif
#ifdef HSF_VRT
    configVMs_VRT(sp);
#endif
#ifdef HSF_DOCKER
    configVMs_DOCKER(sp);
#endif
    
    // 3. remove any VMs (and their pollers) that don't survive
    UTHASH_WALK(sp->vmsByUUID, state) {
      if(state->marked) {
	removeAndFreeVM(sp, state);
      }
    }
  }

#endif /* HSF_XEN || HSF_VRT || HSF_DOCKER */
    
  /*_________________---------------------------__________________
    _________________       printIP             __________________
    -----------------___________________________------------------
  */
  
  static const char *printIP(SFLAddress *addr, char *buf, size_t len) {
    return inet_ntop(addr->type == SFLADDRESSTYPE_IP_V6 ? AF_INET6 : AF_INET,
		     &addr->address,
		     buf,
		     len);
  }

  /*_________________---------------------------__________________
    _________________    syncOutputFile         __________________
    -----------------___________________________------------------
  */
  
  static void syncOutputFile(HSP *sp) {
    if(debug) myLog(LOG_INFO, "syncOutputFile");
    rewind(sp->f_out);
    fprintf(sp->f_out, "# WARNING: Do not edit this file. It is generated automatically by hsflowd.\n");

    // revision appears both at the beginning and at the end
    fprintf(sp->f_out, "rev_start=%u\n", sp->sFlow->revisionNo);
    if(sp->sFlow && sp->sFlow->sFlowSettings_str) fputs(sp->sFlow->sFlowSettings_str, sp->f_out);
    // repeat the revision number. The reader knows that if the revison number
    // has not changed under his feet then he has a consistent config.
    fprintf(sp->f_out, "rev_end=%u\n", sp->sFlow->revisionNo);
    fflush(sp->f_out);
    // chop off anything that may be lingering from before
    truncateOpenFile(sp->f_out);
  }

  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */
  
  static void tick(HSP *sp) {
    
    // send a tick to the sFlow agent
    sfl_agent_tick(sp->sFlow->agent, sp->clk);
    
    // possibly poll the nio counters to avoid 32-bit rollover
    if(sp->nio_polling_secs &&
       ((sp->clk % sp->nio_polling_secs) == 0)) {
      updateNioCounters(sp, NULL);
    }

#ifdef HSF_PCAP
    // read pcap stats to get drops - will go out with
    // packet samples sent from readPackets.c
    for(BPFSoc *bpfs = sp->bpf_socs; bpfs; bpfs = bpfs->nxt) {
      struct pcap_stat stats;
      if(pcap_stats(bpfs->pcap, &stats) == 0) {
	bpfs->drops = stats.ps_drop;
      }
    }
#endif


#if defined(HSF_XEN) || defined(HSF_DOCKER) || defined(HSF_VRT)
    // refresh the list of VMs periodically or on request
    if(sp->refreshVMList || (sp->clk % sp->refreshVMListSecs) == 0) {
      sp->refreshVMList = NO;
      configVMs(sp);
    }
#endif

    // refresh the interface list periodically or on request
    if(sp->refreshAdaptorList || (sp->clk % sp->refreshAdaptorListSecs) == 0) {
      sp->refreshAdaptorList = NO;
      uint32_t ad_added=0, ad_removed=0, ad_cameup=0, ad_wentdown=0, ad_changed=0;
      if(readInterfaces(sp, &ad_added, &ad_removed, &ad_cameup, &ad_wentdown, &ad_changed) == 0) {
	myLog(LOG_ERR, "failed to re-read interfaces\n");
      }
      else {
	if(debug) {
	  myLog(LOG_INFO, "interfaces added: %u removed: %u cameup: %u wentdown: %u changed: %u",
		ad_added, ad_removed, ad_cameup, ad_wentdown, ad_changed);
	}
      }

      int agentAddressChanged=NO;
      if(selectAgentAddress(sp, &agentAddressChanged) == NO) {
	  myLog(LOG_ERR, "failed to re-select agent address\n");
      }
      if(debug) {
	myLog(LOG_INFO, "agentAddressChanged=%s", agentAddressChanged ? "YES" : "NO");
      }

      if(sp->DNSSD == NO) {
	// see if we need to kick anything
	if(agentAddressChanged) {
	  // DNS-SD is not running so we have to kick the config
	  // to make it flush this change.  If DNS-SD is running then
	  // this will happen automatically the next time the config
	  // is checked (don't want to call it from here now because
	  // when DNS-SD is running then installSFlowSettings() is
	  // only called from that thread).
	  installSFlowSettings(sp->sFlow, sp->sFlow->sFlowSettings);
	}
	if(ad_added || ad_cameup || ad_wentdown || ad_changed) {
	  // set sampling rates again because ifSpeeds may have changed
	  setPacketSamplingRates(sp->sFlow, sp->sFlow->sFlowSettings);
	}
      }

#ifdef HSP_SWITCHPORT_REGEX
      configSwitchPorts(sp); // in readPackets.c
#endif
    }

#ifdef HSF_JSON
    // give the JSON module a chance to remove idle apps
    if(sp->clk % HSP_JSON_APP_TIMEOUT) {
      json_app_timeout_check(sp);
    }

#endif

    // rewrite the output if the config has changed
    if(sp->outputRevisionNo != sp->sFlow->revisionNo) {
      syncOutputFile(sp);
      sp->outputRevisionNo = sp->sFlow->revisionNo;
    }

#ifdef HSF_NVML
    // poll the GPU
    nvml_tick(sp);
#endif

  }

#ifdef HSF_ULOG
  /*_________________---------------------------__________________
    _________________     openULOG              __________________
    -----------------___________________________------------------
    Have to do this before we relinquish root privileges.  
  */

  static void openULOG(HSP *sp)
  {
    // open the netfilter socket to ULOG
    sp->ulog_soc = socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
    if(sp->ulog_soc > 0) {
      if(debug) myLog(LOG_INFO, "ULOG socket fd=%d", sp->ulog_soc);
      
      // set the socket to non-blocking
      int fdFlags = fcntl(sp->ulog_soc, F_GETFL);
      fdFlags |= O_NONBLOCK;
      if(fcntl(sp->ulog_soc, F_SETFL, fdFlags) < 0) {
	myLog(LOG_ERR, "ULOG fcntl(O_NONBLOCK) failed: %s", strerror(errno));
      }
      
      // make sure it doesn't get inherited, e.g. when we fork a script
      fdFlags = fcntl(sp->ulog_soc, F_GETFD);
      fdFlags |= FD_CLOEXEC;
      if(fcntl(sp->ulog_soc, F_SETFD, fdFlags) < 0) {
	myLog(LOG_ERR, "ULOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
      }
      
      // bind
      sp->ulog_bind.nl_family = AF_NETLINK;
      sp->ulog_bind.nl_pid = getpid();
      // Note that the ulogGroup setting is only ever retrieved from the config file (i.e. not settable by DNSSD)
      sp->ulog_bind.nl_groups = 1 << (sp->sFlow->sFlowSettings_file->ulogGroup - 1); // e.g. 16 => group 5
      if(bind(sp->ulog_soc, (struct sockaddr *)&sp->ulog_bind, sizeof(sp->ulog_bind)) == -1) {
	myLog(LOG_ERR, "ULOG bind() failed: %s", strerror(errno));
      }
      
      // increase receiver buffer size
      uint32_t rcvbuf = HSP_ULOG_RCV_BUF;
      if(setsockopt(sp->ulog_soc, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
	myLog(LOG_ERR, "setsockopt(SO_RCVBUF=%d) failed: %s", HSP_ULOG_RCV_BUF, strerror(errno));
      }
    }
    else {
      myLog(LOG_ERR, "error opening ULOG socket: %s", strerror(errno));
      // just disable it
      sp->ulog_soc = 0;
    }
  }
#endif

#ifdef HSF_NFLOG

  /*_________________---------------------------__________________
    _________________     openNFLOG             __________________
    -----------------___________________________------------------
  */

  static int bind_group_nflog(struct nfnl_handle *nfnl, uint32_t group)
  {
    // need a sub-system handle too.  Seems odd that it's still called NFNL_SUBSYS_ULOG,  but this
    // works so I'm not arguing:
    struct nfnl_subsys_handle *subsys = nfnl_subsys_open(nfnl, NFNL_SUBSYS_ULOG, NFULNL_MSG_MAX, 0);
    if(!subsys) {
      myLog(LOG_ERR, "NFLOG nfnl_subsys_open() failed: %s", strerror(errno));
      return NO;
    }
    /* These details were borrowed from libnetfilter_log.c */
    union {
      char buf[NFNL_HEADER_LEN
	       +NFA_LENGTH(sizeof(struct nfulnl_msg_config_cmd))];
      struct nlmsghdr nmh;
    } u;
    struct nfulnl_msg_config_cmd cmd;
    nfnl_fill_hdr(subsys, &u.nmh, 0, 0, group,
		  NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);
    cmd.command =  NFULNL_CFG_CMD_BIND;
    nfnl_addattr_l(&u.nmh, sizeof(u), NFULA_CFG_CMD, &cmd, sizeof(cmd));
    if(nfnl_query(nfnl, &u.nmh) < 0) {
      myLog(LOG_ERR, "NFLOG bind group failed: %s", strerror(errno));
      return NO;
    }
    return YES;
  }

  static void openNFLOG(HSP *sp)
  {
    // open the netfilter socket to ULOG
    sp->nfnl = nfnl_open();
    if(sp->nfnl == NULL) {
      myLog(LOG_ERR, "nfnl_open() failed: %s\n", strerror(errno));
      return;
    }

    /* subscribe to group  */
    if(!bind_group_nflog(sp->nfnl, sp->sFlow->sFlowSettings_file->nflogGroup)) {
      myLog(LOG_ERR, "bind_group_nflog() failed\n");
      return;
    }      
 
    // increase receiver buffer size
    nfnl_set_rcv_buffer_size(sp->nfnl, HSP_NFLOG_RCV_BUF);

    // get the fd
    sp->nflog_soc = nfnl_fd(sp->nfnl);
    if(debug) myLog(LOG_INFO, "NFLOG socket fd=%d", sp->nflog_soc);
 
    // set the socket to non-blocking
    int fdFlags = fcntl(sp->nflog_soc, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(sp->nflog_soc, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "NFLOG fcntl(O_NONBLOCK) failed: %s", strerror(errno));
    }
      
    // make sure it doesn't get inherited, e.g. when we fork a script
    fdFlags = fcntl(sp->nflog_soc, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(sp->nflog_soc, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "NFLOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
    }
  }

#endif // HSF_NFLOG

#ifdef HSF_JSON
  /*_________________---------------------------__________________
    _________________     openJSON              __________________
    -----------------___________________________------------------
  */


  static int openUDPListenSocket(char *bindaddr, int family, uint16_t port, uint32_t bufferSize)
  {
    struct sockaddr_in myaddr_in = { 0 };
    struct sockaddr_in6 myaddr_in6 = { 0 };
    SFLAddress loopbackAddress = { 0 };
    int soc = 0;

    // create socket
    if((soc = socket(family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      myLog(LOG_ERR, "error opening socket: %s", strerror(errno));
      return 0;
    }
      
    // set the socket to non-blocking
    int fdFlags = fcntl(soc, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(soc, F_SETFL, fdFlags) < 0) {
      myLog(LOG_ERR, "fcntl(O_NONBLOCK) failed: %s", strerror(errno));
      close(soc);
      return 0;
    }

    // make sure it doesn't get inherited, e.g. when we fork a script
    fdFlags = fcntl(soc, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(soc, F_SETFD, fdFlags) < 0) {
      myLog(LOG_ERR, "ULOG fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
    }
      
    // lookup bind address
    struct sockaddr *psockaddr = (family == PF_INET6) ?
      (struct sockaddr *)&myaddr_in6 :
      (struct sockaddr *)&myaddr_in;
    if(lookupAddress(bindaddr, psockaddr, &loopbackAddress, family) == NO) {
      myLog(LOG_ERR, "error resolving <%s> : %s", bindaddr, strerror(errno));
      close(soc);
      return 0;
    }

    // bind
    if(family == PF_INET6) myaddr_in6.sin6_port = htons(port);
    else myaddr_in.sin_port = htons(port);
    if(bind(soc,
	    psockaddr,
	    (family == PF_INET6) ?
	    sizeof(myaddr_in6) :
	    sizeof(myaddr_in)) == -1) {
      myLog(LOG_ERR, "bind(%s) failed: %s", bindaddr, strerror(errno));
      close(soc); 
      return 0;
    }

    // increase receiver buffer size
    uint32_t rcvbuf = bufferSize;
    if(setsockopt(soc, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
      myLog(LOG_ERR, "setsockopt(SO_RCVBUF=%d) failed: %s", bufferSize, strerror(errno));
    }

    return soc;
  }

#endif


#ifdef HSF_PCAP
  /*_________________---------------------------__________________
    _________________   setKernelSampling       __________________
    -----------------___________________________------------------

    https://www.kernel.org/doc/Documentation/networking/filter.txt

    Apply a packet-sampling BPF filter to the socket we are going
    to read packets from.  We could possibly have expressed this
    as a struct bpf_program and called the libpcap pcap_setfilter()
    to set the filter,  but that would have involved re-casting the
    instructions becuse the struct bpf_insn differs from the
    from the kernel's struct sock_filter.  The only way this
    makes sense is if the filter makes it all the way into the
    kernel and works using the SKF_AD_RANDOM negative-offset hack,
    so here we just try it directly.
    (Since pcap_setfilter() calls fix_offset() to adust the width
    of the offset fields there was a risk that putting in an
    offset of, say,  -56 would come out differently in the
    resulting sock_filter).
    There is an assumption here that SF_AD_RANDOM will always
    be offset=-56 (== 0xffffff038) and that the other opcodes
    will not change their values either.
  */

  static uint64_t kernelVer64(HSP *sp) {
    // return the kernel version as an integer,  so that
    // for example "4.3.3" becomes 400030003000.  This
    // makes it easier to test for kernel > x.y.z at
    // runtime.
    char buf[8];
    char *p = sp->os_release;
    uint64_t ver = 0;
    for(int ii = 0; ii < 3; ii++) {
      char *str = parseNextTok(&p, ".", NO, 0, NO, buf, 8);
      if(str) ver = (ver * 1000) + strtol(str, NULL, 0);
    }
    return ver;
  }
    
  static int setKernelSampling(HSP *sp, BPFSoc *bpfs)
  {
    if(debug) {
      myLog(LOG_INFO, "PCAP: setKernelSampling() kernel version (as int) == %"PRIu64,
	    kernelVer64(sp));
    }
    
    if(kernelVer64(sp) < 3019000L) {
      // kernel earlier than 3.19 == not new enough.
      // This would fail silently,  so we have to bail
      // here and rely on uesr-space sampling.  It may
      // have come in before 3.19,  but this is the
      // earliest version that I have tested on
      // successfully.
      myLog(LOG_ERR, "PCAP: warning: kernel too old for BPF sampling. Fall back on user-space sampling.");
      return NO;
    }
    
    struct sock_filter code[] = {
      { 0x20,  0,  0, 0xfffff038 }, // ld rand
      { 0x94,  0,  0, 0x00000100 }, // mod #256
      { 0x15,  0,  1, 0x00000001 }, // jneq #1, drop
      { 0x06,  0,  0, 0xffffffff }, // ret #-1
      { 0x06,  0,  0, 0000000000 }, // drop: ret #0
    };
    
    // overwrite the sampling-rate
    code[1].k = bpfs->samplingRate;
    if(debug) myLog(LOG_INFO, "PCAP: sampling rate set to %u for dev=%s", code[1].k, bpfs->deviceName);
    struct sock_fprog bpf = {
      .len = 5, // ARRAY_SIZE(code),
      .filter = code,
    };
    
    // install the filter
    int status = setsockopt(bpfs->soc, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if(debug) myLog(LOG_INFO, "PCAP: setsockopt (SO_ATTACH_FILTER) status=%d", status);
    if(status == -1) {
      myLog(LOG_ERR, "PCAP: setsockopt (SO_ATTACH_FILTER) status=%d : %s", status, strerror(errno));
      return NO;
    }

    // success - now we don't need to sub-sample in user-space
    bpfs->subSamplingRate = 1;
    if(debug) myLog(LOG_INFO, "PCAP: kernel sampling OK");
    return YES;
  }
#endif /* HSF_PCAP */
  
  /*_________________---------------------------__________________
    _________________         initAgent         __________________
    -----------------___________________________------------------
  */
  
  static int initAgent(HSP *sp)
  {
    if(debug) myLog(LOG_INFO,"creating sfl agent");

    HSPSFlow *sf = sp->sFlow;
    
    if(sf->sFlowSettings == NULL) {
      myLog(LOG_ERR, "No sFlow config defined");
      return NO;
    }
    
    if(sf->sFlowSettings->collectors == NULL) {
      if(!sp->DNSSD)
	myLog(LOG_ERR, "No collectors defined");
      return NO;
    }

    assert(sf->agentIP.type);
    

    // open the sockets if not open already - one for v4 and another for v6
    if(sp->socket4 <= 0) {
      if((sp->socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	myLog(LOG_ERR, "IPv4 send socket open failed : %s", strerror(errno));
      }
      else {
        // increase tx buffer size
        uint32_t sndbuf = HSP_SFLOW_SND_BUF;
        if(setsockopt(sp->socket4, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
          myLog(LOG_ERR, "setsockopt(SO_SNDBUF=%d) failed(v4): %s", HSP_SFLOW_SND_BUF, strerror(errno));
        }
      }
    }
    if(sp->socket6 <= 0) {
      if((sp->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	myLog(LOG_ERR, "IPv6 send socket open failed : %s", strerror(errno));
      }
      else {
        // increase tx buffer size
        uint32_t sndbuf = HSP_SFLOW_SND_BUF;
        if(setsockopt(sp->socket6, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
          myLog(LOG_ERR, "setsockopt(SO_SNDBUF=%d) failed(v6): %s", HSP_SFLOW_SND_BUF, strerror(errno));
        }
      }
    }

    time_t now = UTClockSeconds();
    sf->agent = (SFLAgent *)my_calloc(sizeof(SFLAgent));
    sfl_agent_init(sf->agent,
		   &sf->agentIP,
		   sf->subAgentId,
		   now,
		   now,
		   sp,
		   agentCB_alloc,
		   agentCB_free,
		   agentCB_error,
		   agentCB_sendPkt);
    // just one receiver - we are serious about making this lightweight for now
    SFLReceiver *receiver = sfl_agent_addReceiver(sf->agent);

    // max datagram size might have been tweaked in the config file
    if(sf->sFlowSettings_file->datagramBytes) {
      sfl_receiver_set_sFlowRcvrMaximumDatagramSize(receiver, sf->sFlowSettings_file->datagramBytes);
    }

    // claim the receiver slot
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Virtual Switch sFlow Probe");
    
    // set the timeout to infinity
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);

    uint32_t pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
    
    // add a <physicalEntity> poller to represent the whole physical host
    SFLDataSource_instance dsi;
  // ds_class = <physicalEntity>, ds_index = <my physical>, ds_instance = 0
    SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, HSP_DEFAULT_PHYSICAL_DSINDEX, 0);
    sf->poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(sf->poller, pollingInterval);
    sfl_poller_set_sFlowCpReceiver(sf->poller, HSP_SFLOW_RECEIVER_INDEX);
    
#if defined(HSF_XEN) || defined(HSF_DOCKER) || defined(HSF_VRT)
    // add <virtualEntity> pollers for each virtual machine
    configVMs(sp);
#endif

 #ifdef HSF_ULOG
    if(sp->sFlow->sFlowSettings_file->ulogGroup != 0) {
      // ULOG group is set, so open the netfilter
      // socket to ULOG while we are still root
      openULOG(sp);
    }
#endif
#ifdef HSF_NFLOG
    if(sp->sFlow->sFlowSettings_file->nflogGroup != 0) {
      // ULOG group is set, so open the netfilter
      // socket to ULOG while we are still root
      openNFLOG(sp);
    }
#endif
      
#ifdef HSF_JSON
    uint16_t jsonPort = sp->sFlow->sFlowSettings_file->jsonPort;
    char *jsonFIFO = sp->sFlow->sFlowSettings_file->jsonFIFO;
    if(jsonPort || jsonFIFO) {
      if(jsonPort) {
	sp->json_soc = openUDPListenSocket("127.0.0.1", PF_INET, jsonPort, HSP_JSON_RCV_BUF);
	sp->json_soc6 = openUDPListenSocket("::1", PF_INET6, jsonPort, HSP_JSON_RCV_BUF);
      }
      if(jsonFIFO) {
	// This makes it possible to use hsflowd from a container whose networking may be
	// virtualized but where a directory such as /tmp is still accessible and shared.
	if((sp->json_fifo = open(jsonFIFO, O_RDONLY|O_NONBLOCK)) == -1) {
	  myLog(LOG_ERR, "json fifo open(%s, O_RDONLY|O_NONBLOCK) failed: %s", jsonFIFO, strerror(errno));
	}
      }
      cJSON_Hooks hooks;
      hooks.malloc_fn = my_calloc;
      hooks.free_fn = my_free;
      cJSON_InitHooks(&hooks);
    }
#endif

#ifdef HSF_PCAP
    for(HSPPcap *pcap = sp->sFlow->sFlowSettings_file->pcaps; pcap; pcap = pcap->nxt) {
      BPFSoc *bpfs = (BPFSoc *)my_calloc(sizeof(BPFSoc));
      bpfs->nxt = sp->bpf_socs;
      sp->bpf_socs = bpfs;
      bpfs->myHSP = sp;
      SFLAdaptor *adaptor = adaptorByName(sp, pcap->dev);
      if(adaptor == NULL) {
	myLog(LOG_ERR, "PCAP: device not found: %s", pcap->dev);
      }
      else {
	bpfs->deviceName = strdup(pcap->dev);
	bpfs->isBridge = (ADAPTOR_NIO(adaptor)->devType == HSPDEV_BRIDGE);
	bpfs->samplingRate = lookupPacketSamplingRate(adaptor, sp->sFlow->sFlowSettings);
	bpfs->subSamplingRate = bpfs->samplingRate;
	bpfs->pcap = pcap_open_live(pcap->dev,
				    sp->sFlow->sFlowSettings_file->headerBytes,
				    NO, /* promisc */
				    0, /* timeout==poll */
				    bpfs->pcap_err);
	if(bpfs->pcap) {
	  if(debug) myLog(LOG_INFO, "PCAP: device %s opened OK", pcap->dev);
	  bpfs->soc = pcap_fileno(bpfs->pcap);
	  setKernelSampling(sp, bpfs);
	}
	else {
	  if(debug) myLog(LOG_ERR, "PCAP: device %s open failed", pcap->dev);
	}
      }
    }
#endif

    return YES;
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
    sp->DNSSD_startDelay = HSP_DEFAULT_DNSSD_STARTDELAY;
    sp->DNSSD_retryDelay = HSP_DEFAULT_DNSSD_RETRYDELAY;
    sp->crashFile = HSP_DEFAULT_CRASH_FILE;
    sp->dropPriv = YES;
    sp->refreshAdaptorListSecs = HSP_REFRESH_ADAPTORS;
    sp->refreshVMListSecs = HSP_REFRESH_VMS;
    sp->forgetVMSecs = HSP_FORGET_VMS;
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-dvP] [-p PIDFile] [-u UUID] [-f CONFIGFile]\n", command);
    fprintf(stderr,"\n\
             -d:  debug mode - do not fork as a daemon, and log to stderr (repeat for more details)\n\
             -v:  print version number and exit\n\
             -P:  do not drop privileges (run as root)\n\
     -p PIDFile:  specify PID file (default is " HSP_DEFAULT_PIDFILE ")\n\
        -u UUID:  specify UUID as unique ID for this host\n\
  -f CONFIGFile:  specify config file (default is "HSP_DEFAULT_CONFIGFILE")\n\n");
  fprintf(stderr, "=============== More Information ============================================\n");
  fprintf(stderr, "| sFlow standard        - http://www.sflow.org                              |\n");
  fprintf(stderr, "| sFlowTrend (FREE)     - http://www.inmon.com/products/sFlowTrend.php      |\n");
  fprintf(stderr, "=============================================================================\n");

    exit(EXIT_FAILURE);
  }

  /*_________________---------------------------__________________
    _________________   processCommandLine      __________________
    -----------------___________________________------------------
  */

  static void processCommandLine(HSP *sp, int argc, char *argv[])
  {
    int in;
    while ((in = getopt(argc, argv, "dDvPp:f:o:u:?h")) != -1) {
      switch(in) {
      case 'd': debug++; break;
      case 'D': daemonize++; break;
      case 'v': printf("%s version %s\n", argv[0], STRINGIFY_DEF(HSP_VERSION)); exit(EXIT_SUCCESS); break;
      case 'P': sp->dropPriv = NO; break;
      case 'p': sp->pidFile = optarg; break;
      case 'f': sp->configFile = optarg; break;
      case 'o': sp->outputFile = optarg; break;
      case 'u':
	if(parseUUID(optarg, sp->uuid) == NO) {
	  fprintf(stderr, "bad UUID format: %s\n", optarg);
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
    _________________     setState              __________________
    -----------------___________________________------------------
  */

  static void setState(HSP *sp, EnumHSPState state) {
    if(debug) myLog(LOG_INFO, "state -> %s", HSPStateNames[state]);
    sp->state = state;
  }

  /*_________________---------------------------__________________
    _________________     signal_handler        __________________
    -----------------___________________________------------------
  */

  static void signal_handler(int sig, siginfo_t *info, void *secret) {
    HSP *sp = &HSPSamplingProbe;
#define HSP_NUM_BACKTRACE_PTRS 50
    static void *backtracePtrs[HSP_NUM_BACKTRACE_PTRS];

    switch(sig) {
    case SIGTERM:
      myLog(LOG_INFO,"Received SIGTERM");
      setState(sp, HSPSTATE_END);
      break;
    case SIGINT:
      myLog(LOG_INFO,"Received SIGINT");
      setState(sp, HSPSTATE_END);
      break;
    default:
      {
	myLog(LOG_INFO,"Received signal %d", sig);
	// first make sure we can't go in a loop
	signal(SIGSEGV, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGILL, SIG_DFL);
	signal(SIGBUS, SIG_DFL);
	signal(SIGXFSZ, SIG_DFL);

	// ask for the backtrace pointers
	size_t siz = backtrace(backtracePtrs, HSP_NUM_BACKTRACE_PTRS);

	if(f_crash == NULL) {
	  f_crash = stderr;
	}

	backtrace_symbols_fd(backtracePtrs, siz, fileno(f_crash));
	fflush(f_crash);
	// Do something useful with siginfo_t 
	if (sig == SIGSEGV) {
	  fprintf(f_crash, "SIGSEGV, faulty address is %p\n", info->si_addr);
#ifdef REG_EIP
	  // only defined for 32-bit arch - not sure what the equivalent is in sys/ucontext.h
	  fprintf(f_crash, "...from %x\n", ((ucontext_t *)secret)->uc_mcontext.gregs[REG_EIP]);
#endif
	}
	
#ifdef REG_EIP
	fprintf(f_crash, "==== reapeat backtrace with REG_EIP =====");
	// overwrite sigaction with caller's address
	backtracePtrs[1] = (void *)(((ucontext_t *)secret)->uc_mcontext.gregs[REG_EIP]);
	// then write again:
	backtrace_symbols_fd(backtracePtrs, siz, fileno(f_crash));
	fflush(f_crash);
#endif
	// exit with the original signal so we get the right idea
	exit(sig);
      }

      break;
    }
  }


  /*_________________---------------------------__________________
    _________________   sFlowSettingsString     __________________
    -----------------___________________________------------------
  */

  char *sFlowSettingsString(HSPSFlow *sf, HSPSFlowSettings *settings)
  {
    UTStrBuf *buf = UTStrBuf_new(1024);

    if(settings) {
      UTStrBuf_printf(buf, "hostname=%s\n", sf->myHSP->hostname);
      UTStrBuf_printf(buf, "sampling=%u\n", settings->samplingRate);
      UTStrBuf_printf(buf, "header=%u\n", settings->headerBytes);
      UTStrBuf_printf(buf, "datagram=%u\n", settings->datagramBytes);
      UTStrBuf_printf(buf, "polling=%u\n", settings->pollingInterval);
      // make sure the application specific ones always come after the general ones - to simplify the override logic there
      for(HSPApplicationSettings *appSettings = settings->applicationSettings; appSettings; appSettings = appSettings->nxt) {
	if(appSettings->got_sampling_n) {
	  UTStrBuf_printf(buf, "sampling.%s=%u\n", appSettings->application, appSettings->sampling_n);
	}
	if(appSettings->got_polling_secs) {
	  UTStrBuf_printf(buf, "polling.%s=%u\n", appSettings->application, appSettings->polling_secs);
	}
      }
      char ipbuf[51];
      UTStrBuf_printf(buf, "agentIP=%s\n", printIP(&sf->agentIP, ipbuf, 50));
      if(sf->agentDevice) {
	UTStrBuf_printf(buf, "agent=%s\n", sf->agentDevice);
      }
      UTStrBuf_printf(buf, "ds_index=%u\n", HSP_DEFAULT_PHYSICAL_DSINDEX);

      // jsonPort always comes from local config file
      if(sf->sFlowSettings_file && sf->sFlowSettings_file->jsonPort != 0) {
	UTStrBuf_printf(buf, "jsonPort=%u\n", sf->sFlowSettings_file->jsonPort);
      }

      // the DNS-SD responses seem to be reordering the collectors every time, so we have to take
      // another step here to make sure they are sorted.  Otherwise we think the config has changed
      // every time(!)
      UTStringArray *iplist = strArrayNew();
      for(HSPCollector *collector = settings->collectors; collector; collector = collector->nxt) {
	// make sure we ignore any where the foward lookup failed
	// this might mean we write a .auto file with no collectors in it,
	// so let's hope the slave agents all do the right thing with that(!)
	if(collector->ipAddr.type != SFLADDRESSTYPE_UNDEFINED) {
	  char collectorStr[128];
	  // <ip> <port> [<priority>]
	  sprintf(collectorStr, "collector=%s %u\n", printIP(&collector->ipAddr, ipbuf, 50), collector->udpPort);
	  strArrayAdd(iplist, collectorStr);
	}
      }
      strArraySort(iplist);
      char *arrayStr = strArrayStr(iplist, NULL/*start*/, NULL/*quote*/, NULL/*delim*/, NULL/*end*/);
      UTStrBuf_printf(buf, "%s", arrayStr);
      my_free(arrayStr);
      strArrayFree(iplist);
      // optional pcap settings
      for(HSPPcap *pcap = settings->pcaps; pcap; pcap = pcap->nxt) {
	UTStrBuf_printf(buf, "pcap=%s\n", pcap->dev);
      }
    }
    return UTStrBuf_unwrap(buf);
  }


#ifdef HSP_SWITCHPORT_CONFIG
  /*_________________-------------------------------__________________
    _________________   setSwitchPortSamplingRates  __________________
    -----------------_______________________________------------------
    return YES = hardware/kernel sampling configured OK
    return NO  = hardware/kernel sampling not set - assume 1:1 on ULOG/NFLOG
  */
  
  static int execOutputLine(void *magic, char *line) {
    if(debug) myLog(LOG_INFO, "execOutputLine: %s", line);
    return YES;
  }
  
  static int setSwitchPortSamplingRates(HSPSFlow *sf, HSPSFlowSettings *settings, uint32_t logGroup)
  {
    int hw_sampling = YES;
    UTStringArray *cmdline = strArrayNew();
    strArrayAdd(cmdline, HSP_SWITCHPORT_CONFIG_PROG);
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
    SFLAdaptor *adaptor;
    UTHASH_WALK(sf->myHSP->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(niostate->switchPort
	 && !niostate->loopback
	 && !niostate->bond_master) {
	niostate->sampling_n = lookupPacketSamplingRate(adaptor, settings);
	if(niostate->sampling_n != niostate->sampling_n_set) {
	  if(debug) myLog(LOG_INFO, "setSwitchPortSamplingRate(%s) %u -> %u",
			  adaptor->deviceName,
			  niostate->sampling_n_set,
			  niostate->sampling_n);
	  strArrayInsert(cmdline, 1, adaptor->deviceName);
	  char srate[HSP_MAX_TOK_LEN];
	  snprintf(srate, HSP_MAX_TOK_LEN, "%u", niostate->sampling_n);
	  if(settings->samplingDirection & HSF_DIRN_IN) strArrayInsert(cmdline, 2, srate); // ingress
	  if(settings->samplingDirection & HSF_DIRN_OUT) strArrayInsert(cmdline, 3, srate); // ingress
	  int status;
	  if(myExec(NULL, strArray(cmdline), execOutputLine, outputLine, HSP_MAX_EXEC_LINELEN, &status)) {
	    if(WEXITSTATUS(status) != 0) {
	      
	      myLog(LOG_ERR, "myExec(%s) exitStatus=%d so assuming ULOG/NFLOG is 1:1",
		    HSP_SWITCHPORT_CONFIG_PROG,
		    WEXITSTATUS(status));
	      
	      hw_sampling = NO;
	      break;
	    }
	    else {
	      if(debug) myLog(LOG_INFO, "setSwitchPortSamplingRate(%s) succeeded", adaptor->deviceName);
	      // hardware or kernel sampling was successfully configured
	      niostate->sampling_n_set = niostate->sampling_n;
	    }
	  }
	  else {
	    myLog(LOG_ERR, "myExec() calling %s failed (adaptor=%s)",
		  strArrayAt(cmdline, 0),
		  strArrayAt(cmdline, 1));
	  }
	}
      }
    }
    strArrayFree(cmdline);
    return hw_sampling;
  }
#endif // HSP_SWITCHPORT_CONFIG


  /*_________________---------------------------__________________
    _________________   setPacketSamplingRates    __________________
    -----------------___________________________------------------
  */
  
  static void setPacketSamplingRates(HSPSFlow *sf, HSPSFlowSettings *settings)
  {
    // set defaults assuming we will get 1:1 on ULOG or NFLOG and do our own sampling.
    settings->ulogSubSamplingRate = settings->nflogSubSamplingRate = settings->samplingRate;
    settings->ulogActualSamplingRate = settings->nflogActualSamplingRate = settings->samplingRate;

#ifdef HSP_SWITCHPORT_CONFIG
    // We get to set the hardware sampling rate here, so do that and then force
    // the ulog settings to reflect it (so that the sub-sampling rate is 1:1)
    if(setSwitchPortSamplingRates(sf, settings, sf->sFlowSettings_file->ulogGroup)) {
      // all sampling is done in the hardware
      settings->ulogSubSamplingRate = settings->nflogSubSamplingRate = 1;
      return;
    }

#endif // HSP_SWITCHPORT_CONFIG

    // calculate the ULOG sub-sampling rate to use.  We may get the local ULOG sampling-rate
    // from the probability setting in the config file and the desired sampling rate from DNS-SD,
    // so that's why we have to reconcile the two here.
    uint32_t ulogsr = sf->sFlowSettings_file->ulogSamplingRate;
    if(ulogsr > 1) {
      // use an integer divide to get the sub-sampling rate, but make sure we round up
      settings->ulogSubSamplingRate = (settings->samplingRate + ulogsr - 1) / ulogsr;
      // and pre-calculate the actual sampling rate that we will end up applying
      settings->ulogActualSamplingRate = settings->ulogSubSamplingRate * ulogsr;
    }

    // repeat for nflog settings
    uint32_t nflogsr = sf->sFlowSettings_file->nflogSamplingRate;
    if(nflogsr > 1) {
      // use an integer divide to get the sub-sampling rate, but make sure we round up
      settings->nflogSubSamplingRate = (settings->samplingRate + nflogsr - 1) / nflogsr;
      // and pre-calculate the actual sampling rate that we will end up applying
      settings->nflogActualSamplingRate = settings->nflogSubSamplingRate * nflogsr;
    }

  }

  /*_________________---------------------------__________________
    _________________   installSFlowSettings    __________________
    -----------------___________________________------------------

    Always increment the revision number whenever we change the sFlowSettings pointer
  */
  
  static void installSFlowSettings(HSPSFlow *sf, HSPSFlowSettings *settings)
  {
    // This pointer-operation should be atomic.  We rely on it to be so
    // in places where we consult sf->sFlowSettings without first acquiring
    // the sf->config_mut lock.
    sf->sFlowSettings = settings;

    // do this every time in case the switchPorts are not detected yet at
    // the point where the config is settled (otherwise we could have moved
    // this into the block below and only executed it when the config changed).
    if(settings && sf->sFlowSettings_file) {
      setPacketSamplingRates(sf, settings);
    }
    
    char *settingsStr = sFlowSettingsString(sf, settings);
    if(my_strequal(sf->sFlowSettings_str, settingsStr)) {
      // no change - don't increment the revision number
      // (which will mean that the file is not rewritten either)
      if(settingsStr) my_free(settingsStr);
    }
    else {
      // new config
      if(sf->sFlowSettings_str) {
	// note that this object may have been allocated in the DNS-SD thread,
	// but if it was then only the DNS-SD thread will call this fn.  Likewise
	// if we are using only the hsflowd.conf file then the main thread is the
	// only thread that will get here. If we ever change that separation then this
	// should be revisited because we can easily end up trying to free something
	// in one thread that was allocated by the other thread.
	my_free(sf->sFlowSettings_str);
      }
      sf->sFlowSettings_str = settingsStr;
      sf->revisionNo++;
    
    }
  }

  /*_________________---------------------------__________________
    _________________        runDNSSD           __________________
    -----------------___________________________------------------
  */

  static void myDnsCB(HSP *sp, uint16_t rtype, uint32_t ttl, u_char *key, int keyLen, u_char *val, int valLen, HSPSFlowSettings *st)
  {
    // latch the min ttl
    if(sp->DNSSD_ttl == 0 || ttl < sp->DNSSD_ttl) {
      sp->DNSSD_ttl = ttl;
    }

    char keyBuf[1024];
    char valBuf[1024];
    if(keyLen > 1023 || valLen > 1023) {
      myLog(LOG_ERR, "myDNSCB: string too long");
      return;
    }
    // make a null-terminated copy of key and value
    // and be careful to avoid memcpy(<target>, 0, 0) because it seems to break
    // things horribly when the gcc optimizer is on.
    if(key && keyLen) memcpy(keyBuf, (char *)key, keyLen);
    keyBuf[keyLen] = '\0';
    if(val && valLen) memcpy(valBuf, (char *)val, valLen);
    valBuf[valLen] = '\0';

    if(debug) {
      myLog(LOG_INFO, "dnsSD: (rtype=%u,ttl=%u) <%s>=<%s>", rtype, ttl, keyBuf, valBuf);
    }

    if(key == NULL) {
      // no key => SRV response. See if we got a collector:
      if(val && valLen > 3) {
	uint32_t delim = strcspn(valBuf, "/");
	if(delim > 0 && delim < valLen) {
	  valBuf[delim] = '\0';
	  HSPCollector *coll = newCollector(st);
	  if(lookupAddress(valBuf, (struct sockaddr *)&coll->sendSocketAddr,  &coll->ipAddr, 0) == NO) {
	    myLog(LOG_ERR, "myDNSCB: SRV record returned hostname, but forward lookup failed");
	    // turn off the collector by clearing the address type
	    coll->ipAddr.type = SFLADDRESSTYPE_UNDEFINED;
	  }
	  coll->udpPort = strtol(valBuf + delim + 1, NULL, 0);
	  if(coll->udpPort < 1 || coll->udpPort > 65535) {
	    myLog(LOG_ERR, "myDNSCB: SRV record returned hostname, but bad port: %d", coll->udpPort);
	    // turn off the collector by clearing the address type
	    coll->ipAddr.type = SFLADDRESSTYPE_UNDEFINED;
	  }
	}
      }
    }
    else {
      // we have a key, so this is a TXT record line
      if(strcmp(keyBuf, "sampling") == 0) {
	st->samplingRate = strtol(valBuf, NULL, 0);
      }
      else if(my_strnequal(keyBuf, "sampling.", 9)) {
	setApplicationSampling(st, keyBuf+9, strtol(valBuf, NULL, 0));
      }
      else if(strcmp(keyBuf, "txtvers") == 0) {
      }
      else if(strcmp(keyBuf, "polling") == 0) {
	st->pollingInterval = strtol(valBuf, NULL, 0);
      }
      else if(my_strnequal(keyBuf, "polling.", 8)) {
	setApplicationPolling(st, keyBuf+8, strtol(valBuf, NULL, 0));
      }
#if HSF_DNSSD_AGENTCIDR
      else if(strcmp(keyBuf, "agent.cidr") == 0) {
	HSPCIDR cidr = { 0 };
	if(SFLAddress_parseCIDR(valBuf,
				&cidr.ipAddr,
				&cidr.mask,
				&cidr.maskBits)) {
	  addAgentCIDR(st, &cidr);
	}
	else {
	  myLog(LOG_ERR, "CIDR parse error in dnsSD record <%s>=<%s>", keyBuf, valBuf);
	}
      }
#endif /* HSF_DNSSD_AGENTCIDR */
      else {
	myLog(LOG_INFO, "unexpected dnsSD record <%s>=<%s>", keyBuf, valBuf);
      }
    }
  }

  static void *runDNSSD(void *magic) {
    HSP *sp = (HSP *)magic;
    sp->DNSSD_countdown = sfl_random(sp->DNSSD_startDelay);
    time_t clk = UTClockSeconds();
    while(1) {
      my_usleep(999983); // just under a second
      time_t test_clk = UTClockSeconds();
      if((test_clk < clk) || (test_clk - clk) > HSP_MAX_TICKS) {
	// avoid a flurry of ticks if the clock jumps
	myLog(LOG_INFO, "time jump detected (DNSSD) %ld->%ld", clk, test_clk);
	clk = test_clk - 1;
      }
      time_t ticks = test_clk - clk;
      clk = test_clk;
      if(sp->DNSSD_countdown > ticks) {
	sp->DNSSD_countdown -= ticks;
      }
      else {
	// initiate server-discovery
	HSPSFlow *sf = sp->sFlow;
	HSPSFlowSettings *newSettings_dnsSD = newSFlowSettings();
	HSPSFlowSettings *prevSettings_dnsSD = sf->sFlowSettings_dnsSD;

	// SIGSEGV on Fedora 14 if HSP_RLIMIT_MEMLOCK is non-zero, because calloc returns NULL.
	// Maybe we need to repeat some of the setrlimit() calls here in the forked thread? Or
	// maybe we are supposed to fork the DNSSD thread before dropping privileges?

	// we want the min ttl, so clear it here
	sp->DNSSD_ttl = 0;
	// now make the requests
	int num_servers = dnsSD(sp, myDnsCB, newSettings_dnsSD);
	SEMLOCK_DO(sp->config_mut) {

	  // three cases here:
	  // A) if(num_servers == -1) (i.e. query failed) then keep the current config
	  // B) if(num_servers == 0) then stop monitoring
	  // C) if(num_servers > 0) then install the new config

	  if(debug) myLog(LOG_INFO, "num_servers == %d", num_servers);

	  if(num_servers < 0) {
	    // A: query failed: keep the current config. Just free the new one.
	    freeSFlowSettings(newSettings_dnsSD);
	  }
	  else if(num_servers == 0) {
	    // B: turn off monitoring.  Free the new one and the previous one.
	    installSFlowSettings(sf, NULL);
	    sf->sFlowSettings_dnsSD = NULL;
	    if(prevSettings_dnsSD) {
	      freeSFlowSettings(prevSettings_dnsSD);
	    }
	    freeSFlowSettings(newSettings_dnsSD);
	  }
	  else {
	    // C: make this new one the running config.  Free the previous one.
	    sf->sFlowSettings_dnsSD = newSettings_dnsSD;
	    installSFlowSettings(sf, newSettings_dnsSD);
	    if(prevSettings_dnsSD) {
	      freeSFlowSettings(prevSettings_dnsSD);
	    }
	  }

	  // whatever happens we might still learn a TTL (e.g. from the TXT record query)
	  sp->DNSSD_countdown = sp->DNSSD_ttl ?: sp->DNSSD_retryDelay;
	  // but make sure it's sane
	  if(sp->DNSSD_countdown < HSP_DEFAULT_DNSSD_MINDELAY) {
	    if(debug) myLog(LOG_INFO, "forcing minimum DNS polling delay");
	    sp->DNSSD_countdown = HSP_DEFAULT_DNSSD_MINDELAY;
	  }
	  if(debug) myLog(LOG_INFO, "DNSSD polling delay set to %u seconds", sp->DNSSD_countdown);
	}
      }    
    }  
    return NULL;
  }
      
  /*_________________---------------------------__________________
    _________________         drop_privileges   __________________
    -----------------___________________________------------------
  */

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
    else if(debug) {
      myLog(LOG_INFO, "setrlimit(%s)=%u", resourceName, request);
    }
    return YES;
  }
  
#define GETMYLIMIT(L) getMyLimit((L), STRINGIFY(L))
#define SETMYLIMIT(L,V) setMyLimit((L), STRINGIFY(L), (V))

#ifdef HSF_CAPABILITIES
  static void logCapability(cap_t myCap, cap_flag_t flag) {
    cap_flag_value_t flag_effective, flag_permitted, flag_inheritable;
    if(cap_get_flag(myCap, flag, CAP_EFFECTIVE, &flag_effective) == -1 ||
       cap_get_flag(myCap, flag, CAP_PERMITTED, &flag_permitted) == -1 ||
       cap_get_flag(myCap, flag, CAP_INHERITABLE, &flag_inheritable) == -1) {
      myLog(LOG_ERR, "cap_get_flag(cap=%u) failed : %s", flag, strerror(errno));
    }
    else {
      myLog(LOG_INFO, "capability:%u (eff,per,inh) = (%u, %u, %u)",
	    flag,
	    flag_effective,
	    flag_permitted,
	    flag_inheritable);
    }
  }

  static void logCapabilities(cap_t myCap) {
    for(int cc = 0; cc <= CAP_LAST_CAP; cc++) {
      logCapability(myCap, cc);
    }
  }

  static void passCapabilities(int parent, cap_value_t *desired_caps, int ncaps) {
    if(debug) myLog(LOG_INFO, "passCapabilities(): getuid=%u parent=%d", getuid(), parent);

    cap_t myCap = cap_get_proc();
    if(myCap == NULL) {
      myLog(LOG_ERR, "cap_get_proc() failed : %s", strerror(errno));
      return;
    }

    if(debug > 1) {
      myLog(LOG_INFO, "logCapabilities(): getuid=%u BEFORE", getuid());
      logCapabilities(myCap);
    }

    /* identified these capabilities as being necessary for setns() system call */
    if(cap_set_flag(myCap, (cap_flag_t)CAP_EFFECTIVE, ncaps, desired_caps, CAP_SET) == -1) {
      myLog(LOG_ERR, "cap_set_flag(EFFECTIVE) failed : %s", strerror(errno));
    }

    if(parent) {
      // only the parent needs to set permitted and inheritable
      if(cap_set_flag(myCap, (cap_flag_t)CAP_PERMITTED, ncaps, desired_caps, CAP_SET) == -1) {
	myLog(LOG_ERR, "cap_set_flag(PERMITTED) failed : %s", strerror(errno));
      }

      if(cap_set_flag(myCap, (cap_flag_t)CAP_INHERITABLE, ncaps, desired_caps, CAP_SET) == -1) {
	myLog(LOG_ERR, "cap_set_flag(INHERITABLE) failed : %s", strerror(errno));
      }
    }

    if(cap_set_proc(myCap) == -1) {
      myLog(LOG_ERR, "cap_set_proc() failed : %s", strerror(errno));
    }

    if(parent) {
      // only the parent needs to set KEEPCAPS.  This is how the
      // inheritable capabilities are made avaiable to the child
      // (where 'child' here means after the setuid)
      if(prctl(PR_SET_KEEPCAPS, 1,0,0,0) == -1) {
	myLog(LOG_ERR, "prctl(KEEPCAPS) failed : %s", strerror(errno));
      }
    }

    if(debug > 1) {
      myLog(LOG_INFO, "logCapabilities(): getuid=%u AFTER", getuid());
      logCapabilities(myCap);
    }

    cap_free(myCap);
  }
#endif /*HSF_CAPABILITIES */

  static void drop_privileges(int requestMemLockBytes) {
    if(debug) myLog(LOG_INFO, "drop_priviliges: getuid=%d", getuid());

    if(getuid() != 0) return;

#ifdef HSF_DOCKER
    /* Make certain capabilities inheritable.  CAP_SYS_PTRACE seems
     * be required just to access /proc/<nspid>/ns/net.  I found
     * some discussion of this here:
     *  http://osdir.com/ml/linux.kernel.containers/2007-12/msg00069.html
     * while CAP_SYS_ADMIN is required for the netns() and unshare()
     * system calls.  Right now all this happens in 
     * readInterfaces.c : readContainerInterfaces()
     * Not yet sure what is required for "docker ps" and
     * "docker inspect",  so this is still a work in progress.
    */
    cap_value_t desired_caps[] = {
      CAP_SYS_PTRACE,
      CAP_SYS_ADMIN,
    };
    passCapabilities(YES, desired_caps, 2);
#endif
						    
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

#if defined(HSF_CUMULUS) || defined(HSF_DOCKER)
    // For now we have to retain root privileges on Cumulus Linux because
    // we need to open netfilter/ULOG and to run the portsamp program.

    // Similarly, when running Docker containers we still need more
    // capabilities to be passed down so that we can run "docker ps -q"
    // and "docker inspect <id>" successfully.
#else
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

#endif /* (not) HSF_CUMULUS */

#ifdef HSF_DOCKER
    // claim my inheritance
    passCapabilities(NO, desired_caps, 2);
#endif

    if(debug) {
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

/*_________________---------------------------__________________
  _________________         main              __________________
  -----------------___________________________------------------
*/

  int main(int argc, char *argv[])
  {
    HSP *sp = &HSPSamplingProbe;
    
#if (HSF_ULOG || HSF_NFLOG || HSF_JSON)
    fd_set readfds;
    FD_ZERO(&readfds);
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

    // init
    setDefaults(sp);

    // read the command line
    processCommandLine(sp, argc, argv);
      
    // don't run if we think another one is already running
    struct stat statBuf;
    if(stat(sp->pidFile, &statBuf) == 0) {
      myLog(LOG_ERR,"Another %s is already running. If this is an error, remove %s", argv[0], sp->pidFile);
      exit(EXIT_FAILURE);
    }

    if(debug == 0 || daemonize) {
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

#ifdef HSF_NVML
    // NVIDIA shared library for interrogating GPU
    nvml_init(sp);
#endif
    
#ifdef HSF_XEN
    // open Xen handles while we still have root privileges
    openXenHandles(sp);
#endif
    
#ifdef HSF_VRT
    // open the libvirt connection
    int virErr = virInitialize();
    if(virErr != 0) {
      myLog(LOG_ERR, "virInitialize() failed: %d\n", virErr);
      exit(EXIT_FAILURE);
    }
    sp->virConn = virConnectOpenReadOnly(NULL);
    if(sp->virConn == NULL) {
      myLog(LOG_ERR, "virConnectOpenReadOnly() failed\n");
      // No longer fatal, because there is a dependency on libvirtd running.
      // If this fails, we simply run without sending per-VM stats.
      // exit(EXIT_FAILURE);
    }
#endif
    
    myLog(LOG_INFO, "started");
    
    // initialize the clock so we can detect second boundaries
    sp->clk = UTClockSeconds();

    // semaphore to protect config shared with DNSSD thread
    sp->config_mut = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(sp->config_mut, NULL);

    // allocate device tables
    sp->adaptorsByName = UTHASH_NEW(SFLAdaptor, deviceName, YES);
    sp->adaptorsByIndex = UTHASH_NEW(SFLAdaptor, ifIndex, NO);
    sp->adaptorsByPeerIndex = UTHASH_NEW(SFLAdaptor, peer_ifIndex, NO);
    sp->adaptorsByMac = UTHASH_NEW(SFLAdaptor, macs[0], NO);
    sp->vmsByUUID = UTHASH_NEW(HSPVMState, uuid, NO);
    sp->vmsByDsIndex = UTHASH_NEW(HSPVMState, dsIndex, NO);
    
#ifdef HSF_DOCKER
    sp->containers = UTHASH_NEW(HSPContainer, id, YES);
#endif
    
    setState(sp, HSPSTATE_READCONFIG);
    
    int configOK = NO;
    while(sp->state != HSPSTATE_END) {

      switch(sp->state) {
	
      case HSPSTATE_READCONFIG:

	{ // read the host-id info up front, so we can include it in hsflowd.auto
	  // (we'll read it again each time we send the counters)
	  SFLCounters_sample_element hidElem = { 0 };
	  hidElem.tag = SFLCOUNTERS_HOST_HID;
	  readHidCounters(sp,
			  &hidElem.counterBlock.host_hid,
			  sp->hostname,
			  SFL_MAX_HOSTNAME_CHARS,
			  sp->os_release,
			  SFL_MAX_OSRELEASE_CHARS);
	}
	
#ifdef HSP_SWITCHPORT_REGEX
	if(compile_swp_regex(sp) == NO) {
	  myLog(LOG_ERR, "failed to compile switchPort regex\n");
	  exit(EXIT_FAILURE);
	}
#endif
	// a sucessful read of the config file is required
	if(HSPReadConfigFile(sp) == NO) {
	  myLog(LOG_ERR, "failed to read config file\n");
	  exitStatus = EXIT_FAILURE;
	  setState(sp, HSPSTATE_END);
	  break;
	}

	// must be able to read interfaces
	if(readInterfaces(sp, NULL, NULL, NULL, NULL, NULL) == 0) {
	  myLog(LOG_ERR, "failed to read interfaces\n");
	  exitStatus = EXIT_FAILURE;
	  setState(sp, HSPSTATE_END);
	  break;
	}

	// must be able to choose an agent address
	if(selectAgentAddress(sp, NULL) == NO) {
	  myLog(LOG_ERR, "failed to select agent address\n");
	  exitStatus = EXIT_FAILURE;
	  setState(sp, HSPSTATE_END);
	  break;
	}

	if(sp->DNSSD) {
	  // launch dnsSD thread.  It will now be responsible for
	  // the sFlowSettings,  and the current thread will loop
	  // in the HSPSTATE_WAITCONFIG state until that pointer
	  // has been set (sp->sFlow.sFlowSettings)
	  // Set a more conservative stacksize here - partly because
	  // we don't need more,  but mostly because Debian was refusing
	  // to create the thread - I guess because it was enough to
	  // blow through our mlockall() allocation.
	  // http://www.mail-archive.com/xenomai-help@gna.org/msg06439.html 
	  pthread_attr_t attr;
	  pthread_attr_init(&attr);
	  pthread_attr_setstacksize(&attr, HSP_DNSSD_STACKSIZE);
	  sp->DNSSD_thread = my_calloc(sizeof(pthread_t));
	  int err = pthread_create(sp->DNSSD_thread, &attr, runDNSSD, sp);
	  if(err != 0) {
	    myLog(LOG_ERR, "pthread_create() failed: %s\n", strerror(err));
	    exit(EXIT_FAILURE);
	  }
	}
	else {
	  // just use the config from the file
	  installSFlowSettings(sp->sFlow, sp->sFlow->sFlowSettings_file);
	}
	setState(sp, HSPSTATE_WAITCONFIG);
	break;
	
      case HSPSTATE_WAITCONFIG:
	SEMLOCK_DO(sp->config_mut) {
	  if(sp->sFlow->sFlowSettings) {
	    // we have a config - proceed
	    // we must have an agentIP now, so we can use
	    // it to seed the random number generator
	    SFLAddress *agentIP = &sp->sFlow->agentIP;
	    uint32_t seed = 0;
	    if(agentIP->type == SFLADDRESSTYPE_IP_V4) seed = agentIP->address.ip_v4.addr;
	    else memcpy(&seed, agentIP->address.ip_v6.addr + 12, 4);
	    sfl_random_init(seed);

	    // desync the clock so we don't detect second rollovers
	    // at the same time as other hosts no matter what clock
	    // source we use...
	    UTClockDesync_uS(sfl_random(1000000));

	    // initialize the faster polling of NIO counters
	    // to avoid undetected 32-bit wraps
	    sp->nio_polling_secs = HSP_NIO_POLLING_SECS_32BIT;
	      
	    if(initAgent(sp)) {
	      if(debug) {
		myLog(LOG_INFO, "initAgent suceeded");
		// print some stats to help us size HSP_RLIMIT_MEMLOCK etc.
		malloc_stats();
	      }

	      if(sp->dropPriv) {
		// don't need to be root any more - we held on to root privileges
		// to make sure we could write the pid file,  and open the output
		// file, and open the Xen handles, and delay the opening of the
		// ULOG socket until we knew the group-number, and on Debian and
		// Fedora 14 we needed to fork the DNSSD thread before dropping root
		// priviliges (something to do with mlockall()). Anway, from now on
		// we just don't want the responsibility...
		drop_privileges(HSP_RLIMIT_MEMLOCK);
	      }

#ifdef HSP_SWITCHPORT_REGEX
	      // now that interfaces have been read and sflow agent is
	      // initialized, check to see if we should be exporting
	      // individual counter data for switch port interfaces.
	      configSwitchPorts(sp); // in readPackets.c
#endif

#ifdef HSF_XEN
	      if(xen_compile_vif_regex(sp) == NO) {
		exit(EXIT_FAILURE);
	      }
#endif
	      setState(sp, HSPSTATE_RUN);
	    }
	    else {
	      if(sp->DNSSD) {
		// if using DNS-SD we can just wait here in this state
		// until someone adds a collector to the SRV record
		if(debug) myLog(LOG_INFO, "failed to init agent - waiting for config change");
	      }
	      else {
		// otherwise a failure to initAgent is fatal
		myLog(LOG_ERR, "failed to init agent");
		exitStatus = EXIT_FAILURE;
		setState(sp, HSPSTATE_END);
	      }
	    }
	  }
	} // config_mut
	break;
	
      case HSPSTATE_RUN:
	{
	  // check for second boundaries and generate ticks for the sFlow library
	  time_t test_clk = UTClockSeconds();
	  if((test_clk < sp->clk) || (test_clk - sp->clk) > HSP_MAX_TICKS) {
	    // avoid a busy-loop of ticks
	    myLog(LOG_INFO, "time jump detected");
	    sp->clk = test_clk - 1;
	  }
	  while(sp->clk < test_clk) {

	    // this would be a good place to test the memory footprint and
	    // bail out if it looks like we are leaking memory(?)

	    SEMLOCK_DO(sp->config_mut) {
	      // was the config turned off?
	      // set configOK flag here while we have the semaphore
	      configOK = (sp->sFlow->sFlowSettings != NULL);
	      if(configOK) {
		// did the polling interval change?  We have the semaphore
		// here so we can just run along and tell everyone.
		uint32_t piv = sp->sFlow->sFlowSettings->pollingInterval;
		if(piv != sp->previousPollingInterval) {
		  
		  if(debug) myLog(LOG_INFO, "polling interval changed from %u to %u",
				  sp->previousPollingInterval, piv);
		  
		  for(SFLPoller *pl = sp->sFlow->agent->pollers; pl; pl = pl->nxt) {
		    sfl_poller_set_sFlowCpInterval(pl, piv);
		  }
		  sp->previousPollingInterval = piv;
		  // make sure slave ports are on the same
		  // polling schedule as their bond master.
		  syncBondPolling(sp);
		}
		// clock-tick
		tick(sp);
	      }
	    } // semaphore
	    sp->clk++;
	  }
	}
	break;

      case HSPSTATE_END:
	break;
      }

      // set the timeout so that if all is quiet we will still loop
      // around and check for ticks/signals several times per second
#define HSP_SELECT_TIMEOUT_uS 200000

#if (HSF_ULOG || HSF_NFLOG || HSF_JSON)
      int max_fd = 0;
#ifdef HSF_ULOG
      if(sp->ulog_soc > 0) {
	if(sp->ulog_soc > max_fd) max_fd = sp->ulog_soc;
	FD_SET(sp->ulog_soc, &readfds);
      }
#endif
#ifdef HSF_NFLOG
      if(sp->nflog_soc > 0) {
	if(sp->nflog_soc > max_fd) max_fd = sp->nflog_soc;
	FD_SET(sp->nflog_soc, &readfds);
      }
#endif
#ifdef HSF_JSON
      if(sp->json_soc > 0) {
	if(sp->json_soc > max_fd) max_fd = sp->json_soc;
	FD_SET(sp->json_soc, &readfds);
      }
      if(sp->json_soc6 > 0) {
	if(sp->json_soc6 > max_fd) max_fd = sp->json_soc6;
	FD_SET(sp->json_soc6, &readfds);
      }
      if(sp->json_fifo > 0) {
	if(sp->json_fifo > max_fd) max_fd = sp->json_fifo;
	FD_SET(sp->json_fifo, &readfds);
      }
#endif


#ifdef HSF_PCAP
      for (BPFSoc *bpfs = sp->bpf_socs; bpfs; bpfs = bpfs->nxt) {
	if(bpfs->soc > 0) {
	  if(bpfs->soc > max_fd) max_fd = bpfs->soc;
	  FD_SET(bpfs->soc, &readfds);
	}
      }
#endif
      
      if(!configOK) {
	// no config (may be temporary condition caused by DNS-SD),
	// so disable the socket polling - just use select() to sleep
	max_fd = 0;
      }
      struct timeval timeout;
      timeout.tv_sec = 0;
      timeout.tv_usec = HSP_SELECT_TIMEOUT_uS;
      int nfds = select(max_fd + 1,
			&readfds,
			(fd_set *)NULL,
			(fd_set *)NULL,
			&timeout);
      // may return prematurely if a signal was caught, in which case nfds will be
      // -1 and errno will be set to EINTR.  If we get any other error, abort.
      if(nfds < 0 && errno != EINTR) {
	myLog(LOG_ERR, "select() returned %d : %s", nfds, strerror(errno));
	exit(EXIT_FAILURE);
      }
      if(debug > 2 && nfds > 0) {
	myLog(LOG_INFO, "select returned %d", nfds);
      }
      // may get here just because a signal was caught so these
      // callbacks need to be non-blocking when they read from the socket
#ifdef HSF_ULOG
      if(sp->ulog_soc > 0 && FD_ISSET(sp->ulog_soc, &readfds)) {
        int batch = readPackets_ulog(sp);
        if(debug) {
          if(debug > 2) myLog(LOG_INFO, "readPackets_ulog batch=%d", batch);
          if(batch == HSP_READPACKET_BATCH) myLog(LOG_INFO, "readPackets_ulog got max batch (%d)", batch);
        }
      }
#endif
#ifdef HSF_NFLOG
      if(sp->nflog_soc > 0 && FD_ISSET(sp->nflog_soc, &readfds)) {
        int batch = readPackets_nflog(sp);
        if(debug) {
          if(debug > 2) myLog(LOG_INFO, "readPackets_nflog batch=%d", batch);
          if(batch == HSP_READPACKET_BATCH) myLog(LOG_INFO, "readPackets_nflog got max batch (%d)", batch);
	}
      }
#endif
#ifdef HSF_JSON
      if(sp->json_soc > 0 && FD_ISSET(sp->json_soc, &readfds)) {
	readJSON(sp, sp->json_soc);
      }
      if(sp->json_soc6 > 0 && FD_ISSET(sp->json_soc6, &readfds)) {
	readJSON(sp, sp->json_soc6);
      }
      if(sp->json_fifo > 0 && FD_ISSET(sp->json_fifo, &readfds)) {
	readJSON(sp, sp->json_fifo);
      }
#endif

#ifdef HSF_PCAP
      for (BPFSoc *bpfs = sp->bpf_socs; bpfs; bpfs = bpfs->nxt) {
	if(bpfs->soc > 0
	   && FD_ISSET(bpfs->soc, &readfds)) {
	  int batch = readPackets_pcap(sp, bpfs);
	  if(debug) {
	    if(debug > 2) myLog(LOG_INFO, "PCAP: readPackets batch=%d", batch);
	    if(batch == HSP_READPACKET_BATCH) myLog(LOG_INFO, "PCAP: readPackets got max batch (%d)", batch);
	  }
	}
      }
#endif

#else /* (HSF_ULOG || HSF_NFLOG || HSF_JSON) */
      my_usleep(HSP_SELECT_TIMEOUT_uS);
#endif /* (HSF_ULOG || HSF_NFLOG || HSF_JSON) */
    }

    // get here if a signal kicks the state to HSPSTATE_END
    // and we break out of the loop above.
    // If that doesn't happen the most likely explanation
    // is a bug that caused the semaphore to be acquired
    // and not released,  but that would only happen if the
    // DNSSD thread died or hung up inside the critical block.
    closelog();
    myLog(LOG_INFO,"stopped");
    
#ifdef HSF_XEN
    closeXenHandles(sp);
#endif
#ifdef HSF_VRT
    virConnectClose(sp->virConn);
#endif
#ifdef HSF_NVML
    nvml_stop(sp);
#endif

    if(debug == 0) {
      // shouldn't need to be root again to remove the pidFile
      // (i.e. we should still have execute permission on /var/run)
      remove(sp->pidFile);
    }

    exit(exitStatus);
  } /* main() */


#if defined(__cplusplus)
} /* extern "C" */
#endif

