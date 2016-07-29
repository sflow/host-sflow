/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "cpu_utils.h"
#include "cJSON.h"
  
  // globals - easier for signal handler
  HSP HSPSamplingProbe;
  int exitStatus = EXIT_SUCCESS;
  FILE *f_crash = NULL;

  static void installSFlowSettings(HSP *sp, HSPSFlowSettings *settings);

  
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
    // grab sp->sync whenever we call sfl_sampler_writeFlowSample(),  because that can
    // bring us here where we read the list of collectors.

    for(HSPCollector *coll = sp->sFlowSettings->collectors; coll; coll=coll->nxt) {
	
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

    // don't send L4 stats from switches.  Save the space for other things.
    // TODO: review this.  Possibly generalize with a request-to-omit flag.
    // host TCP/IP counters
    SFLCounters_sample_element ipElem = { 0 }, icmpElem = { 0 }, tcpElem = { 0 }, udpElem = { 0 };
    if(!sp->cumulus.cumulus
       && !sp->os10.os10) {
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

    // send the cs out to be annotated by other modules such as docker, xen, vrt and NVML
    EVEvent *evt_host_cs = EVGetEvent(sp->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE);
    EVEventTx(sp->rootModule, evt_host_cs, cs, sizeof(cs));

    SEMLOCK_DO(sp->sync_agent) {
      sfl_poller_writeCountersSample(poller, cs);
    }
  }

  static void agentCB_getCounters_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)poller->magic;
    UTArrayAdd(sp->pollActions, poller);
    UTArrayAdd(sp->pollActions, agentCB_getCounters);
    // Note readPackets.c uses this mechanism too (for switch port
    // pollers), but other mods use their own array.
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
	sp->refreshAdaptorList = YES;
	SFLDataSource_instance dsi;
	// ds_class = <virtualEntity>, ds_index = offset + <assigned>, ds_instance = 0
	SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, state->dsIndex, 0);
	SEMLOCK_DO(sp->sync_agent) {
	  state->poller = sfl_agent_addPoller(sp->agent, &dsi, mod, getCountersFn);
	  state->poller->userData = state;
	  sfl_poller_set_sFlowCpInterval(state->poller, sp->sFlowSettings->pollingInterval);
	  sfl_poller_set_sFlowCpReceiver(state->poller, HSP_SFLOW_RECEIVER_INDEX);
	}
      }
    }
    return state;
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
      adaptorListMarkAll(state->interfaces);
      // delete any hash-table references to these adaptors
      deleteMarkedAdaptors_adaptorList(sp, state->interfaces);
      // then free them along with the adaptorList itself
      adaptorListFree(state->interfaces);
    }
    if(state->poller) {
      state->poller->userData = NULL;
      SEMLOCK_DO(sp->sync_agent) {
	sfl_agent_removePoller(sp->agent, &state->poller->dsi);
      }
    }
    my_free(state);
    sp->refreshAdaptorList = YES;
  }

  /*_________________---------------------------__________________
    _________________    syncOutputFile         __________________
    -----------------___________________________------------------
  */
  
  static void syncOutputFile(HSP *sp) {
    myDebug(1, "syncOutputFile");
    rewind(sp->f_out);
    fprintf(sp->f_out, "# WARNING: Do not edit this file. It is generated automatically by hsflowd.\n");

    // revision appears both at the beginning and at the end
    fprintf(sp->f_out, "rev_start=%u\n", sp->revisionNo);
    if(sp->sFlowSettings_str) fputs(sp->sFlowSettings_str, sp->f_out);
    // repeat the revision number. The reader knows that if the revison number
    // has not changed under his feet then he has a consistent config.
    fprintf(sp->f_out, "rev_end=%u\n", sp->revisionNo);
    fflush(sp->f_out);
    // chop off anything that may be lingering from before
    UTTruncateOpenFile(sp->f_out);
  }

  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */
  
  static void evt_poll_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    time_t clk = evt->bus->clk;

    // reset the pollActions
    UTArrayReset(sp->pollActions);

    // send a tick to the sFlow agent. This will be passed on
    // to the samplers, pollers and receiver.  If the poller is
    // ready to poll counters it will pull it's callback, but
    // we are using that just to populate the poll actions list.
    // That way we can relinquish the sync semaphore quickly.
    // It is up to the poller's getCounters Fn to grab it again
    // if and when it is required.  Same goes for the
    // sync_receiver lock,  which is needed when the final
    // counter sample is submitted for XDR serialization.
    SEMLOCK_DO(sp->sync_agent) {
      sfl_agent_tick(sp->agent, clk);
    }
    // We can only get away with this scheme because the poller
    // objects are only ever removed and free by this thread.
    // So we don't need to worry about them being freed under
    // our feet below.

    // now we can execute them without holding on to the semaphore
    for(uint32_t ii = 0; ii < UTArrayN(sp->pollActions); ii += 2) {
      SFLPoller *poller = (SFLPoller *)UTArrayAt(sp->pollActions, ii);
      getCountersFn_t cb = (getCountersFn_t)UTArrayAt(sp->pollActions, ii+1);
      SFL_COUNTERS_SAMPLE_TYPE cs;
      memset(&cs, 0, sizeof(cs));
      (cb)((void *)sp, poller, &cs);
    }

    // possibly poll the nio counters to avoid 32-bit rollover
    if(sp->nio_polling_secs &&
       ((clk % sp->nio_polling_secs) == 0)) {
      updateNioCounters(sp, NULL);
    }

    // refresh the interface list periodically or on request
    if(sp->refreshAdaptorList || (clk % sp->refreshAdaptorListSecs) == 0) {
      sp->refreshAdaptorList = NO;
      uint32_t ad_added=0, ad_removed=0, ad_cameup=0, ad_wentdown=0, ad_changed=0;
      if(readInterfaces(sp, &ad_added, &ad_removed, &ad_cameup, &ad_wentdown, &ad_changed) == 0) {
	myLog(LOG_ERR, "failed to re-read interfaces\n");
      }
      else {
	myDebug(1, "interfaces added: %u removed: %u cameup: %u wentdown: %u changed: %u",
		ad_added, ad_removed, ad_cameup, ad_wentdown, ad_changed);
      }

      int agentAddressChanged=NO;
      if(selectAgentAddress(sp, &agentAddressChanged) == NO) {
	  myLog(LOG_ERR, "failed to re-select agent address\n");
      }
      myDebug(1, "agentAddressChanged=%s", agentAddressChanged ? "YES" : "NO");
      if(agentAddressChanged) {
	// this incs the revision No so it causes the
	// output file to be rewritten below too.
	installSFlowSettings(sp, sp->sFlowSettings);
      }

      if(ad_added || ad_cameup || ad_wentdown || ad_changed) {
	// test for switch ports
	configSwitchPorts(sp); // in readPackets.c
	// announce (e.g. to adjust sampling rates if ifSpeeds changed)
	EVEventTxAll(sp->rootModule, HSPEVENT_INTF_CHANGED, NULL, 0);
      }
    }

    // rewrite the output if the config has changed
    if(sp->outputRevisionNo != sp->revisionNo) {
      syncOutputFile(sp);
      sp->outputRevisionNo = sp->revisionNo;
    }

  }

  
  /*_________________---------------------------__________________
    _________________         initAgent         __________________
    -----------------___________________________------------------
  */
  
  static void initAgent(HSP *sp)
  {
    myDebug(1,"creating sfl agent");

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

    SEMLOCK_DO(sp->sync_agent) {
      time_t now = UTClockSeconds();
      sp->agent = (SFLAgent *)my_calloc(sizeof(SFLAgent));
      sfl_agent_init(sp->agent,
		     &sp->agentIP,
		     sp->subAgentId,
		     now,
		     now,
		     sp,
		     agentCB_alloc,
		     agentCB_free,
		     agentCB_error,
		     agentCB_sendPkt);
      // just one receiver - we are serious about making this lightweight for now
      SFLReceiver *receiver = sfl_agent_addReceiver(sp->agent);
      
      // max datagram size might have been tweaked in the config file
      if(sp->sFlowSettings_file->datagramBytes) {
	sfl_receiver_set_sFlowRcvrMaximumDatagramSize(receiver, sp->sFlowSettings_file->datagramBytes);
      }
      
      // claim the receiver slot
      sfl_receiver_set_sFlowRcvrOwner(receiver, "Virtual Switch sFlow Probe");
      
      // set the timeout to infinity
      sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);
    }
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
    sp->daemonize = YES;
    sp->dropPriv = YES;
    sp->refreshAdaptorListSecs = HSP_REFRESH_ADAPTORS;
    sp->refreshVMListSecs = HSP_REFRESH_VMS;
    sp->forgetVMSecs = HSP_FORGET_VMS;
    sp->modulesPath = STRINGIFY_DEF(HSP_MOD_DIR);
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-dvP] [-p PIDFile] [-u UUID] [-f CONFIGFile]\n", command);
    fprintf(stderr,"\n\
             -d:  do not daemonize, and log to stdout/stderr (repeat for more debug details)\n\
             -v:  print version number and exit\n\
             -P:  do not drop privileges (run as root)\n\
     -p PIDFile:  specify PID file (default is " HSP_DEFAULT_PIDFILE ")\n\
        -u UUID:  specify UUID as unique ID for this host\n\
  -f CONFIGFile:  specify config file (default is " HSP_DEFAULT_CONFIGFILE ")\n\n\
   -c CRASHFile:  specify file to write crash info to (default is stderr)\n");
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
    while ((in = getopt(argc, argv, "dDvPp:f:o:u:?hc:")) != -1) {
      switch(in) {
      case 'v':
	printf("%s version %s\n", argv[0], STRINGIFY_DEF(HSP_VERSION)); 
	exit(EXIT_SUCCESS);
	break;
      case 'd':
	// first 'd' just turns off daemonize, second increments debug
	if(!sp->daemonize)
	  setDebug(getDebug() + 1);
	sp->daemonize=NO;
	break;
      case 'P': sp->dropPriv = NO; break;
      case 'p': sp->pidFile = optarg; break;
      case 'f': sp->configFile = optarg; break;
      case 'o': sp->outputFile = optarg; break;
      case 'c': sp->crashFile = optarg; break;
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
    _________________    log_backtrace          __________________
    -----------------___________________________------------------
  */

  static void log_backtrace(int sig, siginfo_t *info) {
#define HSP_NUM_BACKTRACE_PTRS 50
    static void *backtracePtrs[HSP_NUM_BACKTRACE_PTRS];
    
    // ask for the backtrace pointers
    size_t siz = backtrace(backtracePtrs, HSP_NUM_BACKTRACE_PTRS);
    
    if(f_crash == NULL)
      f_crash = stderr;

    // do this first in case everything else is compromised
    backtrace_symbols_fd(backtracePtrs, siz, fileno(f_crash));
    fflush(f_crash);

    // Do something useful with siginfo_t 
    if (sig == SIGSEGV)
      fprintf(f_crash, "SIGSEGV, faulty address is %p\n", info->si_addr);
    
    // thread info
    EVBus *bus = EVCurrentBus();
    fprintf(f_crash, "current bus: %s\n", (bus ? bus->name : "<none>"));
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
    case SIGINT:
      myLog(LOG_INFO,"Received SIGINT");
      // abrupt
      exit(sig);
      break;
    case SIGUSR1:
      myLog(LOG_INFO,"Received SIGUSR1");
      // backtrace only - then keep going
      log_backtrace(sig, info);
      break;
    case SIGUSR2:
      myLog(LOG_INFO,"Received SIGUSR2");
      // memory only - then keep going
      malloc_stats();
      break;
    default:
      myLog(LOG_INFO,"Received signal %d", sig);
      // first make sure we can't go in a loop
      signal(SIGSEGV, SIG_DFL);
      signal(SIGFPE, SIG_DFL);
      signal(SIGILL, SIG_DFL);
      signal(SIGBUS, SIG_DFL);
      signal(SIGXFSZ, SIG_DFL);
      // backtrace and bail
      log_backtrace(sig, info);
      exit(sig);
      break;
    }
  }


  /*_________________---------------------------__________________
    _________________   sFlowSettingsString     __________________
    -----------------___________________________------------------
  */

  char *sFlowSettingsString(HSP *sp, HSPSFlowSettings *settings)
  {
    UTStrBuf *buf = UTStrBuf_new(1024);

    if(settings) {
      UTStrBuf_printf(buf, "hostname=%s\n", sp->hostname);
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
      UTStrBuf_printf(buf, "agentIP=%s\n", SFLAddress_print(&sp->agentIP, ipbuf, 50));
      if(sp->agentDevice) {
	UTStrBuf_printf(buf, "agent=%s\n", sp->agentDevice);
      }
      UTStrBuf_printf(buf, "ds_index=%u\n", HSP_DEFAULT_PHYSICAL_DSINDEX);

      // jsonPort always comes from local config file, but include it here so that
      // others know where to send their JSON application/rtmetric/rtflow messages
      if(sp->json.port) {
	UTStrBuf_printf(buf, "jsonPort=%u\n", sp->json.port);
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
	  sprintf(collectorStr, "collector=%s %u\n", SFLAddress_print(&collector->ipAddr, ipbuf, 50), collector->udpPort);
	  strArrayAdd(iplist, collectorStr);
	}
      }
      strArraySort(iplist);
      char *arrayStr = strArrayStr(iplist, NULL/*start*/, NULL/*quote*/, NULL/*delim*/, NULL/*end*/);
      UTStrBuf_printf(buf, "%s", arrayStr);
      my_free(arrayStr);
      strArrayFree(iplist);
    }
    return UTStrBuf_unwrap(buf);
  }

  /*_________________---------------------------__________________
    _________________   installSFlowSettings    __________________
    -----------------___________________________------------------

    Always increment the revision number whenever we change the sFlowSettings pointer
  */
  
  static void installSFlowSettings(HSP *sp, HSPSFlowSettings *settings)
  {
    char *settingsStr = sFlowSettingsString(sp, settings);
    if(my_strequal(sp->sFlowSettings_str, settingsStr)) {
      // no change - don't increment the revision number
      // (which will mean that the file is not rewritten either)
      if(settingsStr) my_free(settingsStr);
    }
    else {
      // new config
      if(sp->sFlowSettings_str)
	my_free(sp->sFlowSettings_str);
      sp->sFlowSettings_str = settingsStr;
      sp->revisionNo++;
      // atomic pointer-switch.  No need for lock.  At least
      // not on the  platforms we expect to run on.
      sp->sFlowSettings = settings;

      // announce the change
      EVEventTxAll(sp->rootModule, HSPEVENT_CONFIG_CHANGED, NULL, 0);
      EVEventTxAll(sp->rootModule, HSPEVENT_CONFIG_DONE, NULL, 0);
    }
  }

      
  /*_________________---------------------------__________________
    _________________  new config line-by-line  __________________
    -----------------___________________________------------------
    These events passed in from DNS-SD module to submit new SRV and TXT record config.
    The config could probably fit in one PIPE_BUF msg but it's safer to pass it in one
    name-value pair at a time to make sure we never hit that limit.  The sequence is
    HSPEVENT_CONFIG_START
    HSPEVENT_CONFIG_LINE (repeat)
    HSPEVENT_CONFIG_END
  */

  static void evt_config_start(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings_dnsSD_prev)
      freeSFlowSettings(sp->sFlowSettings_dnsSD_prev);
    sp->sFlowSettings_dnsSD_prev = sp->sFlowSettings_dnsSD;
    sp->sFlowSettings_dnsSD = newSFlowSettings();
  }

  static void evt_config_line(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPSFlowSettings *st = sp->sFlowSettings_dnsSD;
    if(st == NULL) {
      myLog(LOG_ERR, "dnssd: no current settings object");
      return;
    }
    char *varval = (char *)data;
    char keyBuf[EV_MAX_EVT_DATALEN];
    char valBuf[EV_MAX_EVT_DATALEN];
    if(parseNextTok(&varval, "=", YES, '"', YES, keyBuf, EV_MAX_EVT_DATALEN)
       && parseNextTok(&varval, "=", YES, '"', YES, valBuf, EV_MAX_EVT_DATALEN)) {
      
      if(my_strequal(keyBuf, "collector")) { // TODO: string constant for this from tokens
	int valLen = my_strlen(valBuf);
	if(valLen > 3) {
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
	// key=val (TXT record line)
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
#if HSP_DNSSD_AGENTCIDR
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
#endif /* HSP_DNSSD_AGENTCIDR */
	else {
	  myLog(LOG_INFO, "unexpected dnsSD record <%s>=<%s>", keyBuf, valBuf);
	}
      }
    }
  }

  static void evt_config_end(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // initiate server-discovery
    HSP *sp = (HSP *)EVROOTDATA(mod);
    assert(dataLen = sizeof(int));
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
      installSFlowSettings(sp, sp->sFlowSettings_dnsSD);
    }
  }
      
  /*_________________---------------------------__________________
    _________________   evt_config_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings) {
      // we have a config - proceed
      
      if(sp->sFlowSettings->collectors == NULL) {
	myLog(LOG_ERR, "evt_config_changed: no collectors defined");
	if(!sp->DNSSD.DNSSD)
	  abort();
      }
      else {
	myDebug(1, "evt_config_changed: got collector(s)");
      }
      
      // pick up the configured polling interval
      uint32_t pollingInterval = sp->sFlowSettings ? sp->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
      uint32_t previousPollingInterval = sp->poller ? sfl_poller_get_sFlowCpInterval(sp->poller) : 0;

      if(!sp->poller) {
	// first time!
	myDebug(1, "evt_config_changed: first valid configuration");

	// print some stats to help us size HSP_RLIMIT_MEMLOCK etc.
	malloc_stats();
	
	// add a <physicalEntity> poller to represent the whole physical host
	SFLDataSource_instance dsi;
	// ds_class = <physicalEntity>, ds_index = <my physical>, ds_instance = 0
	SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, HSP_DEFAULT_PHYSICAL_DSINDEX, 0);
	sp->poller = sfl_agent_addPoller(sp->agent, &dsi, sp, agentCB_getCounters_request);
	sfl_poller_set_sFlowCpInterval(sp->poller, pollingInterval);
	sfl_poller_set_sFlowCpReceiver(sp->poller, HSP_SFLOW_RECEIVER_INDEX);
      }
	
	
      // did the polling interval change?
      if(pollingInterval != previousPollingInterval) {
	
	myDebug(1, "polling interval changed from %u to %u",
		previousPollingInterval, pollingInterval);
	
	// Note that this will change polling for VMs etc. as well
	SEMLOCK_DO(sp->sync_agent) {
	  for(SFLPoller *pl = sp->agent->pollers; pl; pl = pl->nxt) {
	    sfl_poller_set_sFlowCpInterval(pl, pollingInterval);
	  }
	}
      }

      // now that interfaces have been read and sflow agent is
      // initialized, check to see if we should be exporting
      // individual counter data for switch port interfaces, and
      // look to sync bond polling.
      configSwitchPorts(sp); // in readPackets.c

    } // sflowSettings
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

    if(sp->cumulus.cumulus) {
      // For now we have to retain root privileges on Cumulus Linux because
      // we need to run the portsamp program any time the sampling-rate changes
      // (which can happen if the ifSpeed changes on a port or if the config
      // is changed via DNS-SD)
      myDebug(1, "not relinquishing root privileges -- needed to set switch port sampling-rates");
    }
    else if(sp->docker.docker) {
      // Similarly, when running Docker containers we still need more
      // capabilities to be passed down so that we can run "docker ps -q"
      // and "docker inspect <id>" successfully.
      myDebug(1, "not relinquishing root privileges -- needed to read docker container info");
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
    // TODO: SIGPIPE?

    // init
    setDefaults(sp);

    // read the command line
    processCommandLine(sp, argc, argv);
      
    // don't run if we think another one is already running
    if(UTFileExists(sp->pidFile)) {
      myLog(LOG_ERR,"Another %s is already running. If this is an error, remove %s", argv[0], sp->pidFile);
      exit(EXIT_FAILURE);
    }

    if(sp->daemonize) {
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
    
    myLog(LOG_INFO, "started");

    // semaphore to protect structure of sFlow agent (sampler and poller lists
    // and XDR datagram encoding)
    sp->sync_agent = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(sp->sync_agent, NULL);

    // poll actions array
    sp->pollActions = UTArrayNew(UTARRAY_DFLT);

    // allocate device tables - these ones need sync
    sp->adaptorsByName = UTHASH_NEW(SFLAdaptor, deviceName, UTHASH_SYNC | UTHASH_SKEY);
    sp->adaptorsByIndex = UTHASH_NEW(SFLAdaptor, ifIndex, UTHASH_SYNC);
    sp->adaptorsByPeerIndex = UTHASH_NEW(SFLAdaptor, peer_ifIndex, UTHASH_SYNC);
    sp->adaptorsByMac = UTHASH_NEW(SFLAdaptor, macs[0], UTHASH_SYNC);

    // these ones do not need sync - always accessed from same thread
    sp->vmsByUUID = UTHASH_NEW(HSPVMState, uuid, UTHASH_DFLT);
    sp->vmsByDsIndex = UTHASH_NEW(HSPVMState, dsIndex, UTHASH_DFLT);
    
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

    // some modules can be triggered to load even if they are not
    // explicitly in the config file - but do this before we read
    // the config so that overrides are possible.
    if(UTFileExists(HSP_CUMULUS_SWITCHPORT_CONFIG_PROG)) {
      myLog(LOG_INFO, "Detected Cumulus Linux");
      sp->cumulus.cumulus = YES;
      sp->ulog.ulog = YES;
      sp->ulog.group = 1;
    }
    if(UTFileExists(HSP_OS10_SWITCHPORT_CONFIG_PROG)) {
      myLog(LOG_INFO, "Detected OS10");
      sp->os10.os10 = YES;
    }
    
    // a sucessful read of the config file is required
    if(HSPReadConfigFile(sp) == NO) {
      myLog(LOG_ERR, "failed to read config file\n");
      exit(EXIT_FAILURE);
    }
    
    // must be able to read interfaces
    if(readInterfaces(sp, NULL, NULL, NULL, NULL, NULL) == 0) {
      myLog(LOG_ERR, "failed to read interfaces\n");
      exit(EXIT_FAILURE);
    }

    // must be able to choose an agent address
    if(selectAgentAddress(sp, NULL) == NO) {
      myLog(LOG_ERR, "failed to select agent address\n");
      exit(EXIT_FAILURE);
    }

    // we must have an agentIP now, so we can use
    // it to seed the random number generator
    SFLAddress *agentIP = &sp->agentIP;
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
	
    // set up the sFlow agent (with no pollers or samplers yet)
    initAgent(sp);

    // initialize event bus
    sp->rootModule = EVInit(sp);

    // load modules (except DNSSD - loaded below)
    if(sp->json.json)
      EVLoadModule(sp->rootModule, "mod_json", sp->modulesPath);
    if(sp->kvm.kvm)
      EVLoadModule(sp->rootModule, "mod_kvm", sp->modulesPath);
    if(sp->xen.xen)
      EVLoadModule(sp->rootModule, "mod_xen", sp->modulesPath);
    if(sp->docker.docker)
      EVLoadModule(sp->rootModule, "mod_docker", sp->modulesPath);
    if(sp->pcap.pcap)
      EVLoadModule(sp->rootModule, "mod_pcap", sp->modulesPath);
    if(sp->ulog.ulog)
      EVLoadModule(sp->rootModule, "mod_ulog", sp->modulesPath);
    if(sp->nflog.nflog)
      EVLoadModule(sp->rootModule, "mod_nflog", sp->modulesPath);
    if(sp->nvml.nvml)
      EVLoadModule(sp->rootModule, "mod_nvml", sp->modulesPath);
    if(sp->ovs.ovs)
      EVLoadModule(sp->rootModule, "mod_ovs", sp->modulesPath);
    if(sp->cumulus.cumulus)
      EVLoadModule(sp->rootModule, "mod_cumulus", sp->modulesPath);
    if(sp->os10.os10)
      EVLoadModule(sp->rootModule, "mod_os10", sp->modulesPath);

    sp->pollBus = EVGetBus(sp->rootModule, HSPBUS_POLL, YES);

    // register for events that we are going to handle here in the main pollBus thread
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_START), evt_config_start);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_LINE), evt_config_line);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_END), evt_config_end);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, HSPEVENT_CONFIG_DONE), evt_config_done);
    EVEventRx(sp->rootModule, EVGetEvent(sp->pollBus, EVEVENT_TICK), evt_poll_tick);

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
      // That calls evt_config_changed() below, which updates polling and
      // sampling settings.
    }
    else {
      // just push in the config from the file. This will trigger a
      // HSPEVENT_CONFIG_CHANGED right away.
      installSFlowSettings(sp, sp->sFlowSettings_file);
    }

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

    exit(exitStatus);
  } /* main() */
  
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

