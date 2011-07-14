/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#define HSFLOWD_MAIN

#include "hsflowd.h"

  // globals - easier for signal handler
  HSP HSPSamplingProbe;
  int exitStatus = EXIT_SUCCESS;
  extern int debug;
  FILE *f_crash;

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
    free(obj);
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


  void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;

    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char hnamebuf[SFL_MAX_HOSTNAME_CHARS+1];
    char osrelbuf[SFL_MAX_OSRELEASE_CHARS+1];
    if(readHidCounters(sp,
		       &hidElem.counterBlock.host_hid,
		       hnamebuf,
		       SFL_MAX_HOSTNAME_CHARS,
		       osrelbuf,
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
      SFLADD_ELEMENT(cs, &cpuElem);
    }

    // host memory counters
    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_MEM;
    if(readMemoryCounters(&memElem.counterBlock.host_mem)) {
      SFLADD_ELEMENT(cs, &memElem);
    }

    // host I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_DSK;
    if(readDiskCounters(sp, &dskElem.counterBlock.host_dsk)) {
      SFLADD_ELEMENT(cs, &dskElem);
    }

    // include the adaptor list
    SFLCounters_sample_element adaptorsElem = { 0 };
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    adaptorsElem.counterBlock.adaptors = sp->adaptorList;
    SFLADD_ELEMENT(cs, &adaptorsElem);

    sfl_poller_writeCountersSample(poller, cs);
  }

  /*_________________---------------------------__________________
    _________________    persistent dsIndex     __________________
    -----------------___________________________------------------
  */

  static HSPVMStore *newVMStore(HSP *sp, char *uuid, uint32_t dsIndex) {
    HSPVMStore *vmStore = (HSPVMStore *)my_calloc(sizeof(HSPVMStore));
    memcpy(vmStore->uuid, uuid, 16);
    vmStore->dsIndex = dsIndex;
    ADD_TO_LIST(sp->vmStore, vmStore);
    return vmStore;
  }

  static void readVMStore(HSP *sp) {
    if(sp->f_vmStore == NULL) return;
    char line[HSP_MAX_VMSTORE_LINELEN+1];
    rewind(sp->f_vmStore);
    uint32_t lineNo = 0;
    while(fgets(line, HSP_MAX_VMSTORE_LINELEN, sp->f_vmStore)) {
      lineNo++;
      char *p = line;
      // comments start with '#'
      p[strcspn(p, "#")] = '\0';
      // should just have two tokens, so check for 3
      uint32_t tokc = 0;
      char *tokv[3];
      for(int i = 0; i < 3; i++) {
	size_t len;
	p += strspn(p, HSP_VMSTORE_SEPARATORS);
	if((len = strcspn(p, HSP_VMSTORE_SEPARATORS)) == 0) break;
	tokv[tokc++] = p;
	p += len;
	if(*p != '\0') *p++ = '\0';
      }
      // expect UUID=int
      char uuid[16];
      if(tokc != 2 || !parseUUID(tokv[0], uuid)) {
	myLog(LOG_ERR, "readVMStore: bad line %u in %s", lineNo, sp->vmStoreFile);
      }
      else {
	HSPVMStore *vmStore = newVMStore(sp, uuid, strtol(tokv[1], NULL, 0));
	if(vmStore->dsIndex > sp->maxDsIndex) {
	  sp->maxDsIndex = vmStore->dsIndex;
	}
      }
    }
  }

  static void writeVMStore(HSP *sp) {
    rewind(sp->f_vmStore);
    for(HSPVMStore *vmStore = sp->vmStore; vmStore != NULL; vmStore = vmStore->nxt) {
      char uuidStr[51];
      printUUID((u_char *)vmStore->uuid, (u_char *)uuidStr, 50);
      fprintf(sp->f_vmStore, "%s=%u\n", uuidStr, vmStore->dsIndex);
    }
    fflush(sp->f_vmStore);
    // chop off anything that may be lingering from before
    truncateOpenFile(sp->f_vmStore);
  }

  uint32_t assignVM_dsIndex(HSP *sp, char *uuid) {
    // check in case we saw this one before
    HSPVMStore *vmStore = sp->vmStore;
    for ( ; vmStore != NULL; vmStore = vmStore->nxt) {
      if(memcmp(uuid, vmStore->uuid, 16) == 0) return vmStore->dsIndex;
    }
    // allocate a new one
    vmStore = newVMStore(sp, uuid, ++sp->maxDsIndex);
    // ask it to be written to disk
    sp->vmStoreInvalid = YES;
    return sp->maxDsIndex;
  }
    
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

    HSPSFlowSettings *settings = sp->sFlow->sFlowSettings;
    if(settings) {
      fprintf(sp->f_out, "sampling=%u\n", settings->samplingRate);
      if(settings->samplingRate_http != HSP_SETTING_UNDEFINED) {
	fprintf(sp->f_out, "sampling.http=%u\n", settings->samplingRate_http);
      }
      if(settings->samplingRate_memcache != HSP_SETTING_UNDEFINED) {
	fprintf(sp->f_out, "sampling.memcache=%u\n", settings->samplingRate_memcache);
      }
      fprintf(sp->f_out, "header=128\n");
      fprintf(sp->f_out, "polling=%u\n", settings->pollingInterval);
      if(settings->pollingInterval_http != HSP_SETTING_UNDEFINED) {
	fprintf(sp->f_out, "polling.http=%u\n", settings->pollingInterval_http);
      }
      if(settings->pollingInterval_memcache != HSP_SETTING_UNDEFINED) {
	fprintf(sp->f_out, "polling.memcache=%u\n", settings->pollingInterval_memcache);
      }
      char ipbuf[51];
      fprintf(sp->f_out, "agentIP=%s\n", printIP(&sp->sFlow->agentIP, ipbuf, 50));
      if(sp->sFlow->agentDevice) {
	fprintf(sp->f_out, "agent=%s\n", sp->sFlow->agentDevice);
      }
      for(HSPCollector *collector = settings->collectors; collector; collector = collector->nxt) {
	// <ip> <port> [<priority>]
	fprintf(sp->f_out, "collector=%s %u\n", printIP(&collector->ipAddr, ipbuf, 50), collector->udpPort);
      }
    }

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
    if(sp->adaptorNIOList.polling_secs &&
       ((sp->clk % sp->adaptorNIOList.polling_secs) == 0)) {
      updateNioCounters(sp);
    }
    
    // refresh the list of VMs if requested
    if(sp->refreshVMList || (sp->clk % HSP_REFRESH_VMS) == 0) {
      sp->refreshVMList = NO;
      // configVMs(sp);
    }

    // write the persistent state if requested
    if(sp->vmStoreInvalid) {
      writeVMStore(sp);
      sp->vmStoreInvalid = NO;
    }

    // refresh the interface list if requested
    if(sp->refreshAdaptorList) {
      sp->refreshAdaptorList = NO;
      readInterfaces(sp);
    }


    // rewrite the output if the config has changed
    if(sp->outputRevisionNo != sp->sFlow->revisionNo) {
      syncOutputFile(sp);
      sp->outputRevisionNo = sp->sFlow->revisionNo;
    }
  }


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
      myLog(LOG_ERR, "No collectors defined");
      return NO;
    }

    assert(sf->agentIP.type);
    
    // open the sockets if not open already - one for v4 and another for v6
    if(sp->socket4 <= 0) {
      if((sp->socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	myLog(LOG_ERR, "IPv4 send socket open failed : %s", strerror(errno));
    }
    if(sp->socket6 <= 0) {
      if((sp->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	myLog(LOG_ERR, "IPv6 send socket open failed : %s", strerror(errno));
    }

    time_t now = time(NULL);
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
    HSPCollector *collector = sf->sFlowSettings->collectors;
    SFLReceiver *receiver = sfl_agent_addReceiver(sf->agent);
    
    // claim the receiver slot
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Virtual Switch sFlow Probe");
    
    // set the timeout to infinity
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);

    // receiver address/port - set it for the first collector,  but
    // actually we'll send the same feed to all collectors.  This step
    // may not be necessary at all when we are using the sendPkt callback.
    sfl_receiver_set_sFlowRcvrAddress(receiver, &collector->ipAddr);
    sfl_receiver_set_sFlowRcvrPort(receiver, collector->udpPort);
    
    uint32_t pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
    
    // add a <physicalEntity> poller to represent the whole physical host
    SFLDataSource_instance dsi;
  // ds_class = <physicalEntity>, ds_index = 1, ds_instance = 0
    SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, 1, 0);
    sf->poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(sf->poller, pollingInterval);
    sfl_poller_set_sFlowCpReceiver(sf->poller, HSP_SFLOW_RECEIVER_INDEX);
    
    // add <virtualEntity> pollers for each virtual machine
    // configVMs(sp);
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
    sp->vmStoreFile = HSP_DEFAULT_VMSTORE_FILE;
    sp->crashFile = HSP_DEFAULT_CRASH_FILE;
    sp->dropPriv = YES;
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
    while ((in = getopt(argc, argv, "dvPp:f:o:u:?h")) != -1) {
      switch(in) {
      case 'd': debug++; break;
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

static void 
signal_handler(int sig, siginfo_t *info, void *secret) 
{
    HSP *sp = &HSPSamplingProbe;
#define HSP_NUM_BACKTRACE_PTRS 50
#if !defined(FreeBSD)
    static void *backtracePtrs[HSP_NUM_BACKTRACE_PTRS];
#endif

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
#if !defined(FreeBSD)
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
#endif
      }
      break;
    }
}

  /*_________________---------------------------__________________
    _________________   installSFlowSettings    __________________
    -----------------___________________________------------------

    Always increment the revision number whenever we change the sFlowSettings pointer
  */
  
  static void installSFlowSettings(HSPSFlow *sf, HSPSFlowSettings *settings)
  {
    sf->sFlowSettings = settings;
    sf->revisionNo++;
  }

  /*_________________---------------------------__________________
    _________________        runDNSSD           __________________
    -----------------___________________________------------------
  */

  static void myDnsCB(HSP *sp, uint16_t rtype, uint32_t ttl, u_char *key, int keyLen, u_char *val, int valLen)
  {
    HSPSFlowSettings *st = sp->sFlow->sFlowSettings_dnsSD;

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
    // null terminate
    memcpy(keyBuf, (char *)key, keyLen);
    keyBuf[keyLen] = '\0';
    memcpy(valBuf, (char *)val, valLen);
    valBuf[valLen] = '\0';

    if(debug) {
      myLog(LOG_INFO, "dnsSD: (rtype=%u,ttl=%u) <%s>=<%s>", rtype, ttl, keyBuf, valBuf);
    }

    if(key == NULL && val && valLen > 3) {
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
    else if(strcmp(keyBuf, "sampling") == 0) {
      st->samplingRate = strtol(valBuf, NULL, 0);
    }
    else if(strcmp(keyBuf, "sampling.http") == 0) {
      st->samplingRate_http = strtol(valBuf, NULL, 0);
    }
    else if(strcmp(keyBuf, "sampling.memcache") == 0) {
      st->samplingRate_memcache = strtol(valBuf, NULL, 0);
    }
    else if(strcmp(keyBuf, "txtvers") == 0) {
    }
    else if(strcmp(keyBuf, "polling") == 0) {
      st->pollingInterval = strtol(valBuf, NULL, 0);
    }
    else if(strcmp(keyBuf, "polling.http") == 0) {
      st->pollingInterval_http = strtol(valBuf, NULL, 0);
    }
    else if(strcmp(keyBuf, "polling.memcache") == 0) {
      st->pollingInterval_memcache = strtol(valBuf, NULL, 0);
    }
    else {
      myLog(LOG_INFO, "unexpected dnsSD record <%s>=<%s>", keyBuf, valBuf);
    }
  }

  static void *runDNSSD(void *magic) {
    HSP *sp = (HSP *)magic;
    sp->DNSSD_countdown = sfl_random(sp->DNSSD_startDelay);
    time_t clk = time(NULL);
    while(1) {
      my_usleep(999983); // just under a second
      time_t test_clk = time(NULL);
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
	// SIGSEGV on Fedora 14 if HSP_RLIMIT_MEMLOCK is non-zero, because calloc returns NULL.
	// Maybe we need to repeat some of the setrlimit() calls here in the forked thread? Or
	// maybe we are supposed to fork the DNSSD thread before dropping privileges?
	sf->sFlowSettings_dnsSD = newSFlowSettings();
	// we want the min ttl, so clear it here
	sp->DNSSD_ttl = 0;
	// now make the requests
	int num_servers = dnsSD(sp, myDnsCB);
	SEMLOCK_DO(sp->config_mut) {
	  // three cases here:
	  // A) if(num_servers == -1) (i.e. query failed) then keep the current config
	  // B) if(num_servers == 0) then stop monitoring
	  // C) if(num_servers > 0) then install the new config
	  if(debug) myLog(LOG_INFO, "num_servers == %d", num_servers);
	  if(num_servers >= 0) {
	    // remove the current config
	    if(sf->sFlowSettings && sf->sFlowSettings != sf->sFlowSettings_file) freeSFlowSettings(sf->sFlowSettings);
	    installSFlowSettings(sf, NULL);
	  }
	  if(num_servers <= 0) {
	    // clean up, and go into 'retry' mode
	    freeSFlowSettings(sf->sFlowSettings_dnsSD);
	    sf->sFlowSettings_dnsSD = NULL;
	    // we might still learn a TTL (e.g. from the TXT record query)
	    sp->DNSSD_countdown = sp->DNSSD_ttl == 0 ? sp->DNSSD_retryDelay : sp->DNSSD_ttl;
	  }
	  else {
	    // make this the running config
	    installSFlowSettings(sf, sf->sFlowSettings_dnsSD);
	    sp->DNSSD_countdown = sp->DNSSD_ttl;
	  }
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
  

  static void drop_privileges(int requestMemLockBytes) {
    
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
      
      // set the real and effective group-id to 'nobody'
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
#if !defined(FreeBSD)
	GETMYLIMIT(RLIMIT_LOCKS);
#endif
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________         main              __________________
    -----------------___________________________------------------
  */
  
  int main(int argc, char *argv[])
  {
    HSP *sp = &HSPSamplingProbe;

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

    if(debug == 0) {
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
	i = open("/dev/null",O_RDWR); // stdin
	dup(i);                       // stdout
	dup(i);                       // stderr
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
    
    myLog(LOG_INFO, "started");
    
    // initialize the clock so we can detect second boundaries
    sp->clk = time(NULL);

    // semaphore to protect config shared with DNSSD thread
    sp->config_mut = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(sp->config_mut, NULL);
    
    setState(sp, HSPSTATE_READCONFIG);

    while(sp->state != HSPSTATE_END) {
      
      switch(sp->state) {
	
      case HSPSTATE_READCONFIG:
	if(readInterfaces(sp) == 0 ){
	   printf("OOPS 1\n");
	  exitStatus = EXIT_FAILURE;
	  setState(sp, HSPSTATE_END);
	}
	if(HSPReadConfigFile(sp) == NO) {
	   printf("OOPS 2\n");
	  exitStatus = EXIT_FAILURE;
	  setState(sp, HSPSTATE_END);
	}
	else {
	  // we must have an agentIP, so we can use
	  // it to seed the random number generator
	  SFLAddress *agentIP = &sp->sFlow->agentIP;
	  uint32_t seed = 0;
	  if(agentIP->type == SFLADDRESSTYPE_IP_V4) seed = agentIP->address.ip_v4.addr;
	  else memcpy(agentIP->address.ip_v6.addr + 12, &seed, 4);
	  sfl_random_init(seed);

	
	  // load the persistent state from last time
	  readVMStore(sp);

	  // initialize the faster polling of NIO counters
	  // to avoid undetected 32-bit wraps
	  sp->adaptorNIOList.polling_secs = HSP_NIO_POLLING_SECS_32BIT;
	  
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
	}
	break;
	
      case HSPSTATE_WAITCONFIG:
	SEMLOCK_DO(sp->config_mut) {
	  if(sp->sFlow->sFlowSettings) {
	    // we have a config - proceed
	    if(initAgent(sp)) {
	      if(debug) {
		myLog(LOG_INFO, "initAgent suceeded");
		// print some stats to help us size HSP_RLIMIT_MEMLOCK etc.
#if !defined(FreeBSD)
		malloc_stats();
#endif
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

	      setState(sp, HSPSTATE_RUN);
	    }
	    else {
	      exitStatus = EXIT_FAILURE;
	      setState(sp, HSPSTATE_END);
	    }
	  }
	}
	break;
	
      case HSPSTATE_RUN:
	{
	  // check for second boundaries and generate ticks for the sFlow library
	  time_t test_clk = time(NULL);
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
	      if(sp->sFlow->sFlowSettings) {
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

      // set the timeout so that if all is quiet we will
      // still loop around and check for ticks/signals
      // several times per second
      my_usleep(200000);
    }

    // get here if a signal kicks the state to HSPSTATE_END
    // and we break out of the loop above.
    // If that doesn't happen the most likely explanation
    // is a bug that caused the semaphore to be acquired
    // and not released,  but that would only happen if the
    // DNSSD thread died or hung up inside the critical block.
    closelog();
    myLog(LOG_INFO,"stopped");

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

