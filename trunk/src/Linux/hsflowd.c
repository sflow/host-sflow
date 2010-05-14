/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  typedef enum { HSPSTATE_END, HSPSTATE_RUN, HSPSTATE_READCONFIG } EnumHSPState;

  // global - easier for signal handler
  EnumHSPState vsp_state = HSPSTATE_READCONFIG;
  int exitStatus = EXIT_SUCCESS;
  int debug = 0;

  /*_________________---------------------------__________________
    _________________        logging            __________________
    -----------------___________________________------------------
  */

  void myLog(int syslogType, char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    if(debug) {
      vfprintf(stderr, fmt, args);
      fprintf(stderr, "\n");
    }
    else vsyslog(syslogType, fmt, args);
  }

  /*_________________---------------------------__________________
    _________________     agent callbacks       __________________
    -----------------___________________________------------------
  */

  static void *agentCB_alloc(void *magic, SFLAgent *agent, size_t bytes)
  {
    return calloc(1, bytes);
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

    for(HSPCollector *coll = sp->sFlow->collectors; coll; coll=coll->nxt) {

      switch(coll->ipAddr.type) {
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
    SFLCounters_sample_element hidElem;
    memset(&hidElem, 0, sizeof(hidElem));
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char hnamebuf[SFL_MAX_HOSTNAME_CHARS+1];
    char osrelbuf[SFL_MAX_OSRELEASE_CHARS+1];
    if(readHidCounters(&hidElem.counterBlock.host_hid,
		       hnamebuf,
		       SFL_MAX_HOSTNAME_CHARS,
		       osrelbuf,
		       SFL_MAX_OSRELEASE_CHARS)) {
      SFLADD_ELEMENT(cs, &hidElem);
    }

    // host Net I/O
    SFLCounters_sample_element nioElem;
    memset(&nioElem, 0, sizeof(nioElem));
    nioElem.tag = SFLCOUNTERS_HOST_NIO;
    if(readNioCounters(&nioElem.counterBlock.host_nio, NULL)) {
      SFLADD_ELEMENT(cs, &nioElem);
    }

    // host cpu counters
    SFLCounters_sample_element cpuElem;
    memset(&cpuElem, 0, sizeof(cpuElem));
    cpuElem.tag = SFLCOUNTERS_HOST_CPU;
    if(readCpuCounters(&cpuElem.counterBlock.host_cpu)) {
      SFLADD_ELEMENT(cs, &cpuElem);
    }

    // host memory counters
    SFLCounters_sample_element memElem;
    memset(&memElem, 0, sizeof(memElem));
    memElem.tag = SFLCOUNTERS_HOST_MEM;
    if(readMemoryCounters(&memElem.counterBlock.host_mem)) {
      SFLADD_ELEMENT(cs, &memElem);
    }

    // host I/O counters
    SFLCounters_sample_element dskElem;
    memset(&dskElem, 0, sizeof(dskElem));
    dskElem.tag = SFLCOUNTERS_HOST_DSK;
    if(readDiskCounters(&dskElem.counterBlock.host_dsk)) {
      SFLADD_ELEMENT(cs, &dskElem);
    }

    // include the adaptor list
    SFLCounters_sample_element adaptorsElem;
    memset(&adaptorsElem, 0, sizeof(adaptorsElem));
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    adaptorsElem.counterBlock.adaptors = sp->adaptorList;
    SFLADD_ELEMENT(cs, &adaptorsElem);

    sfl_poller_writeCountersSample(poller, cs);
  }

#ifdef XENSTAT

#define HSP_MAX_PATHLEN 256
#define XEN_SYSFS_VBD_PATH "/sys/devices/xen-backend"

  static int64_t xen_vbd_counter(uint32_t dom_id, uint32_t vbd_dev, char *counter)
  {
    int64_t ctr64 = 0;
    char path[HSP_MAX_PATHLEN];
    snprintf(path, HSP_MAX_PATHLEN, XEN_SYSFS_VBD_PATH "/vbd-%u-%u/statistics/%s", dom_id, vbd_dev, counter);
    FILE *file = fopen(path, "r");
    if(file) {
      fscanf(file, "%"SCNi64, &ctr64);
      fclose(file);
    }
    return ctr64;
  }
  
  static int xenstat_dsk(HSP *sp, uint32_t dom_id, SFLHost_vrt_dsk_counters *dsk)
  {
    // [ref xenstat_linux.c]
#define SYSFS_VBD_PATH "/sys/devices/xen-backend/"
    DIR *sysfsvbd = opendir(SYSFS_VBD_PATH);
    if(sysfsvbd == NULL) {
      myLog(LOG_ERR, "opendir %s failed : %s", SYSFS_VBD_PATH, strerror(errno));
      return NO;
    }

    char scratch[sizeof(struct dirent) + _POSIX_PATH_MAX];
    struct dirent *dp = NULL;
    for(;;) {
      readdir_r(sysfsvbd, (struct dirent *)scratch, &dp);
      if(dp == NULL) break;
      uint32_t vbd_dom_id;
      uint32_t vbd_dev;
      char vbd_type[256];
      if(sscanf(dp->d_name, "%3s-%u-%u", vbd_type, &vbd_dom_id, &vbd_dev) == 3) {
	if(vbd_dom_id == dom_id) {
	  //dsk->apacity 
	  //dsk->allocation 
	  //dsk->available
	  if(debug > 1) myLog(LOG_INFO, "reading VBD %s for dom_id %u", dp->d_name, dom_id); 
	  dsk->rd_req += xen_vbd_counter(dom_id, vbd_dev, "rd_req");
	  dsk->rd_bytes += (xen_vbd_counter(dom_id, vbd_dev, "rd_sect") * HSP_SECTOR_BYTES);
	  dsk->wr_req += xen_vbd_counter(dom_id, vbd_dev, "wr_req");
	  dsk->wr_bytes += (xen_vbd_counter(dom_id, vbd_dev, "wr_sect") * HSP_SECTOR_BYTES);
	}
      }
    }
    closedir(sysfsvbd);
    return YES;
  }

  static SFLAdaptorList *xenstat_adaptors(HSP *sp, uint32_t dom_id, SFLAdaptorList *myAdaptors)
  {
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      uint32_t vif_domid;
      uint32_t vif_netid;
      if(sscanf(adaptor->deviceName, "vif%"SCNu32".%"SCNu32, &vif_domid, &vif_netid) == 2) {
	if(vif_domid == dom_id && myAdaptors->num_adaptors < HSP_MAX_VIFS) {
	  myAdaptors->adaptors[myAdaptors->num_adaptors++] = adaptor;
	  char macQuery[256];
	  snprintf(macQuery, sizeof(macQuery), "/local/domain/%u/device/vif/%u/mac", vif_domid, vif_netid);
	  char *macStr = xs_read(sp->xs_handle, XBT_NULL, "/local/domain/1/device/vif/0/mac", NULL);
	  if(macStr == NULL) {
	    myLog(LOG_ERR, "mac address query failed : %s : %s", macQuery, strerror(errno));
	  }
	  else{
	    if(adaptor->num_macs > 0) {
	      if(hexToBinary((u_char *)macStr, adaptor->macs[0].mac, 6) != 6) {
		myLog(LOG_ERR, "mac address format error in xenstore query <%s> : %s", macQuery, macStr);
	      }
	    }
	    free(macStr);
	  }
	}
      }
    }
    return myAdaptors;
  }
  
#endif

  void agentCB_getCountersVM(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
#ifdef XENSTAT
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;
    HSPVMState *state = (HSPVMState *)poller->userData;

    if(state && sp->xs_handle) {
      
      uint32_t dom_id = SFL_DS_INDEX(poller->dsi);
      xc_domaininfo_t domaininfo;
      int32_t n = xc_domain_getinfolist(sp->xc_handle, state->vm_index, 1, &domaininfo);
      if(n < 0 || domaininfo.domain != dom_id) {
	// Assume something changed under our feet.
	// Request a reload of the VM information and bail.
	// We'll try again next time.
	myLog(LOG_INFO, "request for vm_index %u (dom_id=%u) returned %d (with dom_id=%u)",
	      state->vm_index,
	      dom_id,
	      n,
	      domaininfo.domain);
	sp->refreshVMList = YES;
	return;
      }
      
      // host ID
      SFLCounters_sample_element hidElem;
      memset(&hidElem, 0, sizeof(hidElem));
      hidElem.tag = SFLCOUNTERS_HOST_HID;
      char query[255];
      char hname[255];
      snprintf(query, sizeof(query), "/local/domain/%u/name", dom_id);
      char *xshname = (char *)xs_read(sp->xs_handle, XBT_NULL, query, NULL);
      if(xshname) {
	// copy it here so we can free it straight away
	strncpy(hname, xshname, 255);
	free(xshname);
	hidElem.counterBlock.host_hid.hostname.str = hname;
	hidElem.counterBlock.host_hid.hostname.len = strlen(hname);
	//hidElem.counterBlock.host_hid.uuid;
	//hidElem.counterBlock.host_hid.machine_type = SFLMT_unknown;
	//hidElem.counterBlock.host_hid.os_name = SFLOS_unknown;
	//hidElem.counterBlock.host_hid.os_release.str = NULL;
	//hidElem.counterBlock.host_hid.os_release.len = 0;
	SFLADD_ELEMENT(cs, &hidElem);
      }
      
      // host parent
      SFLCounters_sample_element parElem;
      memset(&parElem, 0, sizeof(parElem));
      parElem.tag = SFLCOUNTERS_HOST_PAR;
      parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
      parElem.counterBlock.host_par.dsIndex = 1;
      SFLADD_ELEMENT(cs, &parElem);

      // VM Net I/O
      SFLCounters_sample_element nioElem;
      memset(&nioElem, 0, sizeof(nioElem));
      nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
      char devFilter[20];
      snprintf(devFilter, 20, "vif%u.", dom_id);
      uint32_t network_count = readNioCounters((SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio, devFilter);
      if(state->network_count != network_count) {
	// request a refresh if the number of VIFs changed. Not a perfect test
	// (e.g. if one was removed and another was added at the same time then
	// we would miss it). I guess we should keep the whole list of network ids,
	// or just force a refresh every few minutes?
	myLog(LOG_INFO, "vif count changed from %u to %u (dom_id=%u). Setting refreshAdaptorList=YES",
	      state->network_count,
	      network_count,
	      dom_id);
	state->network_count = network_count;
	sp->refreshAdaptorList = YES;
      }
      SFLADD_ELEMENT(cs, &nioElem);

      // VM cpu counters [ref xenstat.c]
      SFLCounters_sample_element cpuElem;
      memset(&cpuElem, 0, sizeof(cpuElem));
      cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
      u_int64_t vcpu_ns = 0;
      for(uint32_t c = 0; c <= domaininfo.max_vcpu_id; c++) {
	xc_vcpuinfo_t info;
	if(xc_vcpu_getinfo(sp->xc_handle, dom_id, c, &info) != 0) {
	  // error or domain is in transition.  Just bail.
	  myLog(LOG_INFO, "vcpu list in transition (dom_id=%u)", dom_id);
	  return;
	}
	else {
	  if(info.online) {
	    vcpu_ns += info.cpu_time;
	  }
	}
      }
      cpuElem.counterBlock.host_vrt_cpu.state = 0; // domain->state libvirt enum $$$
      cpuElem.counterBlock.host_vrt_cpu.cpuTime = vcpu_ns;
      cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = domaininfo.max_vcpu_id + 1;
      SFLADD_ELEMENT(cs, &cpuElem);

      // VM memory counters [ref xenstat.c]
      SFLCounters_sample_element memElem;
      memset(&memElem, 0, sizeof(memElem));
      memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
      uint64_t memBytes = domaininfo.tot_pages * sp->page_size;
      memElem.counterBlock.host_vrt_mem.memory = (memBytes / 1024);
      if(domaininfo.max_pages == UINT_MAX) {
	memElem.counterBlock.host_vrt_mem.maxMemory = -1;
      }
      else {
	uint64_t maxBytes = domaininfo.max_pages * sp->page_size;
	memElem.counterBlock.host_vrt_mem.maxMemory = (maxBytes / 1024);
      }
      SFLADD_ELEMENT(cs, &memElem);

      // VM disk I/O counters
      SFLCounters_sample_element dskElem;
      memset(&dskElem, 0, sizeof(dskElem));
      dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
      if(xenstat_dsk(sp, dom_id, &dskElem.counterBlock.host_vrt_dsk)) {
	SFLADD_ELEMENT(cs, &dskElem);
      }

      // include my slice of the adaptor list - and update
      // the MAC with the correct one at the same time
      SFLCounters_sample_element adaptorsElem;
      memset(&adaptorsElem, 0, sizeof(adaptorsElem));
      adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
      SFLAdaptorList myAdaptors;
      SFLAdaptor *adaptors[HSP_MAX_VIFS];
      myAdaptors.adaptors = adaptors;
      myAdaptors.capacity = HSP_MAX_VIFS;
      myAdaptors.num_adaptors = 0;
      adaptorsElem.counterBlock.adaptors = xenstat_adaptors(sp, dom_id, &myAdaptors);
      SFLADD_ELEMENT(cs, &adaptorsElem);

      
      sfl_poller_writeCountersSample(poller, cs);
    }

#endif /* XENSTAT */
  }

  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */
  
  static void configVMs(HSP *sp) {
    if(debug) myLog(LOG_INFO, "configVMs");
    HSPSFlow *sf = sp->sFlow;
    if(sf && sf->agent) {
      // mark and sweep
      // 1. mark all the current virtual pollers
      for(SFLPoller *pl = sf->agent->pollers; pl; pl = pl->nxt) {
	if(SFL_DS_CLASS(pl->dsi) == SFL_DSCLASS_LOGICAL_ENTITY) {
	  HSPVMState *state = (HSPVMState *)pl->userData;
	  state->marked = YES;
	}
      }

      // 2. create new VM pollers, or clear the mark on existing ones
#ifdef XENSTAT

      if(sp->xs_handle) {
#define DOMAIN_CHUNK_SIZE 256
	xc_domaininfo_t domaininfo[DOMAIN_CHUNK_SIZE];
	int32_t num_domains=0, new_domains=0;
	do {
	  new_domains = xc_domain_getinfolist(sp->xc_handle,
					      num_domains,
					      DOMAIN_CHUNK_SIZE,
					      domaininfo);
	  if(new_domains < 0) {
	    myLog(LOG_ERR, "xc_domain_getinfolist() failed : %s", strerror(errno));
	  }
	  else {
	    for(uint32_t i = 0; i < new_domains; i++) {
	      uint32_t domId = domaininfo[i].domain;
	      // dom0 is the hypervisor. We want the others.
	      if(domId != 0) {
		SFLDataSource_instance dsi;
		// ds_class = <virtualEntity>, ds_index = <domId>, ds_instance = 0
		SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, domId, 0);
		SFLPoller *vpoller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCountersVM);
		if(vpoller->userData) {
		  // it was already there, just clear the mark.
		  HSPVMState *state = (HSPVMState *)vpoller->userData;
		  state->marked = NO;
		}
		else {
		  // new one - tell it what to do.
		  myLog(LOG_INFO, "configVMs: new domain=%u", domId);
		  uint32_t pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
		  sfl_poller_set_sFlowCpInterval(vpoller, pollingInterval);
		  sfl_poller_set_sFlowCpReceiver(vpoller, HSP_SFLOW_RECEIVER_INDEX);
		  // hang my HSPVMState object on the datasource userData hook
		  HSPVMState *state = (HSPVMState *)malloc(sizeof(HSPVMState));
		  state->network_count = 0;
		  state->marked = NO;
		  vpoller->userData = state;
		  sp->refreshAdaptorList = YES;
		}
		// remember the index so we can access this individually later
		HSPVMState *state = (HSPVMState *)vpoller->userData;
		state->vm_index = num_domains + i;
	      }
	    }
	  }
	  num_domains += new_domains;
	} while(new_domains > 0);
      }
#endif
      
      // 3. remove any that don't exist any more
      for(SFLPoller *pl = sf->agent->pollers; pl; ) {
	SFLPoller *nextPl = pl->nxt;
	if(SFL_DS_CLASS(pl->dsi) == SFL_DSCLASS_LOGICAL_ENTITY) {
	  HSPVMState *state = (HSPVMState *)pl->userData;
	  if(state->marked) {
	    myLog(LOG_INFO, "configVMs: removing domain=%u", SFL_DS_INDEX(pl->dsi));
	    free(pl->userData);
	    pl->userData = NULL;
	    sfl_agent_removePoller(sf->agent, &pl->dsi);
	    sp->refreshAdaptorList = YES;
	  }
	}
	pl = nextPl;
      }
    }
  }


  /*_________________---------------------------__________________
    _________________       tick                __________________
    -----------------___________________________------------------
  */
  
  static void tick(HSP *sp, time_t clk) {

    // possibly refresh the list of VMs
    if(sp->refreshVMList || (clk % 60) == 0) {
      sp->refreshVMList = NO;
      configVMs(sp);
    }

    // see if a refresh of the interface list was requested
    if(sp->refreshAdaptorList) {
      sp->refreshAdaptorList = NO;
      readInterfaces(sp);
    }
  }

  /*_________________---------------------------__________________
    _________________         initAgent         __________________
    -----------------___________________________------------------
  */
  
  static int initAgent(HSP *sp)
  {
    if(debug) myLog(LOG_INFO,"creating sfl agent");

#ifdef XENSTAT
    if(sp->xc_handle == 0) {
      sp->xc_handle = xc_interface_open();
      if(sp->xc_handle <= 0) {
	myLog(LOG_ERR, "xc_interface_open() failed : %s", strerror(errno));
      }
      else {
	sp->xs_handle = xs_daemon_open_readonly();
	if(sp->xs_handle == NULL) {
	  myLog(LOG_ERR, "xs_daemon_open_readonly() failed : %s", strerror(errno));
	}
	// get the page size [ref xenstat.c]
#if defined(PAGESIZE)
	sp->page_size = PAGESIZE;
#elif defined(PAGE_SIZE)
	sp->page_size = PAGE_SIZE;
#else
	sp->page_size = sysconf(_SC_PAGE_SIZE);
	if(pgsiz < 0) {
	  myLog(LOG_ERR, "Failed to retrieve page size : %s", strerror(errno));
	  abort();
	}
#endif
      }
    }
#endif

    HSPSFlow *sf = sp->sFlow;
    
    if(sf->collectors == NULL) {
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
    sf->agent = (SFLAgent *)calloc(1, sizeof(SFLAgent));
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
    HSPCollector *collector = sf->collectors;
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
    configVMs(sp);

    return YES;
  }


  /*_________________---------------------------__________________
    _________________       freeSFlow           __________________
    -----------------___________________________------------------
  */

  static void freeSFlow(HSPSFlow *sf)
  {
    if(sf == NULL) return;
    if(sf->sFlowSettings) free(sf->sFlowSettings);
    if(sf->agent) sfl_agent_release(sf->agent);
    for(HSPCollector *coll = sf->collectors; coll; ) {
      HSPCollector *nextColl = coll->nxt;
      free(coll);
      coll = nextColl;
    }
    free(sf);
  }

  /*_________________---------------------------__________________
    _________________     setDefaults           __________________
    -----------------___________________________------------------
  */

  static void setDefaults(HSP *sp)
  {
    sp->configFile = HSP_DEFAULT_CONFIGFILE;
    sp->pidFile = HSP_DEFAULT_PIDFILE;
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-d] [-v] [-p PIDFile] [-f CONFIGFile] \n", command);
    fprintf(stderr,"\n\
             -d:  debug mode - do not fork as a daemon, and log to stderr (repeat for more details)\n\
             -v:  print version number and exit\n\
     -p PIDFile:  specify PID file (default is " HSP_DEFAULT_PIDFILE ")\n\
  -f CONFIGFile:  specify config file (default is "HSP_DEFAULT_CONFIGFILE")\n\n");
  fprintf(stderr, "=============== More Information ============================================\n");
  fprintf(stderr, "| sFlow standard        - http://www.sflow.org                              |\n");
  fprintf(stderr, "| sFlowTrend (FREE)     - http://www.inmon.com/products/sFlowTrend.php      |\n");
  fprintf(stderr, "| Traffic Sentinel      - http://www.inmon.com/products/trafficsentinel.php |\n");
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
    while ((in = getopt(argc, argv, "dvp:f:u:?h")) != -1) {
      switch(in) {
      case 'd': debug++; break;
      case 'v': printf("%s version %s\n", argv[0], HSP_VERSION); exit(EXIT_SUCCESS); break;
      case 'p': sp->pidFile = optarg; break;
      case 'f': sp->configFile = optarg; break;
      case '?':
      case 'h':
      default: instructions(*argv);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     signal_handler        __________________
    -----------------___________________________------------------
  */

  static void signal_handler(int sig) {
    switch(sig) {
    case SIGTERM:
      myLog(LOG_INFO,"Received SIGTERM");
      vsp_state = HSPSTATE_END;
      break;
    case SIGINT:
      myLog(LOG_INFO,"Received SIGINT");
      vsp_state = HSPSTATE_END;
      break;
    case SIGHUP:
      myLog(LOG_INFO,"Received SIGHUP - re-reading config");
      vsp_state = HSPSTATE_READCONFIG;
      break;
    default:
      myLog(LOG_INFO,"Received signal %d", sig);
      break;
    }
  }

  /*_________________---------------------------__________________
    _________________         main              __________________
    -----------------___________________________------------------
  */

  int main(int argc, char *argv[])
  {
    HSP sp;
    memset(&sp, 0, sizeof(sp));

    // open syslog
    openlog(HSP_DAEMON_NAME, LOG_CONS, LOG_USER);
    setlogmask(LOG_UPTO(LOG_DEBUG));

    // register signal handler
    signal(SIGTERM,signal_handler);
    signal(SIGINT,signal_handler); 
    signal(SIGHUP,signal_handler); 

    // init
    setDefaults(&sp);

    // read the command line
    processCommandLine(&sp, argc, argv);
      
    // don't run if we think another one is already running
    struct stat statBuf;
    if(stat(sp.pidFile, &statBuf) == 0) {
      myLog(LOG_ERR,"Another %s is already running. If this is an error, remove %s", argv[0], sp.pidFile);
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
	if(!(f = fopen(sp.pidFile,"w"))) {
	  myLog(LOG_ERR,"Could not open the pid file %s for writing : %s", sp.pidFile, strerror(errno));
	  exit(EXIT_FAILURE);
	}
	fprintf(f,"%"PRIu64"\n",(uint64_t)pid);
	if(fclose(f) == -1) {
	  myLog(LOG_ERR,"Could not close pid file %s : %s", sp.pidFile, strerror(errno));
	  exit(EXIT_FAILURE);
	}
	
	exit(EXIT_SUCCESS);
      }
      else {
	
	// in child
	umask(0);
	
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

    myLog(LOG_INFO, "started");
    
    // initialize the clock so we can detect second boundaries
    time_t clk = time(NULL);

    while(vsp_state != HSPSTATE_END) {
     
      switch(vsp_state) {
      case HSPSTATE_READCONFIG:
	{
	  if(sp.sFlow) {
	    // we have been asked to re-read
	    // the config e.g. on a SIGHUP
	    freeSFlow(sp.sFlow);
	    sp.sFlow = NULL;
	  }

	  if(readInterfaces(&sp)
	     && HSPReadConfigFile(&sp)
	     && initAgent(&sp)) {
	    vsp_state = HSPSTATE_RUN;

	    // Try to lock this process in memory so that we don't get
	    // swapped out. It's probably less than 100KB,  and this way
	    // we don't consume extra resources swapping in and out
	    // every 20 seconds.
	    if(mlockall(MCL_CURRENT) == -1) {
	      myLog(LOG_ERR, "mlockall(MCL_CURRENT) failed : %s", strerror(errno));
	    }

	  }
	  else{
	    exitStatus = EXIT_FAILURE;
	    vsp_state = HSPSTATE_END;
	  }
	}
	break;
	
      case HSPSTATE_RUN:
	{
	  // read some packets (or time out)
	  fd_set readfds;
	  FD_ZERO(&readfds);
	  // set the timeout so that if all is quiet we will
	  // still loop around and check for ticks/signals about
	  // 10 times per second
	  struct timeval timeout;
	  timeout.tv_sec = 0;
	  timeout.tv_usec = 100000;
	  int max_fd = 0;
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
	  if(nfds > 0) {
	    // got something?
	  }
	
	  // check for second boundaries and generate ticks for the sFlow library
	  time_t test_clk = time(NULL);
	  while(clk < test_clk) {
	    sfl_agent_tick(sp.sFlow->agent, clk);
	    // and a tick for myself too
	    tick(&sp, clk);
	    clk++;
	  }
	}
      case HSPSTATE_END:
	break;
      }
    }

    // get here if terminated by a signal
    closelog();
    myLog(LOG_INFO,"stopped");
    if(debug == 0) remove(sp.pidFile);

#ifdef XENSTAT
    if(sp.xc_handle && sp.xc_handle != -1) {
      xc_interface_close(sp.xc_handle);
      sp.xc_handle = 0;
    }
    if(sp.xs_handle) {
      xs_daemon_close(sp.xs_handle);
      sp.xs_handle = NULL;
    }
#endif

    exit(exitStatus);
  } /* main() */


#if defined(__cplusplus)
} /* extern "C" */
#endif

