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
    _________________       my_calloc             __________________
    -----------------___________________________------------------
  */
  
  void *my_calloc(size_t bytes)
  {
    void *mem = calloc(1, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "calloc() failed : %s", strerror(errno));
      // if(debug) malloc_stats();
      exit(EXIT_FAILURE);
    }
    return mem;
  }
  
  void *my_realloc(void *ptr, size_t bytes)
  {
    void *mem = realloc(ptr, bytes);
    if(mem == NULL) {
      myLog(LOG_ERR, "realloc() failed : %s", strerror(errno));
      //if(debug) malloc_stats();
      exit(EXIT_FAILURE);
    }
    return mem;
  }

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

#ifdef HSF_XEN
  static void openXenHandles(HSP *sp)
  {
    // need to do this while we still have root privileges
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
  }

  // if sp->xs_handle is not NULL then we know that sp->xc_handle is good too
  // because of the way we opened the handles in the first place.
  static int xenHandlesOK(HSP *sp) { return (sp->xs_handle != NULL); }

  static void closeXenHandles(HSP *sp)
  {
    if(sp->xc_handle && sp->xc_handle != -1) {
      xc_interface_close(sp->xc_handle);
      sp->xc_handle = 0;
    }
    if(sp->xs_handle) {
      xs_daemon_close(sp->xs_handle);
      sp->xs_handle = NULL;
    }
  }

  static int readVNodeCounters(HSP *sp, SFLHost_vrt_node_counters *vnode)
  {
    if(xenHandlesOK(sp)) {
      xc_physinfo_t physinfo = { 0 };
      if(xc_physinfo(sp->xc_handle, &physinfo) < 0) {
	myLog(LOG_ERR, "xc_physinfo() failed : %s", strerror(errno));
      }
      else {
      	vnode->mhz = (physinfo.cpu_khz / 1000);
	vnode->cpus = physinfo.nr_cpus;
	vnode->memory = ((uint64_t)physinfo.total_pages * sp->page_size);
	vnode->memory_free = ((uint64_t)physinfo.free_pages * sp->page_size);
	vnode->num_domains = sp->num_domains;
	return YES;
      }
    }
    return NO;
  }

  static SFLAdaptorList *xenstat_adaptors(HSP *sp, uint32_t dom_id, SFLAdaptorList *myAdaptors)
  {
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      uint32_t vif_domid;
      uint32_t vif_netid;
      int isVirtual = (sscanf(adaptor->deviceName, "vif%"SCNu32".%"SCNu32, &vif_domid, &vif_netid) == 2);
      if((isVirtual && dom_id == vif_domid) ||
	 (!isVirtual && dom_id == 0)) {
	// include this one (if we have room)
	if(myAdaptors->num_adaptors < HSP_MAX_VIFS) {
	  myAdaptors->adaptors[myAdaptors->num_adaptors++] = adaptor;
	  if(isVirtual) {
	    // for virtual interfaces we need to query for the MAC address
	    char macQuery[256];
	    snprintf(macQuery, sizeof(macQuery), "/local/domain/%u/device/vif/%u/mac", vif_domid, vif_netid);
	    char *macStr = xs_read(sp->xs_handle, XBT_NULL, macQuery, NULL);
	    if(macStr == NULL) {
	      myLog(LOG_ERR, "mac address query failed : %s : %s", macQuery, strerror(errno));
	    }
	    else{
	      // got it - but make sure there is a place to write it
	      if(adaptor->num_macs > 0) {
		// OK, just overwrite the 'dummy' one that was there
		if(hexToBinary((u_char *)macStr, adaptor->macs[0].mac, 6) != 6) {
		  myLog(LOG_ERR, "mac address format error in xenstore query <%s> : %s", macQuery, macStr);
		}
	      }
	      free(macStr);
	    }
	  }
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
    if(readNioCounters(&nioElem.counterBlock.host_nio, NULL)) {
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
    if(readDiskCounters(&dskElem.counterBlock.host_dsk)) {
      SFLADD_ELEMENT(cs, &dskElem);
    }

    // include the adaptor list
    SFLCounters_sample_element adaptorsElem = { 0 };
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    adaptorsElem.counterBlock.adaptors = sp->adaptorList;
    SFLADD_ELEMENT(cs, &adaptorsElem);

#ifdef HSF_XEN
    // replace the adaptorList with a filtered version of the same
      SFLAdaptorList myAdaptors;
      SFLAdaptor *adaptors[HSP_MAX_VIFS];
      myAdaptors.adaptors = adaptors;
      myAdaptors.capacity = HSP_MAX_VIFS;
      myAdaptors.num_adaptors = 0;
      adaptorsElem.counterBlock.adaptors = xenstat_adaptors(sp, 0, &myAdaptors);

    // hypervisor node stats
    SFLCounters_sample_element vnodeElem = { 0 };
    vnodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
    if(readVNodeCounters(sp, &vnodeElem.counterBlock.host_vrt_node)) {
      SFLADD_ELEMENT(cs, &vnodeElem);
    }
#endif

    sfl_poller_writeCountersSample(poller, cs);
  }

#ifdef HSF_XEN

#define HSP_MAX_PATHLEN 256
#define XEN_SYSFS_VBD_PATH "/sys/devices/xen-backend"

  static int64_t xen_vbd_counter(char *vbd_type, uint32_t dom_id, uint32_t vbd_dev, char *counter)
  {
    int64_t ctr64 = 0;
    char path[HSP_MAX_PATHLEN];
    snprintf(path, HSP_MAX_PATHLEN, XEN_SYSFS_VBD_PATH "/%s-%u-%u/statistics/%s",
	     vbd_type,
	     dom_id,
	     vbd_dev,
	     counter);
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
	  //dsk->capacity $$$
	  //dsk->allocation $$$
	  //dsk->available $$$
	  if(debug > 1) myLog(LOG_INFO, "reading VBD %s for dom_id %u", dp->d_name, dom_id); 
	  dsk->rd_req += xen_vbd_counter(vbd_type, dom_id, vbd_dev, "rd_req");
	  dsk->rd_bytes += (xen_vbd_counter(vbd_type, dom_id, vbd_dev, "rd_sect") * HSP_SECTOR_BYTES);
	  dsk->wr_req += xen_vbd_counter(vbd_type, dom_id, vbd_dev, "wr_req");
	  dsk->wr_bytes += (xen_vbd_counter(vbd_type, dom_id, vbd_dev, "wr_sect") * HSP_SECTOR_BYTES);
	}
      }
    }
    closedir(sysfsvbd);
    return YES;
  }
  
#endif

  void agentCB_getCountersVM(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
#ifdef HSF_XEN
    assert(poller->magic);
    HSP *sp = (HSP *)poller->magic;
    HSPVMState *state = (HSPVMState *)poller->userData;

    if(state && xenHandlesOK(sp)) {
      
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
      SFLCounters_sample_element hidElem = { 0 };
      memset(&hidElem, 0, sizeof(hidElem));
      hidElem.tag = SFLCOUNTERS_HOST_HID;
      char query[255];
      char hname[255];
      snprintf(query, sizeof(query), "/local/domain/%u/name", dom_id);
      char *xshname = (char *)xs_read(sp->xs_handle, XBT_NULL, query, NULL);
      if(xshname) {
	// copy the name out here so we can free it straight away
	strncpy(hname, xshname, 255);
	free(xshname);
	hidElem.counterBlock.host_hid.hostname.str = hname;
	hidElem.counterBlock.host_hid.hostname.len = strlen(hname);
	memcpy(hidElem.counterBlock.host_hid.uuid, &domaininfo.handle, 16);
	hidElem.counterBlock.host_hid.machine_type = SFLMT_unknown;
	hidElem.counterBlock.host_hid.os_name = SFLOS_unknown;
	//hidElem.counterBlock.host_hid.os_release.str = NULL;
	//hidElem.counterBlock.host_hid.os_release.len = 0;
	SFLADD_ELEMENT(cs, &hidElem);
      }
      
      // host parent
      SFLCounters_sample_element parElem = { 0 };
      parElem.tag = SFLCOUNTERS_HOST_PAR;
      parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
      parElem.counterBlock.host_par.dsIndex = 1;
      SFLADD_ELEMENT(cs, &parElem);

      // VM Net I/O
      SFLCounters_sample_element nioElem = { 0 };
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
      SFLCounters_sample_element cpuElem = { 0 };
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
      uint32_t st = domaininfo.flags;
      // first 8 bits (b7-b0) are a mask of flags (see tools/libxc/xen/domctl.h)
      // next 8 bits (b15-b8) indentify the CPU to which the domain is bound
      // next 8 bits (b23-b16) indentify the the user-supplied shutdown code
      cpuElem.counterBlock.host_vrt_cpu.state = SFL_VIR_DOMAIN_NOSTATE;
      if(st & XEN_DOMINF_shutdown) {
	cpuElem.counterBlock.host_vrt_cpu.state = SFL_VIR_DOMAIN_SHUTDOWN;
	if(((st >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask) == SHUTDOWN_crash) {
	  cpuElem.counterBlock.host_vrt_cpu.state = SFL_VIR_DOMAIN_CRASHED;
	}
      }
      else if(st & XEN_DOMINF_paused) cpuElem.counterBlock.host_vrt_cpu.state = SFL_VIR_DOMAIN_PAUSED;
      else if(st & XEN_DOMINF_blocked) cpuElem.counterBlock.host_vrt_cpu.state = SFL_VIR_DOMAIN_BLOCKED;
      else if(st & XEN_DOMINF_running) cpuElem.counterBlock.host_vrt_cpu.state = SFL_VIR_DOMAIN_RUNNING;
      // SFL_VIR_DOMAIN_SHUTOFF ?
      // other domaininfo flags include:
      // XEN_DOMINF_dying      : not sure when this is set -- perhaps always :)
      // XEN_DOMINF_hvm_guest  : as opposed to a PV guest
      // XEN_DOMINF_debugged   :

      cpuElem.counterBlock.host_vrt_cpu.cpuTime = vcpu_ns;
      cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = domaininfo.max_vcpu_id + 1;
      SFLADD_ELEMENT(cs, &cpuElem);

      // VM memory counters [ref xenstat.c]
      SFLCounters_sample_element memElem = { 0 };
      memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
      memElem.counterBlock.host_vrt_mem.memory = domaininfo.tot_pages * sp->page_size;
      memElem.counterBlock.host_vrt_mem.maxMemory = (domaininfo.max_pages == UINT_MAX) ? -1 : (domaininfo.max_pages * sp->page_size);
      SFLADD_ELEMENT(cs, &memElem);

      // VM disk I/O counters
      SFLCounters_sample_element dskElem = { 0 };
      dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
      if(xenstat_dsk(sp, dom_id, &dskElem.counterBlock.host_vrt_dsk)) {
	SFLADD_ELEMENT(cs, &dskElem);
      }

      // include my slice of the adaptor list - and update
      // the MAC with the correct one at the same time
      SFLCounters_sample_element adaptorsElem = { 0 };
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

#endif /* HSF_XEN */
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
#ifdef HSF_XEN

      if(xenHandlesOK(sp)) {
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
		  HSPVMState *state = (HSPVMState *)my_calloc(sizeof(HSPVMState));
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
	// remember the number of domains we found
	sp->num_domains = num_domains;
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
    configVMs(sp);

    return YES;
  }

  /*_________________---------------------------__________________
    _________________     setDefaults           __________________
    -----------------___________________________------------------
  */

  static void setDefaults(HSP *sp)
  {
    sp->configFile = HSP_DEFAULT_CONFIGFILE;
    sp->pidFile = HSP_DEFAULT_PIDFILE;
    sp->DNSSD_startDelay = HSP_DEFAULT_DNSSD_STARTDELAY;
    sp->DNSSD_retryDelay = HSP_DEFAULT_DNSSD_RETRYDELAY;
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-d] [-v] [-p PIDFile] [-f CONFIGFile] [-u UUID] \n", command);
    fprintf(stderr,"\n\
             -d:  debug mode - do not fork as a daemon, and log to stderr (repeat for more details)\n\
             -v:  print version number and exit\n\
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
    while ((in = getopt(argc, argv, "dvp:f:u:?h")) != -1) {
      switch(in) {
      case 'd': debug++; break;
      case 'v': printf("%s version %s\n", argv[0], HSP_VERSION); exit(EXIT_SUCCESS); break;
      case 'p': sp->pidFile = optarg; break;
      case 'f': sp->configFile = optarg; break;
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

  static void signal_handler(int sig) {
    HSP *sp = &HSPSamplingProbe;
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
      myLog(LOG_INFO,"Received signal %d", sig);
      break;
    }
  }

  /*_________________---------------------------__________________
    _________________     my_usleep             __________________
    -----------------___________________________------------------
  */
  
  void my_usleep(uint32_t microseconds) {
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = microseconds;
    int max_fd = 0;
    int nfds = select(max_fd + 1,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      (fd_set *)NULL,
		      &timeout);
    // may return prematurely if a signal was caught, in which case nfds will be
    // -1 and errno will be set to EINTR.  If we get any other error, abort.
    if(nfds < 0 && errno != EINTR) {
      myLog(LOG_ERR, "select() returned %d : %s", nfds, strerror(errno));
      exit(EXIT_FAILURE);
    }
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
    }
    else if(strcmp(keyBuf, "txtvers") == 0) {
    }
    else if(strcmp(keyBuf, "polling") == 0) {
      st->pollingInterval = strtol(valBuf, NULL, 0);
      if(st->pollingInterval < 1 || st->pollingInterval > 300) {
	// $$$ what if this fails?
      }
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
      my_usleep(1000000);
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
	sf->sFlowSettings_dnsSD = newSFlowSettings();
	// pick up default polling interval from config file
	sf->sFlowSettings_dnsSD->pollingInterval = sf->sFlowSettings_file->pollingInterval;
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
	    sf->sFlowSettings = NULL;
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
	    sf->sFlowSettings = sf->sFlowSettings_dnsSD;
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

  static void drop_privileges(int requestMemLockBytes) {
    if(getuid() == 0) {

      if(requestMemLockBytes) {
	// Request to lock this process in memory so that we don't get
	// swapped out. It's probably less than 100KB,  and this way
	// we don't consume extra resources swapping in and out
	// every 20 seconds.  The default limit is just 32K on most
	// systems,  so for this to be useful we have to increase it
	// somewhat first.
	struct rlimit rlim = {0};
#ifdef RLIMIT_MEMLOCK
	rlim.rlim_cur = rlim.rlim_max = requestMemLockBytes;
	if(setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
	  myLog(LOG_ERR, "setrlimit(RLIMIT_MEMLOCK, %d) failed : %s", requestMemLockBytes, strerror(errno));
	}
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
	rlim.rlim_cur = rlim.rlim_max = requestMemLockBytes;
	if(setrlimit(RLIMIT_DATA, &rlim) != 0) {
	  myLog(LOG_ERR, "setrlimit(RLIMIT_DATA, %d) failed : %s", requestMemLockBytes, strerror(errno));
	}
#endif

	// consider overriding other limits to make sure we fail quickly if anything is wrong
	// RLIMIT_STACK
	// RLIMIT_CORE
	// RLIMIT_RSS
	// RLIMIT_NOFILE
	// RLIMIT_AS
	// RLIMIT_LOCKS
      }
      
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
      /*       if(initgroups("nobody", nobody->pw_gid) != 0) { */
      /* 	myLog(LOG_ERR, "drop_privileges: initgroups failed : %s", strerror(errno)); */
      /* 	exit(EXIT_FAILURE); */
      /*       } */
      /*       endpwent(); */
      /*       endgrent(); */
      if(setuid(nobody->pw_uid) != 0) {
	myLog(LOG_ERR, "drop_privileges: setuid(%d) failed : %s", nobody->pw_uid, strerror(errno));
	exit(EXIT_FAILURE);
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
    signal(SIGTERM,signal_handler);
    signal(SIGINT,signal_handler); 

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
	umask(0);

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
    
#ifdef HSF_XEN
    // open Xen handles while we still have root privileges
    openXenHandles(sp);
#endif

    // don't need to be root any more - we held on to root privileges
    // to make sure we could write the pid file (and possibly open the
    // Xen handles,  but from now on we don't want the responsibility...
    drop_privileges(HSP_RLIMIT_MEMLOCK);

    myLog(LOG_INFO, "started");
    
    // initialize the clock so we can detect second boundaries
    time_t clk = time(NULL);

    // semaphore to protect config shared with DNSSD thread
    sp->config_mut = (pthread_mutex_t *)my_calloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(sp->config_mut, NULL);
    
    setState(sp, HSPSTATE_READCONFIG);

    while(sp->state != HSPSTATE_END) {
      
      switch(sp->state) {
	
      case HSPSTATE_READCONFIG:
	{
	  if(readInterfaces(sp)
	     && HSPReadConfigFile(sp)) {
	    
	    { // we must have an agentIP, so we can use
	      // it to seed the random number generator
	      SFLAddress *agentIP = &sp->sFlow->agentIP;
	      uint32_t seed;
	      if(agentIP->type == SFLADDRESSTYPE_IP_V4) seed = agentIP->address.ip_v4.addr;
	      else memcpy(agentIP->address.ip_v6.addr + 12, &seed, 4);
	      sfl_random_init(seed);
	    }
	    
	    if(sp->DNSSD) {
	      // launch dnsSD thread.  It will now be responsible for
	      // the sFlowSettings,  and the current thread will loop
	      // in the HSPSTATE_WAITCONFIG state until that pointer
	      // has been set (sp->sFlow.sFlowSettings)
	      sp->DNSSD_thread = my_calloc(sizeof(pthread_t));
	      if(pthread_create(sp->DNSSD_thread, NULL, runDNSSD, sp) != 0) {
		myLog(LOG_ERR, "pthread_create() failed\n");
		exit(EXIT_FAILURE);
	      }
	    }
	    else {
	      // just use the config from the file
	      sp->sFlow->sFlowSettings = sp->sFlow->sFlowSettings_file;
	    }
	    setState(sp, HSPSTATE_WAITCONFIG);
	  }
	  else{
	    exitStatus = EXIT_FAILURE;
	    setState(sp, HSPSTATE_END);
	  }
	  
	}
	break;
	
      case HSPSTATE_WAITCONFIG:
	SEMLOCK_DO(sp->config_mut) {
	  if(sp->sFlow->sFlowSettings) {
	    // we have a config - proceed
	    if(initAgent(sp)) {
	      if(debug) {
		if(debug) myLog(LOG_INFO, "initAgent suceeded");
		// print some stats to help us size HSP_RLIMIT_MEMLOCK etc.
		// malloc_stats();
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
	  if((test_clk < clk) || (test_clk - clk) > HSP_MAX_TICKS) {
	    // avoid a busy-loop of ticks
	    myLog(LOG_INFO, "time jump detected");
	    clk = test_clk - 1;
	  }
	  while(clk < test_clk) {

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
		
		// send a tick to the sFlow agent
		sfl_agent_tick(sp->sFlow->agent, clk);
		// and a tick for myself too
		tick(sp, clk);
	      }
	    } // semaphore
	    
	    clk++;
	  }
	}
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
    
#ifdef HSF_XEN
    closeXenHandles(sp);
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

