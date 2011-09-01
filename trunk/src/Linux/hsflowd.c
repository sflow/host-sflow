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

#ifdef XENCTRL_HAS_XC_INTERFACE
#define HSF_XENCTRL_INTERFACE_OPEN() xc_interface_open(NULL /*logger*/, NULL/*dombuild_logger*/, XC_OPENFLAG_NON_REENTRANT);
#define HSF_XENCTRL_HANDLE_OK(h) ((h) != NULL)
#else
#define HSF_XENCTRL_INTERFACE_OPEN() xc_interface_open()
#define HSF_XENCTRL_HANDLE_OK(h) ((h) && (h) != -1)
#endif

  static void openXenHandles(HSP *sp)
  {
    // need to do this while we still have root privileges
    if(sp->xc_handle == 0) {
      sp->xc_handle = HSF_XENCTRL_INTERFACE_OPEN();
      if(!HSF_XENCTRL_HANDLE_OK(sp->xc_handle)) {
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
        if(sp->page_size <= 0) {
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
    if(HSF_XENCTRL_HANDLE_OK(sp->xc_handle)) {
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
    if(debug > 3) myLog(LOG_INFO, "xenstat_adaptors(): looking for vif%"PRIu32".<netid>", dom_id);
    for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      uint32_t vif_domid=0;
      uint32_t vif_netid=0;
      int isVirtual = (sscanf(adaptor->deviceName, "vif%"SCNu32".%"SCNu32, &vif_domid, &vif_netid) == 2);
      if(debug > 3) myLog(LOG_INFO, "- xenstat_adaptors(): found %s (virtual=%s, domid=%"PRIu32", netid=%"PRIu32")",
			  adaptor->deviceName,
			  isVirtual ? "YES" : "NO",
			  vif_domid,
			  vif_netid);
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
	      myLog(LOG_ERR, "xenstat_adaptors(): mac address query failed : %s : %s", macQuery, strerror(errno));
	    }
	    else{
	      if(debug > 3) myLog(LOG_INFO, "- xenstat_adaptors(): got MAC from xenstore: %s", macStr);
	      // got it - but make sure there is a place to write it
	      if(adaptor->num_macs > 0) {
		// OK, just overwrite the 'dummy' one that was there
		if(hexToBinary((u_char *)macStr, adaptor->macs[0].mac, 6) != 6) {
		  myLog(LOG_ERR, "mac address format error in xenstore query <%s> : %s", macQuery, macStr);
		}
	      }
	      free(macStr); // allocated by xs_read()
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

  static int64_t xen_vbd_counter(uint32_t dom_id, char *vbd_dev, char *counter, int usec)
  {
    int64_t ctr64 = 0;
    char ctrspec[HSP_MAX_PATHLEN];
    snprintf(ctrspec, HSP_MAX_PATHLEN, "%u-%s/statistics/%s",
	     dom_id,
	     vbd_dev,
	     counter);
    char path[HSP_MAX_PATHLEN];
    FILE *file = NULL;
    // try vbd first,  then tap
    snprintf(path, HSP_MAX_PATHLEN, XEN_SYSFS_VBD_PATH "/vbd-%s", ctrspec);
    if((file = fopen(path, "r")) == NULL) {
      snprintf(path, HSP_MAX_PATHLEN, XEN_SYSFS_VBD_PATH "/tap-%s", ctrspec);
      file = fopen(path, "r");
    }
    
    if(file) {
      if(usec) {
	uint64_t requests, avg_usecs, max_usecs;
	if(fscanf(file, "requests: %"SCNi64", avg usecs: %"SCNi64", max usecs: %"SCNi64,
		  &requests,
		  &avg_usecs,
		  &max_usecs) == 3) {
	  // we want the total time in mS
	  ctr64 = (requests * avg_usecs) / 1000;
	}
      }
      else {
	fscanf(file, "%"SCNi64, &ctr64);
      }
      fclose(file);
    }
    else {
      if(debug) myLog(LOG_INFO, "xen_vbd_counter: <%s> not found ", path);
    }
    if(debug) myLog(LOG_INFO, "xen_vbd_counter: <%s> = %"PRIu64, path, ctr64);
    return ctr64;
  }
  
  static int xen_collect_block_devices(HSP *sp, HSPVMState *state)
  {
    DIR *sysfsvbd = opendir(XEN_SYSFS_VBD_PATH);
    if(sysfsvbd == NULL) {
      myLog(LOG_ERR, "opendir %s failed : %s", XEN_SYSFS_VBD_PATH, strerror(errno));
      return 0;
    }
    int found = 0;
    char scratch[sizeof(struct dirent) + _POSIX_PATH_MAX];
    struct dirent *dp = NULL;
    for(;;) {
      readdir_r(sysfsvbd, (struct dirent *)scratch, &dp);
      if(dp == NULL) break;
      uint32_t vbd_dom_id;
      char vbd_type[256];
      char vbd_dev[256];
      if(sscanf(dp->d_name, "%3s-%u-%s", vbd_type, &vbd_dom_id, vbd_dev) == 3) {
	if(vbd_dom_id == state->domId
	   && (my_strequal(vbd_type, "vbd") || my_strequal(vbd_type, "tap"))) {
	  strArrayAdd(state->volumes, vbd_dev);
	  found++;
	}
      }
    }
    closedir(sysfsvbd);
    return found;
  }

  static int xenstat_dsk(HSP *sp, HSPVMState *state, SFLHost_vrt_dsk_counters *dsk)
  {
    for(uint32_t i = 0; i < strArrayN(state->volumes); i++) {
      char *vbd_dev = strArrayAt(state->volumes, i);
      if(debug > 1) myLog(LOG_INFO, "reading VBD %s for dom_id %u", vbd_dev, state->domId); 
      dsk->rd_req += xen_vbd_counter(state->domId, vbd_dev, "rd_req", NO);
      dsk->rd_bytes += (xen_vbd_counter(state->domId, vbd_dev, "rd_sect", NO) * HSP_SECTOR_BYTES);
      dsk->rd_bytes += (xen_vbd_counter(state->domId, vbd_dev, "rd_sect", NO) * HSP_SECTOR_BYTES);
      dsk->wr_req += xen_vbd_counter(state->domId, vbd_dev, "wr_req", NO);
      dsk->wr_bytes += (xen_vbd_counter(state->domId, vbd_dev, "wr_sect", NO) * HSP_SECTOR_BYTES);
      dsk->errs += xen_vbd_counter(state->domId, vbd_dev, "oo_req", NO);
      //dsk->capacity $$$
      //dsk->allocation $$$
      //dsk->available $$$
    }
    return YES;
  }
  
#endif

  void agentCB_getCountersVM(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSPVMState *state = (HSPVMState *)poller->userData;
    if(state == NULL) return;

#if defined(HSF_XEN) || defined(HSF_VRT)

    HSP *sp = (HSP *)poller->magic;

#ifdef HSF_XEN
    if(xenHandlesOK(sp)) {

      xc_domaininfo_t domaininfo;
      // it seems that xc_domain_getinfolist takes the domId after all
      // so state->vm_index is not actually needed any more
      // int32_t n = xc_domain_getinfolist(sp->xc_handle, state->vm_index, 1, &domaininfo);
      int32_t n = xc_domain_getinfolist(sp->xc_handle, state->domId, 1, &domaininfo);
      if(n < 0 || domaininfo.domain != state->domId) {
	// Assume something changed under our feet.
	// Request a reload of the VM information and bail.
	// We'll try again next time.
	myLog(LOG_INFO, "request for vm_index %u (dom_id=%u) returned %d (with dom_id=%u)",
	      state->vm_index,
	      state->domId,
	      n,
	      domaininfo.domain);
	sp->refreshVMList = YES;
	return;
      }
      
      // host ID
      SFLCounters_sample_element hidElem = { 0 };
      hidElem.tag = SFLCOUNTERS_HOST_HID;
      char query[255];
      char hname[255];
      snprintf(query, sizeof(query), "/local/domain/%u/name", state->domId);
      char *xshname = (char *)xs_read(sp->xs_handle, XBT_NULL, query, NULL);
      if(xshname) {
	// copy the name out here so we can free it straight away
	strncpy(hname, xshname, 255);
	free(xshname); // allocated by xs_read
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
      parElem.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
      SFLADD_ELEMENT(cs, &parElem);

      // VM Net I/O
      SFLCounters_sample_element nioElem = { 0 };
      nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
      char devFilter[20];
      snprintf(devFilter, 20, "vif%u.", state->domId);
      uint32_t network_count = readNioCounters(sp, &nioElem.counterBlock.host_vrt_nio, devFilter, NULL);
      if(state->network_count != network_count) {
	// request a refresh if the number of VIFs changed. Not a perfect test
	// (e.g. if one was removed and another was added at the same time then
	// we would miss it). I guess we should keep the whole list of network ids,
	// or just force a refresh every few minutes?
	myLog(LOG_INFO, "vif count changed from %u to %u (dom_id=%u). Setting refreshAdaptorList=YES",
	      state->network_count,
	      network_count,
	      state->domId);
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
	if(xc_vcpu_getinfo(sp->xc_handle, state->domId, c, &info) != 0) {
	  // error or domain is in transition.  Just bail.
	  myLog(LOG_INFO, "vcpu list in transition (dom_id=%u)", state->domId);
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

      cpuElem.counterBlock.host_vrt_cpu.cpuTime = (vcpu_ns / 1000000);
      cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = domaininfo.max_vcpu_id + 1;
      SFLADD_ELEMENT(cs, &cpuElem);

      // VM memory counters [ref xenstat.c]
      SFLCounters_sample_element memElem = { 0 };
      memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;

      if(debug) myLog(LOG_INFO, "vm domid=%u, dsIndex=%u, vm_index=%u, tot_pages=%u",
		      state->domId,
		      SFL_DS_INDEX(poller->dsi),
		      state->vm_index,
		      domaininfo.tot_pages);

		      
      memElem.counterBlock.host_vrt_mem.memory = domaininfo.tot_pages * sp->page_size;
      memElem.counterBlock.host_vrt_mem.maxMemory = (domaininfo.max_pages == UINT_MAX) ? -1 : (domaininfo.max_pages * sp->page_size);
      SFLADD_ELEMENT(cs, &memElem);

      // VM disk I/O counters
      SFLCounters_sample_element dskElem = { 0 };
      dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
      if(xenstat_dsk(sp, state, &dskElem.counterBlock.host_vrt_dsk)) {
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
      adaptorsElem.counterBlock.adaptors = xenstat_adaptors(sp, state->domId, &myAdaptors);
      SFLADD_ELEMENT(cs, &adaptorsElem);

      
      sfl_poller_writeCountersSample(poller, cs);
    }

#endif /* HSF_XEN */
#ifdef HSF_VRT
    if(sp->virConn) {
      virDomainPtr domainPtr = virDomainLookupByID(sp->virConn, state->domId);
      if(domainPtr == NULL) {
	sp->refreshVMList = YES;
      }
      else {
	// host ID
	SFLCounters_sample_element hidElem = { 0 };
	hidElem.tag = SFLCOUNTERS_HOST_HID;
	const char *hname = virDomainGetName(domainPtr); // no need to free this one
	if(hname) {
	  // copy the name out here so we can free it straight away
	  hidElem.counterBlock.host_hid.hostname.str = (char *)hname;
	  hidElem.counterBlock.host_hid.hostname.len = strlen(hname);
	  virDomainGetUUID(domainPtr, hidElem.counterBlock.host_hid.uuid);
	
	  // char *osType = virDomainGetOSType(domainPtr); $$$
	  hidElem.counterBlock.host_hid.machine_type = SFLMT_unknown;//$$$
	  hidElem.counterBlock.host_hid.os_name = SFLOS_unknown;//$$$
	  //hidElem.counterBlock.host_hid.os_release.str = NULL;
	  //hidElem.counterBlock.host_hid.os_release.len = 0;
	  SFLADD_ELEMENT(cs, &hidElem);
	}
      
	// host parent
	SFLCounters_sample_element parElem = { 0 };
	parElem.tag = SFLCOUNTERS_HOST_PAR;
	parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
	parElem.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
	SFLADD_ELEMENT(cs, &parElem);

	// VM Net I/O
	SFLCounters_sample_element nioElem = { 0 };
	nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
	// since we are already maintaining the accumulated network counters (and handling issues like 32-bit
	// rollover) then we can just use the same mechanism again.  On a non-linux platform we may
	// want to take advantage of the libvirt call to get the counters (it takes the domain id and the
	// device name as parameters so you have to call it multiple times),  but even then we would
	// probably do that down inside the readNioCounters() fn in case there is work to do on the
	// accumulation and rollover-detection.
	readNioCounters(sp, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio, NULL, state->interfaces);
	SFLADD_ELEMENT(cs, &nioElem);
      
	// VM cpu counters [ref xenstat.c]
	SFLCounters_sample_element cpuElem = { 0 };
	cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
	virDomainInfo domainInfo;
	int domainInfoOK = NO;
	if(virDomainGetInfo(domainPtr, &domainInfo) != 0) {
	  myLog(LOG_ERR, "virDomainGetInfo() failed");
	}
	else {
	  domainInfoOK = YES;
	  // enum virDomainState really is the same as enum SFLVirDomainState
	  cpuElem.counterBlock.host_vrt_cpu.state = domainInfo.state;
	  cpuElem.counterBlock.host_vrt_cpu.cpuTime = (domainInfo.cpuTime / 1000000);
	  cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = domainInfo.nrVirtCpu;
	  SFLADD_ELEMENT(cs, &cpuElem);
	}
      
	SFLCounters_sample_element memElem = { 0 };
	memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
	if(domainInfoOK) {
	  memElem.counterBlock.host_vrt_mem.memory = domainInfo.memory * 1024;
	  memElem.counterBlock.host_vrt_mem.maxMemory = (domainInfo.maxMem == UINT_MAX) ? -1 : (domainInfo.maxMem * 1024);
	  SFLADD_ELEMENT(cs, &memElem);
	}

    
	// VM disk I/O counters
	SFLCounters_sample_element dskElem = { 0 };
	dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
	for(int i = strArrayN(state->disks); --i >= 0; ) {
	  /* state->volumes and state->disks are populated in lockstep
	   * so they always have the same number of elements
	   */
	  char *volPath = strArrayAt(state->volumes, i);
	  char *dskPath = strArrayAt(state->disks, i);
	  int gotVolInfo = NO;

#ifndef HSP_VRT_USE_DISKPATH
	  /* define HSP_VRT_USE_DISKPATH if you want to bypass this virStorageVolGetInfo
	   *  approach and just use virDomainGetBlockInfo instead.
	   */
	  virStorageVolPtr volPtr = virStorageVolLookupByPath(sp->virConn, volPath);
	  if(volPtr == NULL) {
	    myLog(LOG_ERR, "virStorageLookupByPath(%s) failed", volPath);
	  }
	  else {
	    virStorageVolInfo volInfo;
	    if(virStorageVolGetInfo(volPtr, &volInfo) != 0) {
	      myLog(LOG_ERR, "virStorageVolGetInfo(%s) failed", volPath);
	    }
	    else {
	      gotVolInfo = YES;
	      dskElem.counterBlock.host_vrt_dsk.capacity += volInfo.capacity;
	      dskElem.counterBlock.host_vrt_dsk.allocation += volInfo.allocation;
	      dskElem.counterBlock.host_vrt_dsk.available += (volInfo.capacity - volInfo.allocation);
	    }
	  }
#endif

#if (LIBVIR_VERSION_NUMBER >= 8001)
	  if(gotVolInfo == NO) {
	    /* try appealing directly to the disk path instead */
	    /* this call was only added in April 2010 (version 0.8.1).
	     * See http://markmail.org/message/mjafgt47f5e5zzfc
	     */
	    virDomainBlockInfo blkInfo;
	    if(virDomainGetBlockInfo(domainPtr, volPath, &blkInfo, 0) == -1) {
	      myLog(LOG_ERR, "virDomainGetBlockInfo(%s) failed", dskPath);
	    }
	    else {
	      dskElem.counterBlock.host_vrt_dsk.capacity += blkInfo.capacity;
	      dskElem.counterBlock.host_vrt_dsk.allocation += blkInfo.allocation;
	      dskElem.counterBlock.host_vrt_dsk.available += (blkInfo.capacity - blkInfo.allocation);
	      // don't need blkInfo.physical
	    }
	  }
#endif
	  /* we get reads, writes and errors from a different call */
	  virDomainBlockStatsStruct blkStats;
	  if(virDomainBlockStats(domainPtr, dskPath, &blkStats, sizeof(blkStats)) != -1) {
	    if(blkStats.rd_req != -1) dskElem.counterBlock.host_vrt_dsk.rd_req += blkStats.rd_req;
	    if(blkStats.rd_bytes != -1) dskElem.counterBlock.host_vrt_dsk.rd_bytes += blkStats.rd_bytes;
	    if(blkStats.wr_req != -1) dskElem.counterBlock.host_vrt_dsk.wr_req += blkStats.wr_req;
	    if(blkStats.wr_bytes != -1) dskElem.counterBlock.host_vrt_dsk.wr_bytes += blkStats.wr_bytes;
	    if(blkStats.errs != -1) dskElem.counterBlock.host_vrt_dsk.errs += blkStats.errs;
	  }
	}
	SFLADD_ELEMENT(cs, &dskElem);
      
	// include my slice of the adaptor list
	SFLCounters_sample_element adaptorsElem = { 0 };
	adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
	adaptorsElem.counterBlock.adaptors = state->interfaces;
	SFLADD_ELEMENT(cs, &adaptorsElem);
      
      
	sfl_poller_writeCountersSample(poller, cs);
      
	virDomainFree(domainPtr);
      }
    }
#endif /* HSF_VRT */
#endif /* HSF_XEN | HSF_VRT */
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
    _________________    domain_xml_node        __________________
    -----------------___________________________------------------
  */

#ifdef HSF_VRT

  static int domain_xml_path_equal(xmlNode *node, char *nodeName, ...) {
    if(node == NULL
       || node->name == NULL
       || node->type != XML_ELEMENT_NODE
       || !my_strequal(nodeName, (char *)node->name)) {
      return NO;
    }
    int match = YES;
    va_list names;
    va_start(names, nodeName);
    xmlNode *parentNode = node->parent;
    char *parentName;
    while((parentName = va_arg(names, char *)) != NULL) {
      if(parentNode == NULL
	 || parentNode->name == NULL
	 || !my_strequal(parentName, (char *)parentNode->name)) {
	match = NO;
	break;
      }
      parentNode = parentNode->parent;
    }
    va_end(names);
    return match;
  }

  static char *get_xml_attr(xmlNode *node, char *attrName) {
    for(xmlAttr *attr = node->properties; attr; attr = attr->next) {
      if(attr->name) {
	if(debug) myLog(LOG_INFO, "attribute %s", attr->name);
	if(attr->children && !strcmp((char *)attr->name, attrName)) {
	  return (char *)attr->children->content;
	}
      }
    }
    return NULL;
  }
    
  void domain_xml_interface(xmlNode *node, char **ifname, char **ifmac) {
    for(xmlNode *n = node; n; n = n->next) {
      if(domain_xml_path_equal(n, "target", "interface", "devices", NULL)) {
	char *dev = get_xml_attr(n, "dev");
	if(dev) {
	  if(debug) myLog(LOG_INFO, "interface.dev=%s", dev);
	  if(ifname) *ifname = dev;
	}
      }
      else if(domain_xml_path_equal(n, "mac", "interface", "devices", NULL)) {
	char *addr = get_xml_attr(n, "address");
	if(debug) myLog(LOG_INFO, "interface.mac=%s", addr);
	if(ifmac) *ifmac = addr;
      }
    }
    if(node->children) domain_xml_interface(node->children, ifname, ifmac);
  }
    
  void domain_xml_disk(xmlNode *node, char **disk_path, char **disk_dev) {
    for(xmlNode *n = node; n; n = n->next) {
      if(domain_xml_path_equal(n, "source", "disk", "devices", NULL)) {
	char *path = get_xml_attr(n, "file");
	if(path) {
	  if(debug) myLog(LOG_INFO, "disk.file=%s", path);
	  if(disk_path) *disk_path = path;
	}
      }
      else if(domain_xml_path_equal(n, "target", "disk", "devices", NULL)) {
	char *dev = get_xml_attr(n, "dev");
	if(debug) myLog(LOG_INFO, "disk.dev=%s", dev);
	if(disk_dev) *disk_dev = dev;
      }
      else if(domain_xml_path_equal(n, "readonly", "disk", "devices", NULL)) {
	if(debug) myLog(LOG_INFO, "ignoring readonly device");
	*disk_path = NULL;
	*disk_dev = NULL;
	return;
      }
    }
    if(node->children) domain_xml_disk(node->children, disk_path, disk_dev);
  }
  
  void domain_xml_node(xmlNode *node, HSPVMState *state) {
    for(xmlNode *n = node; n; n = n->next) {
      if(domain_xml_path_equal(n, "interface", "devices", "domain", NULL)) {
	char *ifname=NULL,*ifmac=NULL;
	domain_xml_interface(n, &ifname, &ifmac);
	if(ifname && ifmac) {
	  u_char macBytes[6];
	  if(hexToBinary((u_char *)ifmac, macBytes, 6) == 6) {
	    SFLAdaptor *ad = adaptorListAdd(state->interfaces, ifname, macBytes, 0);
	    // clear the mark so we don't free it
	    ad->marked = NO;
	  }
	}
      }
      else if(domain_xml_path_equal(n, "disk", "devices", "domain", NULL)) {
	// need both a path and a dev before we will accept it
	char *disk_path=NULL,*disk_dev=NULL;
	domain_xml_disk(n, &disk_path, &disk_dev);
	if(disk_path && disk_dev) {
	  strArrayAdd(state->volumes, (char *)disk_path);
	  strArrayAdd(state->disks, (char *)disk_dev);
	}
      }
      else if(n->children) domain_xml_node(n->children, state);
    }
  }

#endif /* HSF_VRT */
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
	  state->vm_index = 0;
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
	      // dom0 is the hypervisor. We used to ignore it, but actually it should be included.
	      if(debug) {
		// may need to ignore any that are not marked as "running" here
		myLog(LOG_INFO, "ConfigVMs(): domId=%u flags=0x%x tot_pages=%"PRIu64" max_pages=%"PRIu64" shared_info_frame=%"PRIu64" cpu_time=%"PRIu64" nr_online_vcpus=%u max_vcpu_id=%u ssidref=%u handle=%x",
		      domId,
		      domaininfo[i].flags,
		      domaininfo[i].tot_pages,
		      domaininfo[i].max_pages,
		      domaininfo[i].shared_info_frame,
		      domaininfo[i].cpu_time,
		      domaininfo[i].nr_online_vcpus,
		      domaininfo[i].max_vcpu_id,
		      domaininfo[i].ssidref,
		      domaininfo[i].handle);
	      }
	      uint32_t dsIndex = assignVM_dsIndex(sp, (char *)&domaininfo[i].handle);
	      SFLDataSource_instance dsi;
	      // ds_class = <virtualEntity>, ds_index = offset + <assigned>, ds_instance = 0
	      SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, HSP_DEFAULT_LOGICAL_DSINDEX_START + dsIndex, 0);
	      SFLPoller *vpoller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCountersVM);
	      HSPVMState *state = (HSPVMState *)vpoller->userData;
	      if(state) {
		// it was already there, just clear the mark.
		state->marked = NO;
		// and reset the information that we are about to refresh
		strArrayReset(state->volumes);
	      }
	      else {
		// new one - tell it what to do.
		myLog(LOG_INFO, "configVMs: new domain=%u", domId);
		uint32_t pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
		sfl_poller_set_sFlowCpInterval(vpoller, pollingInterval);
		sfl_poller_set_sFlowCpReceiver(vpoller, HSP_SFLOW_RECEIVER_INDEX);
		// hang a new HSPVMState object on the userData hook
		state = (HSPVMState *)my_calloc(sizeof(HSPVMState));
		state->network_count = 0;
		state->marked = NO;
		vpoller->userData = state;
		state->volumes = strArrayNew();
		sp->refreshAdaptorList = YES;
	      }
	      // remember the index so we can access this individually later
	      // (actually this was a misunderstanding - the vm_index is not
	      // really needed at all.  Should take it out. Can still detect
	      // duplicates using the 'marked' flag).
	      if(state->vm_index) {
		if(debug) {
		  myLog(LOG_INFO, "duplicate entry for domId=%u vm_index %u repeated at %u (keep first one)", domId, state->vm_index, (num_domains + i));
		}
	      }
	      else {
		state->vm_index = num_domains + i;
	      }
	      // and the domId, which might have changed (if vm rebooted)
	      state->domId = domId;
	      // pick up the list of block device numbers
	      xen_collect_block_devices(sp, state);
	    }
	  }
	  num_domains += new_domains;
	} while(new_domains > 0);
	// remember the number of domains we found
	sp->num_domains = num_domains;
      }
#endif

#ifdef HSF_VRT
      if(sp->virConn == NULL) {
	// no libvirt connection
	return;
      }
      int num_domains = virConnectNumOfDomains(sp->virConn);
      if(num_domains == -1) {
	myLog(LOG_ERR, "virConnectNumOfDomains() returned -1");
	return;
      }
      int *domainIds = (int *)my_calloc(num_domains * sizeof(int));
      if(virConnectListDomains(sp->virConn, domainIds, num_domains) != num_domains) {
	my_free(domainIds);
	return;
      }
      for(int i = 0; i < num_domains; i++) {
	int domId = domainIds[i];
	virDomainPtr domainPtr = virDomainLookupByID(sp->virConn, domId);
	if(domainPtr) {
	  char uuid[16];
	  virDomainGetUUID(domainPtr, (u_char *)uuid);
	  uint32_t dsIndex = assignVM_dsIndex(sp, uuid);
	  SFLDataSource_instance dsi;
	  // ds_class = <virtualEntity>, ds_index = offset + <assigned>, ds_instance = 0
	  SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, HSP_DEFAULT_LOGICAL_DSINDEX_START + dsIndex, 0);
	  SFLPoller *vpoller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCountersVM);
	  HSPVMState *state = (HSPVMState *)vpoller->userData;
	  if(state) {
	    // it was already there, just clear the mark.
	    state->marked = NO;
	    // and reset the information that we are about to refresh
	    adaptorListMarkAll(state->interfaces);
	    strArrayReset(state->volumes);
	    strArrayReset(state->disks);
	  }
	  else {
	    // new one - tell it what to do.
	    myLog(LOG_INFO, "configVMs: new domain=%u", domId);
	    uint32_t pollingInterval = sf->sFlowSettings ? sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
	    sfl_poller_set_sFlowCpInterval(vpoller, pollingInterval);
	    sfl_poller_set_sFlowCpReceiver(vpoller, HSP_SFLOW_RECEIVER_INDEX);
	    // hang a new HSPVMState object on the userData hook
	    state = (HSPVMState *)my_calloc(sizeof(HSPVMState));
	    state->network_count = 0;
	    state->marked = NO;
	    vpoller->userData = state;
	    state->interfaces = adaptorListNew();
	    state->volumes = strArrayNew();
	    state->disks = strArrayNew();
	    sp->refreshAdaptorList = YES;
	  }
	  // remember the index so we can access this individually later
	  if(debug) {
	    if(state->vm_index != i) {
	      myLog(LOG_INFO, "domId=%u vm_index %u->%u", domId, state->vm_index, i);
	    }
	  }
	  state->vm_index = i;
	  // and the domId, which might have changed (if vm rebooted)
	  state->domId = domId;
	  
	  // get the XML descr - this seems more portable than some of
	  // the newer libvert API calls,  such as those to list interfaces
	  char *xmlstr = virDomainGetXMLDesc(domainPtr, 0 /*VIR_DOMAIN_XML_SECURE not allowed for read-only */);
	  if(xmlstr == NULL) {
	    myLog(LOG_ERR, "virDomainGetXMLDesc(domain=%u, 0) failed", domId);
	  }
	  else {
	    // parse the XML to get the list of interfaces and storage nodes
	    xmlDoc *doc = xmlParseMemory(xmlstr, strlen(xmlstr));
	    if(doc) {
	      xmlNode *rootNode = xmlDocGetRootElement(doc);
	      domain_xml_node(rootNode, state);
	      xmlFreeDoc(doc);
	    }
	    free(xmlstr); // allocated by virDomainGetXMLDesc()
	  }
	  xmlCleanupParser();
	  virDomainFree(domainPtr);
	  adaptorListFreeMarked(state->interfaces);
	}
      }
      // remember the number of domains we found
      sp->num_domains = num_domains;
      my_free(domainIds);
#endif
      
      // 3. remove any that don't exist any more
      for(SFLPoller *pl = sf->agent->pollers; pl; ) {
	SFLPoller *nextPl = pl->nxt;
	if(SFL_DS_CLASS(pl->dsi) == SFL_DSCLASS_LOGICAL_ENTITY) {
	  HSPVMState *state = (HSPVMState *)pl->userData;
	  if(state->marked) {
	    myLog(LOG_INFO, "configVMs: removing poller with dsIndex=%u (domId=%u)",
		  SFL_DS_INDEX(pl->dsi),
		  state->domId);
	    if(state->disks) strArrayFree(state->disks);
	    if(state->volumes) strArrayFree(state->volumes);
	    if(state->interfaces) adaptorListFree(state->interfaces);
	    my_free(state);
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
      fprintf(sp->f_out, "header=%u\n", SFL_DEFAULT_HEADER_SIZE);
      fprintf(sp->f_out, "polling=%u\n", settings->pollingInterval);
      // make sure the application specific ones always come after the general ones - to simplify the override logic there
      for(HSPApplicationSettings *appSettings = settings->applicationSettings; appSettings; appSettings = appSettings->nxt) {
	if(appSettings->got_sampling_n) fprintf(sp->f_out, "sampling.%s=%u\n", appSettings->application, appSettings->sampling_n);
	if(appSettings->got_polling_secs) fprintf(sp->f_out, "polling.%s=%u\n", appSettings->application, appSettings->polling_secs);
      }
      char ipbuf[51];
      fprintf(sp->f_out, "agentIP=%s\n", printIP(&sp->sFlow->agentIP, ipbuf, 50));
      if(sp->sFlow->agentDevice) {
	fprintf(sp->f_out, "agent=%s\n", sp->sFlow->agentDevice);
      }
      fprintf(sp->f_out, "ds_index=%u\n", HSP_DEFAULT_PHYSICAL_DSINDEX);
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
    if(sp->nio_polling_secs &&
       ((sp->clk % sp->nio_polling_secs) == 0)) {
      updateNioCounters(sp);
    }
    
    // refresh the list of VMs periodically or on request
    if(sp->refreshVMList || (sp->clk % HSP_REFRESH_VMS) == 0) {
      sp->refreshVMList = NO;
      configVMs(sp);
    }

    // write the persistent state if requested
    if(sp->vmStoreInvalid) {
      writeVMStore(sp);
      sp->vmStoreInvalid = NO;
    }

    // refresh the interface list perioducally or on request
    if(sp->refreshAdaptorList || (sp->clk % HSP_REFRESH_ADAPTORS) == 0) {
      sp->refreshAdaptorList = NO;
      readInterfaces(sp);
    }


    // rewrite the output if the config has changed
    if(sp->outputRevisionNo != sp->sFlow->revisionNo) {
      syncOutputFile(sp);
      sp->outputRevisionNo = sp->sFlow->revisionNo;
    }
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
      
      // bind
      sp->ulog_bind.nl_family = AF_NETLINK;
      sp->ulog_bind.nl_pid = getpid();
      // Note that the ulogGroup setting is only ever retrieved from the config file (i.e. not settable by DNSSD)
      sp->ulog_bind.nl_groups = 1 << (sp->sFlow->sFlowSettings_file->ulogGroup - 1); // e.g. 16 => group 5
      if(bind(sp->ulog_soc, (struct sockaddr *)&sp->ulog_bind, sizeof(sp->ulog_bind)) == -1) {
	myLog(LOG_ERR, "ULOG bind() failed: %s", strerror(errno));
      }
      
      // increase receiver buffer size? (probably not necessary)
      // uint32_t rcvbuf = HSP_ULOG_RCV_BUF;
      // setsockopt(sp->ulog_soc, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }
    else {
      myLog(LOG_ERR, "error opening ULOG socket: %s", strerror(errno));
      // just disable it
      sp->ulog_soc = 0;
    }
  }
#endif

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
  // ds_class = <physicalEntity>, ds_index = <my physical>, ds_instance = 0
    SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, HSP_DEFAULT_PHYSICAL_DSINDEX, 0);
    sf->poller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(sf->poller, pollingInterval);
    sfl_poller_set_sFlowCpReceiver(sf->poller, HSP_SFLOW_RECEIVER_INDEX);
    
    // add <virtualEntity> pollers for each virtual machine
    configVMs(sp);

 #ifdef HSF_ULOG
    if(sp->sFlow->sFlowSettings_file->ulogGroup != 0) {
      // ULOG group is set, so open the netfilter
      // socket to ULOG while we are still root
      openULOG(sp);
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
    _________________   installSFlowSettings    __________________
    -----------------___________________________------------------

    Always increment the revision number whenever we change the sFlowSettings pointer
  */
  
  static void installSFlowSettings(HSPSFlow *sf, HSPSFlowSettings *settings)
  {
    if(settings && sf->sFlowSettings_file) {
      // calculate the ULOG sub-sampling rate to use.  We may get the local ULOG sampling-rate
      // from the config file and the desired sampling rate from DNS-SD,  so that's why
      // we have to reconcile the two here.
      uint32_t ulogsr = sf->sFlowSettings_file->ulogSamplingRate;
      if(ulogsr == 0) {
	// assume we have to do all sampling in user-space
	settings->ulogSubSamplingRate = settings->ulogActualSamplingRate = settings->samplingRate;
      }
      else {
	// use an integer divide to get the sub-sampling rate, but make sure we round up
	settings->ulogSubSamplingRate = (settings->samplingRate + ulogsr - 1) / ulogsr;
	// and pre-calculate the actual sampling rate that we will end up applying
	settings->ulogActualSamplingRate = settings->ulogSubSamplingRate * ulogsr;
      }
    }
    
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

    if(key == NULL) {
      // no key => SRV response.  We always ask for SRV first,  then TXT, so we can take
      // this opportunity to clear out the TXT state from last time
      clearApplicationSettings(st);

      // now see if we got a collector
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
      else {
	myLog(LOG_INFO, "unexpected dnsSD record <%s>=<%s>", keyBuf, valBuf);
      }
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
	GETMYLIMIT(RLIMIT_LOCKS);
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
    
#if defined(HSF_XEN) || defined(HSF_VRT)
    // open the vmStore file while we still have root priviliges
    // use mode "w+" because we intend to write it and rewrite it.
    if((sp->f_vmStore = fopen(sp->vmStoreFile, "w+")) == NULL) {
      myLog(LOG_ERR, "cannot open vmStore file %s : %s", sp->vmStoreFile, strerror(errno));
      exit(EXIT_FAILURE);
    }
#endif

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
	if(readInterfaces(sp) == 0 || HSPReadConfigFile(sp) == NO) {
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
	  sp->nio_polling_secs = HSP_NIO_POLLING_SECS_32BIT;
	  
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
#ifdef HSF_ULOG
	  readPackets(sp);
#endif
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
#ifdef HSF_ULOG
      if(sp->ulog_soc) my_usleep_fd(200000, sp->ulog_soc);
      else my_usleep(200000);
#else
      my_usleep(200000);
#endif
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

