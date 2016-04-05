/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#ifdef HSP_XEN
	    
  /*_________________---------------------------__________________
    _________________     Xen Handles           __________________
    -----------------___________________________------------------
  */

#ifdef XENCTRL_HAS_XC_INTERFACE
#define HSP_XENCTRL_INTERFACE_OPEN() xc_interface_open(NULL /*logger*/, NULL/*dombuild_logger*/, XC_OPENFLAG_NON_REENTRANT);
#define HSP_XENCTRL_HANDLE_OK(h) ((h) != NULL)
#else
#define HSP_XENCTRL_INTERFACE_OPEN() xc_interface_open()
#define HSP_XENCTRL_HANDLE_OK(h) ((h) && (h) != -1)
#endif

  void openXenHandles(HSP *sp)
  {
    // need to do this while we still have root privileges
    if(sp->xc_handle == 0) {
      sp->xc_handle = HSP_XENCTRL_INTERFACE_OPEN();
      if(!HSP_XENCTRL_HANDLE_OK(sp->xc_handle)) {
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

  void closeXenHandles(HSP *sp)
  {
    if(HSP_XENCTRL_HANDLE_OK(sp->xc_handle)) {
      xc_interface_close(sp->xc_handle);
      sp->xc_handle = 0;
    }
    if(sp->xs_handle) {
      xs_daemon_close(sp->xs_handle);
      sp->xs_handle = NULL;
    }
  }

  int readXenVNodeCounters(HSP *sp, SFLHost_vrt_node_counters *vnode)
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

  int xen_compile_vif_regex(HSP *sp) {
    int err = regcomp(&sp->vif_regex, HSP_XEN_VIF_REGEX, REG_EXTENDED);
    if(err) {
      char errbuf[101];
      myLog(LOG_ERR, "regcomp(%s) failed: %s", HSP_XEN_VIF_REGEX, regerror(err, &sp->vif_regex, errbuf, 100));
      return NO;
    }
    return YES;
  }

  static long regmatch_as_long(regmatch_t *rm, char *str) {
    int len = (int)rm->rm_eo - (int)rm->rm_so;
      // copy it out so we can null-terminate just to be safe
      char extraction[8];
      if(rm->rm_so != -1 && len > 0 && len < 8) {
	memcpy(extraction, str + rm->rm_so, len);
	extraction[len] = '\0';
	return strtol(extraction, NULL, 0);
      }
      else {
	return -1;
      }
  }

  SFLAdaptorList *xenstat_adaptors(HSP *sp, uint32_t dom_id, SFLAdaptorList *myAdaptors, int capacity)
  {
    if(debug > 3) {
      if(dom_id == XEN_DOMID_PHYSICAL) myLog(LOG_INFO, "xenstat_adaptors(): looking for physical host interfaces");
      else myLog(LOG_INFO, "xenstat_adaptors(): looking for vif with domId=%"PRIu32, dom_id);
    }

    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(niostate->up
	 && (niostate->switchPort == NO)
	 && adaptor->num_macs
	 && !isZeroMAC(&adaptor->macs[0])) {
	if(myAdaptors->num_adaptors >= capacity) break;
	uint32_t vif_domid=0;
	uint32_t vif_netid=0;
	uint32_t xapi_index=0;
	int isVirtual = NO;
#ifdef HSP_XEN_VIF_REGEX
	// we could move this regex extraction to the point where we first learn the adaptor->name and
	// store it wit the adaptor user-data.  Then we wouldn't have to do it so often.  It might get
	// expensive on a system with a large number of VMs.
	if(regexec(&sp->vif_regex, adaptor->deviceName, HSP_XEN_VIF_REGEX_NMATCH, sp->vif_match, 0) == 0) {
	  long ifield1 = regmatch_as_long(&sp->vif_match[1], adaptor->deviceName);
	  long ifield2 = regmatch_as_long(&sp->vif_match[2], adaptor->deviceName);
	  if(ifield1 == -1 || ifield2 == -1) {
	    myLog(LOG_ERR, "failed to parse domId and netId from vif name <%s>", adaptor->deviceName);
	  }
	  else {
	    vif_domid = (uint32_t)ifield1;
	    vif_netid = (uint32_t)ifield2;
	    isVirtual = YES;
	  }
	}
#else
	isVirtual = (sscanf(adaptor->deviceName, "vif%"SCNu32".%"SCNu32, &vif_domid, &vif_netid) == 2);
#endif
	
	int isXapi = (sscanf(adaptor->deviceName, "xapi%"SCNu32, &xapi_index) == 1);
	if(debug > 3) {
	  myLog(LOG_INFO, "- xenstat_adaptors(): found %s (virtual=%s, domid=%"PRIu32", netid=%"PRIu32") (xapi=%s, index=%"PRIu32")",
		adaptor->deviceName,
		isVirtual ? "YES" : "NO",
		vif_domid,
		vif_netid,
		isXapi ? "YES" : "NO",
		xapi_index);
	}
	if((isVirtual && dom_id == vif_domid) ||
	   (!isVirtual && !isXapi && dom_id == XEN_DOMID_PHYSICAL)) {
	  // include this one
	  myAdaptors->adaptors[myAdaptors->num_adaptors++] = adaptor;
	  // mark it as a vm/container device
	  ADAPTOR_NIO(adaptor)->vm_or_container = YES;
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

#define HSP_MAX_PATHLEN 256

  // allow HSP_XEN_VBD_PATH to be passed in at compile time,  but fall back on the default if it is not.
#ifndef HSP_XEN_VBD_PATH
#define HSP_XEN_VBD_PATH /sys/devices/xen-backend
#endif

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
    snprintf(path, HSP_MAX_PATHLEN, STRINGIFY_DEF(HSP_XEN_VBD_PATH) "/vbd-%s", ctrspec);
    if((file = fopen(path, "r")) == NULL) {
      snprintf(path, HSP_MAX_PATHLEN, STRINGIFY_DEF(HSP_XEN_VBD_PATH) "/tap-%s", ctrspec);
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
    DIR *sysfsvbd = opendir(STRINGIFY_DEF(HSP_XEN_VBD_PATH));
    if(sysfsvbd == NULL) {
      static int logcount = 0;
      if(logcount++ < 3) {
	myLog(LOG_ERR, "opendir %s failed : %s", STRINGIFY_DEF(HSP_XEN_VBD_PATH), strerror(errno));
      }
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
      dsk->wr_req += xen_vbd_counter(state->domId, vbd_dev, "wr_req", NO);
      dsk->wr_bytes += (xen_vbd_counter(state->domId, vbd_dev, "wr_sect", NO) * HSP_SECTOR_BYTES);
      dsk->errs += xen_vbd_counter(state->domId, vbd_dev, "oo_req", NO);
      //dsk->capacity $$$
      //dsk->allocation $$$
      //dsk->available $$$
    }
    return YES;
  }

  static void agentCB_getCounters_XEN(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSPVMState *state = (HSPVMState *)poller->userData;
    if(state == NULL) {
      if(debug) myLog(LOG_INFO, "agentCB_getCounters_XEN: state==NULL");
      return;
    }
    if(state->vmType != VMTYPE_XEN) {
      myLog(LOG_ERR, "agentCB_getCounters_XEN(): not a XEN VM");
      return;
    }
    HSP *sp = (HSP *)poller->magic;

    if(xenHandlesOK(sp)) {
      
      xc_domaininfo_t domaininfo;
      if(!sp->sFlow->sFlowSettings_file->xen_update_dominfo) {
	// this optimization forces us to use the (stale) domaininfo from the last time
	// we refreshed the VM list.  Most of these parameters change very rarely anyway
	// so this is not a big sacrifice at all.
	domaininfo = state->domaininfo; // struct copy
      }
      else {
	int32_t n = xc_domain_getinfolist(sp->xc_handle, state->domId, 1, &domaininfo);
	if(n < 0 || domaininfo.domain != state->domId) {
	  // Assume something changed under our feet.
	  // Request a reload of the VM information and bail.
	  // We'll try again next time.
	  myLog(LOG_INFO, "request for dom_id=%u returned %d (with dom_id=%u)",
		state->domId,
		n,
		domaininfo.domain);
	  sp->refreshVMList = YES;
	  return;
	}
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

      if(debug) myLog(LOG_INFO, "vm domid=%u, dsIndex=%u, tot_pages=%u",
		      state->domId,
		      SFL_DS_INDEX(poller->dsi),
		      domaininfo.tot_pages);

		      
      memElem.counterBlock.host_vrt_mem.memory = domaininfo.tot_pages * sp->page_size;
      memElem.counterBlock.host_vrt_mem.maxMemory = (domaininfo.max_pages == UINT_MAX) ? -1 : (domaininfo.max_pages * sp->page_size);
      SFLADD_ELEMENT(cs, &memElem);

      // VM disk I/O counters
      SFLCounters_sample_element dskElem = { 0 };
      dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
      if(sp->sFlow->sFlowSettings_file->xen_dsk) {
	if(xenstat_dsk(sp, state, &dskElem.counterBlock.host_vrt_dsk)) {
	  SFLADD_ELEMENT(cs, &dskElem);
	}
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
      adaptorsElem.counterBlock.adaptors = xenstat_adaptors(sp, state->domId, &myAdaptors, HSP_MAX_VIFS);
      SFLADD_ELEMENT(cs, &adaptorsElem);

      SEMLOCK_DO(sp->sync_receiver) {
	sfl_poller_writeCountersSample(poller, cs);
      }
    }
  }

  static void agentCB_getCounters_XEN_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)poller->magic;
    UTArrayAdd(sp->pollActions, poller);
    UTArrayAdd(sp->pollActions, agentCB_getCounters_XEN);
  }

  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */
  
  void configVMs_XEN(HSP *sp) {
    if(xenHandlesOK(sp)) {
#define DOMAIN_CHUNK_SIZE 256
      xc_domaininfo_t domaininfo[DOMAIN_CHUNK_SIZE];
      int32_t num_domains=0, new_domains=0, duplicate_domains=0;
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
	    HSPVMState *state = getVM(sp, (char *)&domaininfo[i].handle, VMTYPE_XEN, agentCB_getCounters_XEN_request);
	    if(state->marked == NO &&
	       state->created == NO) {
	      duplicate_domains++;
	      if(debug) {
		myLog(LOG_INFO, "duplicate entry for domId=%u repeated at %u (keep first one)", domId, (num_domains + i));
	      }
	    }
	    else {
	      state->marked = NO;
	      state->created = NO;
	      // domId can change if VM is rebooted
	      state->domId = domId;

	      // reset information we are about to refresh
	      // strArrayReset(state->interfaces);
	      strArrayReset(state->volumes);
	      // strArrayReset(state->disks);
	      
	      if(sp->sFlow->sFlowSettings_file->xen_dsk) {
		// pick up the list of block device numbers
		xen_collect_block_devices(sp, state);
	      }

	      // store state so we don't have to call xc_domain_getinfolist() again for every
	      // VM when we are sending it's counter-sample in agentCB_getCountersVM
	      state->domaininfo = domaininfo[i]; // structure copy
	    }
	  }
	}
	num_domains += new_domains;
      } while(new_domains > 0);
      // remember the number of domains we found
      sp->num_domains = num_domains - duplicate_domains;
    }
  }

#endif /* HSP_XEN */

#if defined(__cplusplus)
} /* extern "C" */
#endif

