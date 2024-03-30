/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

// xs.h because xenstore.h
#ifdef HSP_XENSTORE_H
#include "xenstore.h"
#else
#include "xs.h"
#endif

#include "xenctrl.h"
#include "dirent.h"
#include "regex.h" // for vif detection
// The pattern on a xenserver is usually just "vif%d.%d" but
// different platforms may have different strings here, so we
// make it a regular expression that can be overridden in the
// config.
// This default expression looks for anything that
// has "vif" in it and ends with domid.netid,  which might
// actually work for most xen variants.
#define HSP_XEN_VIF_REGEX "vif[^0-9]*([0-9]+)\\.([0-9]+)$"
#define HSP_XEN_VIF_REGEX_NMATCH 3 // fields-to-extract + 1
// For convenience, define a domId to mean "the physical host"
#define XEN_DOMID_PHYSICAL (uint32_t)-1

  typedef struct _HSPVMState_XEN {
    HSPVMState vm; // superclass: must come first
    xc_domaininfo_t domaininfo;
    int domId;
    int network_count;
  } HSPVMState_XEN;

  typedef struct _HSP_mod_XEN {
    UTHash *vmsByUUID;
    int num_domains;
#ifdef XENCTRL_HAS_XC_INTERFACE
    xc_interface *xc_handle;
#else
    int xc_handle; // libxc
#endif
    struct xs_handle *xs_handle; // xenstore
    uint32_t page_size;
    SFLCounters_sample_element vnodeElem;
    uint32_t refreshVMListSecs;
    time_t next_refreshVMList;
    uint32_t forgetVMSecs;
  } HSP_mod_XEN;

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

  void openXenHandles(EVMod *mod)
  {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    // need to do this while we still have root privileges
    if(mdata->xc_handle == 0) {
      mdata->xc_handle = HSP_XENCTRL_INTERFACE_OPEN();
      if(!HSP_XENCTRL_HANDLE_OK(mdata->xc_handle)) {
        myLog(LOG_ERR, "xc_interface_open() failed : %s", strerror(errno));
      }
      else {
        mdata->xs_handle = xs_daemon_open_readonly();
        if(mdata->xs_handle == NULL) {
          myLog(LOG_ERR, "xs_daemon_open_readonly() failed : %s", strerror(errno));
        }
        // get the page size [ref xenstat.c]
#if defined(PAGESIZE)
        mdata->page_size = PAGESIZE;
#elif defined(PAGE_SIZE)
        mdata->page_size = PAGE_SIZE;
#else
        mdata->page_size = sysconf(_SC_PAGE_SIZE);
        if(mdata->page_size <= 0) {
          myLog(LOG_ERR, "Failed to retrieve page size : %s", strerror(errno));
          abort();
        }
#endif
      }
    }
  }

  // if mdata->xs_handle is not NULL then we know that mdata->xc_handle is good too
  // because of the way we opened the handles in the first place.
  static int xenHandlesOK(EVMod *mod) {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    return (mdata->xs_handle != NULL);
  }

  void closeXenHandles(EVMod *mod)
  {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;

    if(HSP_XENCTRL_HANDLE_OK(mdata->xc_handle)) {
      xc_interface_close(mdata->xc_handle);
      mdata->xc_handle = 0;
    }
    if(mdata->xs_handle) {
      xs_daemon_close(mdata->xs_handle);
      mdata->xs_handle = NULL;
    }
  }

  int readXenVNodeCounters(EVMod *mod, SFLHost_vrt_node_counters *vnode)
  {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    if(xenHandlesOK(mod)) {
      xc_physinfo_t physinfo = { 0 };
      if(xc_physinfo(mdata->xc_handle, &physinfo) < 0) {
	myLog(LOG_ERR, "xc_physinfo() failed : %s", strerror(errno));
      }
      else {
      	vnode->mhz = (physinfo.cpu_khz / 1000);
	vnode->cpus = physinfo.nr_cpus;
	vnode->memory = ((uint64_t)physinfo.total_pages * mdata->page_size);
	vnode->memory_free = ((uint64_t)physinfo.free_pages * mdata->page_size);
	vnode->num_domains = mdata->num_domains;
	return YES;
      }
    }
    return NO;
  }

  SFLAdaptorList *xenstat_adaptors(EVMod *mod, uint32_t dom_id, SFLAdaptorList *myAdaptors, int capacity) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(getDebug() > 3) {
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

	if(myAdaptors->num_adaptors >= capacity)
	  break;

	uint32_t xapi_index = 0;
	int isVirtual = niostate->vm_or_container;
	int isXapi = (sscanf(adaptor->deviceName, "xapi%"SCNu32, &xapi_index) == 1);
	if(getDebug() > 3) {
	  myLog(LOG_INFO, "- xenstat_adaptors(): found %s (virtual=%s, domid=%"PRIu32", netid=%"PRIu32") (xapi=%s, index=%"PRIu32")",
		adaptor->deviceName,
		isVirtual ? "YES" : "NO",
		niostate->xen_domid,
		niostate->xen_netid,
		isXapi ? "YES" : "NO",
		xapi_index);
	}
	if((isVirtual
	    && dom_id == niostate->xen_domid) ||
	   (!isVirtual
	    && !isXapi
	    && dom_id == XEN_DOMID_PHYSICAL)) {
	  // include this one
	  myAdaptors->adaptors[myAdaptors->num_adaptors++] = adaptor;
	}
      }
    }
    return myAdaptors;
  }

  static int64_t xen_vbd_counter(uint32_t dom_id, char *vbd_dev, char *vbd_path, char *counter, int usec) {
    int64_t ctr64 = 0;
    char ctrspec[HSP_MAX_PATHLEN];
    snprintf(ctrspec, HSP_MAX_PATHLEN, "%u-%s/statistics/%s",
	     dom_id,
	     vbd_dev,
	     counter);
    char path[HSP_MAX_PATHLEN];
    FILE *file = NULL;
    // try vbd first,  then tap
    snprintf(path, HSP_MAX_PATHLEN, "%s/vbd-%s", vbd_path, ctrspec);
    if((file = fopen(path, "r")) == NULL) {
      snprintf(path, HSP_MAX_PATHLEN, "%s/tap-%s", vbd_path, ctrspec);
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
	if(fscanf(file, "%"SCNi64, &ctr64) != 1) {
	  myDebug(1, "xen_vbd_counter: <%s> fscanf failed ", path);
	  ctr64 = 0;
	}
      }
      fclose(file);
    }
    else {
      myDebug(1, "xen_vbd_counter: <%s> not found ", path);
    }
    myDebug(1, "xen_vbd_counter: <%s> = %"PRIu64, path, ctr64);
    return ctr64;
  }

  static int xen_collect_block_devices(EVMod *mod, HSPVMState_XEN *state) {
    // HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    DIR *sysfsvbd = opendir(sp->xen.vbd);
    if(sysfsvbd == NULL) {
      static int logcount = 0;
      if(logcount++ < 3) {
	myLog(LOG_ERR, "opendir %s failed : %s", sp->xen.vbd, strerror(errno));
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
	  strArrayAdd(state->vm.volumes, vbd_dev);
	  found++;
	}
      }
    }
    closedir(sysfsvbd);
    return found;
  }

  static int xenstat_dsk(EVMod *mod, HSPVMState_XEN *state, SFLHost_vrt_dsk_counters *dsk)
  {
    // HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    for(uint32_t i = 0; i < strArrayN(state->vm.volumes); i++) {
      char *vbd_dev = strArrayAt(state->vm.volumes, i);
      myDebug(3, "reading VBD %s for dom_id %u", vbd_dev, state->domId);
      dsk->rd_req += xen_vbd_counter(state->domId, vbd_dev, sp->xen.vbd, "rd_req", NO);
      dsk->rd_bytes += (xen_vbd_counter(state->domId, vbd_dev, sp->xen.vbd, "rd_sect", NO) * HSP_SECTOR_BYTES);
      dsk->wr_req += xen_vbd_counter(state->domId, vbd_dev, sp->xen.vbd, "wr_req", NO);
      dsk->wr_bytes += (xen_vbd_counter(state->domId, vbd_dev, sp->xen.vbd, "wr_sect", NO) * HSP_SECTOR_BYTES);
      dsk->errs += xen_vbd_counter(state->domId, vbd_dev, sp->xen.vbd, "oo_req", NO);
      //dsk->capacity $$$
      //dsk->allocation $$$
      //dsk->available $$$
    }
    return YES;
  }

  static void agentCB_getCounters_XEN(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    assert(poller->magic);
    HSPVMState_XEN *state = (HSPVMState_XEN *)poller->userData;
    if(state == NULL) {
      myDebug(1, "agentCB_getCounters_XEN: state==NULL");
      return;
    }
    EVMod *mod = (EVMod *)poller->magic;
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;

    if(xenHandlesOK(mod)) {
      HSP *sp = (HSP *)EVROOTDATA(mod);

      xc_domaininfo_t domaininfo;
      if(!sp->xen.update_dominfo) {
	// this optimization forces us to use the (stale) domaininfo from the last time
	// we refreshed the VM list.  Most of these parameters change very rarely anyway
	// so this is not a big sacrifice at all.
	domaininfo = state->domaininfo; // struct copy
      }
      else {
	int32_t n = xc_domain_getinfolist(mdata->xc_handle, state->domId, 1, &domaininfo);
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
      char *xshname = (char *)xs_read(mdata->xs_handle, XBT_NULL, query, NULL);
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
	if(xc_vcpu_getinfo(mdata->xc_handle, state->domId, c, &info) != 0) {
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

      myDebug(1, "vm domid=%u, dsIndex=%u, tot_pages=%u",
		      state->domId,
		      SFL_DS_INDEX(poller->dsi),
		      domaininfo.tot_pages);

      memElem.counterBlock.host_vrt_mem.memory = domaininfo.tot_pages * mdata->page_size;
      memElem.counterBlock.host_vrt_mem.maxMemory = (domaininfo.max_pages == UINT_MAX) ? -1 : (domaininfo.max_pages * mdata->page_size);
      SFLADD_ELEMENT(cs, &memElem);

      // VM disk I/O counters
      SFLCounters_sample_element dskElem = { 0 };
      dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
      if(sp->xen.dsk) {
	if(xenstat_dsk(mod, state, &dskElem.counterBlock.host_vrt_dsk)) {
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
      adaptorsElem.counterBlock.adaptors = xenstat_adaptors(mod, state->domId, &myAdaptors, HSP_MAX_VIFS);
      SFLADD_ELEMENT(cs, &adaptorsElem);

      sfl_poller_writeCountersSample(poller, cs);
      sp->counterSampleQueued = YES;
      sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES]++;
    }
  }

  /*_________________---------------------------__________________
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  HSPVMState_XEN *getVM_XEN(EVMod *mod, char *uuid) {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSPVMState_XEN search;
    memset(&search, 0, sizeof(search));
    memcpy(search.vm.uuid, uuid, 16);
    HSPVMState_XEN *state = UTHashGet(mdata->vmsByUUID, &search);
    if(state == NULL) {
      // new vm or container
      myDebug(1, "adding new Xen VM");
      state = (HSPVMState_XEN *)getVM(mod, uuid, YES, sizeof(HSPVMState_XEN), VMTYPE_XEN, agentCB_getCounters_XEN);
      if(state) {
	UTHashAdd(mdata->vmsByUUID, state);
      }
    }
    return state;
  }

  static void removeAndFreeVM_XEN(EVMod *mod, HSPVMState_XEN *state) {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    myDebug(1, "removeAndFreeVM: removing vm with dsIndex=%u (domId=%u)",
	    state->vm.dsIndex,
	    state->domId);
    UTHashDel(mdata->vmsByUUID, state);
    HSPVMState *vm = &state->vm;
    removeAndFreeVM(mod, vm);
  }

  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */

  void configVMs_XEN(EVMod *mod) {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(xenHandlesOK(mod)) {
#define DOMAIN_CHUNK_SIZE 256
      xc_domaininfo_t domaininfo[DOMAIN_CHUNK_SIZE];
      int32_t num_domains=0, new_domains=0, duplicate_domains=0;
      do {
	new_domains = xc_domain_getinfolist(mdata->xc_handle,
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
	    if(getDebug()) {
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
	    HSPVMState_XEN *state = getVM_XEN(mod, (char *)&domaininfo[i].handle);
	    HSPVMState *vm = (HSPVMState *)&state->vm;
	    if(vm->marked == NO &&
	       vm->created == NO) {
	      duplicate_domains++;
	      myDebug(1, "duplicate entry for domId=%u repeated at %u (keep first one)", domId, (num_domains + i));
	    }
	    else {
	      vm->marked = NO;
	      vm->created = NO;
	      // domId can change if VM is rebooted
	      state->domId = domId;

	      // reset information we are about to refresh
	      // strArrayReset(state->interfaces);
	      strArrayReset(vm->volumes);
	      // strArrayReset(state->disks);

	      if(sp->xen.dsk) {
		// pick up the list of block device numbers
		xen_collect_block_devices(mod, state);
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
      mdata->num_domains = num_domains - duplicate_domains;
    }
  }

  static void configVMs(EVMod *mod) {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    // mark and sweep
    // 1. mark all the current virtual pollers
    HSPVMState_XEN *state;
    UTHASH_WALK(mdata->vmsByUUID, state) {
      state->vm.marked = YES;
    }

    // 2. create new VM pollers, or clear the mark on existing ones
    configVMs_XEN(mod);

    // 3. remove any VMs (and their pollers) that don't survive
    UTHASH_WALK(mdata->vmsByUUID, state) {
      if(state->vm.marked) {
	removeAndFreeVM_XEN(mod, state);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   markSwitchPorts         __________________
    -----------------___________________________------------------
  */

  static void markSwitchPorts(EVMod *mod)  {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->xen.vif_regex_str == NULL) {
      // pattern not specified in config, so compile the default
      sp->xen.vif_regex_str = HSP_XEN_VIF_REGEX;
      sp->xen.vif_regex = UTRegexCompile(HSP_XEN_VIF_REGEX);
      assert(sp->xen.vif_regex);
    }

    // use pattern to mark the switch ports - and extract domid and netid
    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByIndex, adaptor) {
      HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
      if(UTRegexExtractInt(sp->xen.vif_regex,
			   adaptor->deviceName,
			   2,
			   &niostate->xen_domid,
			   &niostate->xen_netid,
			   NULL)) {
	niostate->vm_or_container = YES;
	// for virtual interfaces we need to query for the MAC address
	char macQuery[256];
	snprintf(macQuery, sizeof(macQuery), "/local/domain/%u/device/vif/%u/mac", niostate->xen_domid, niostate->xen_netid);
	char *macStr = xs_read(mdata->xs_handle, XBT_NULL, macQuery, NULL);
	if(macStr == NULL) {
	  myLog(LOG_ERR, "xenstat_adaptors(): mac address query failed : %s : %s", macQuery, strerror(errno));
	}
	else{
	  if(getDebug() > 3) myLog(LOG_INFO, "- xenstat_adaptors(): got MAC from xenstore: %s", macStr);
	  // got it - but make sure there is a place to write it
	  if(adaptor->num_macs > 0) {
	    // OK, just overwrite the 'dummy' one that was there.
	    SFLMacAddress mac;
	    memset(&mac, 0, sizeof(mac));
	    if(hexToBinary((u_char *)macStr, mac.mac, 6) != 6) {
	      myLog(LOG_ERR, "mac address format error in xenstore query <%s> : %s", macQuery, macStr);
	    }
	    else {
	      // take care not to corrupt sp->adaptorsByMac
	      UTHashDel(sp->adaptorsByMac, adaptor);
	      adaptor->macs[0] = mac; // struct copy
	      UTHashAdd(sp->adaptorsByMac, adaptor);
	    }
	  }
	  free(macStr); // allocated by xs_read()
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    myDebug(1, "event %s.%s dataLen=%u", mod->name, evt->name, dataLen);
    markSwitchPorts(mod);
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    evt_config_changed(mod, evt, data, dataLen);
  }

  /*_________________---------------------------__________________
    _________________    tick, tock             __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    time_t clk = evt->bus->now.tv_sec;
    if(clk >= mdata->next_refreshVMList
       && sp->sFlowSettings) {
      configVMs(mod);
      mdata->next_refreshVMList = clk + mdata->refreshVMListSecs;
    }
  }

  /*_________________---------------------------__________________
    _________________   host counter sample     __________________
    -----------------___________________________------------------
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;

    if(!hasVNodeRole(mod, HSP_VNODE_PRIORITY_XEN))
      return;

    memset(&mdata->vnodeElem, 0, sizeof(mdata->vnodeElem));
    mdata->vnodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
    if(readXenVNodeCounters(mod, &mdata->vnodeElem.counterBlock.host_vrt_node)) {
      SFLADD_ELEMENT(cs, &mdata->vnodeElem);
    }
  }

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    closeXenHandles(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_xen(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_XEN));
    HSP_mod_XEN *mdata = (HSP_mod_XEN *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    requestVNodeRole(mod, HSP_VNODE_PRIORITY_XEN);

    mdata->vmsByUUID = UTHASH_NEW(HSPVMState_XEN, vm.uuid, UTHASH_DFLT);
    mdata->refreshVMListSecs = sp->xen.refreshVMListSecs ?: sp->refreshVMListSecs;
    mdata->forgetVMSecs = sp->xen.forgetVMSecs ?: sp->forgetVMSecs;

    // open Xen handles while we still have root privileges
    openXenHandles(mod);

    // register call-backs
    EVBus *pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_FINAL), evt_final);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
