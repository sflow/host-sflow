/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "cpu_utils.h"

#ifdef HSF_DOCKER

  static int getContainerPeerAdaptors(HSP *sp, HSPVMState *vm, SFLAdaptorList *peerAdaptors, int capacity)
  {
    // we want the slice of global-namespace adaptors that are veth peers of the adaptors
    // that belong to this container.
    for(uint32_t j=0; j < vm->interfaces->num_adaptors; j++) {
      SFLAdaptor *vm_adaptor = vm->interfaces->adaptors[j];
      SFLAdaptor *adaptor = adaptorByPeerIndex(sp, vm_adaptor->ifIndex);
      if(adaptor) {
	HSPAdaptorNIO *niostate = ADAPTOR_NIO(adaptor);
	if(niostate->up
	   && (niostate->switchPort == NO)
	   && (niostate->loopback == NO)
	   && peerAdaptors->num_adaptors < capacity) {
	  // include this one (if we have room)
	  if(peerAdaptors->num_adaptors < capacity) {
	    peerAdaptors->adaptors[peerAdaptors->num_adaptors++] = adaptor;
	  }
	}
      }
    }
    return peerAdaptors->num_adaptors;
  }

  void agentCB_getCounters_DOCKER(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)poller->magic;
    HSPVMState *state = (HSPVMState *)poller->userData;
    if(state == NULL) {
      if(debug) myLog(LOG_INFO, "agentCB_getCounters_DOCKER: state==NULL");
      return;
    }
    if(state->vmType != VMTYPE_DOCKER) {
      myLog(LOG_ERR, "agentCB_getCounters_DOCKER(): not a DOCKER container");
      return;
    }
    HSPContainer *container = state->container;
    if(container == NULL) {
      if(debug) myLog(LOG_INFO, "agentCB_getCounters_DOCKER: container==NULL");
      return;
    }
    
    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char *hname = my_strnequal(container->hostname, container->id, HSF_DOCKER_SHORTID_LEN) ? container->name : container->hostname;
    hidElem.counterBlock.host_hid.hostname.str = hname;
    hidElem.counterBlock.host_hid.hostname.len = my_strlen(hname);
    memcpy(hidElem.counterBlock.host_hid.uuid, container->uuid, 16);
 
    // for containers we can show the same OS attributes as the parent
    hidElem.counterBlock.host_hid.machine_type = sp->machine_type;
    hidElem.counterBlock.host_hid.os_name = SFLOS_linux;
    hidElem.counterBlock.host_hid.os_release.str = sp->os_release;
    hidElem.counterBlock.host_hid.os_release.len = my_strlen(sp->os_release);
    SFLADD_ELEMENT(cs, &hidElem);
      
    // host parent
    SFLCounters_sample_element parElem = { 0 };
    parElem.tag = SFLCOUNTERS_HOST_PAR;
    parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
    parElem.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
    SFLADD_ELEMENT(cs, &parElem);
    
    // VM Net I/O
    SFLCounters_sample_element nioElem = { 0 };
    nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
    // conjure the list of global-namespace adaptors that are
    // actually veth adaptors peered to adaptors belonging to this
    // container, and make that the list of adaptors that we sum counters over.
    SFLAdaptorList peerAdaptors;
    SFLAdaptor *adaptors[HSP_MAX_VIFS];
    peerAdaptors.adaptors = adaptors;
    peerAdaptors.capacity = HSP_MAX_VIFS;
    peerAdaptors.num_adaptors = 0;
    if(getContainerPeerAdaptors(sp, state, &peerAdaptors, HSP_MAX_VIFS) > 0) {
      readNioCounters(sp, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio, NULL, &peerAdaptors);
      SFLADD_ELEMENT(cs, &nioElem);
    }
      
    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    HSFNameVal cpuVals[] = {
      { "user",0,0 },
      { "system",0,0},
      { NULL,0,0},
    };
    if(readContainerCounters("cpuacct", container->id, "cpuacct.stat", 2, cpuVals)) {
      uint64_t cpu_total = 0;
      if(cpuVals[0].nv_found) cpu_total += cpuVals[0].nv_val64;
      if(cpuVals[1].nv_found) cpu_total += cpuVals[1].nv_val64;
      
      cpuElem.counterBlock.host_vrt_cpu.state = container->running ? 
	SFL_VIR_DOMAIN_RUNNING :
	SFL_VIR_DOMAIN_PAUSED;
      cpuElem.counterBlock.host_vrt_cpu.cpuTime = (uint32_t)(JIFFY_TO_MS(cpu_total));
      cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = 0;
      SFLADD_ELEMENT(cs, &cpuElem);
    }
      
    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
    HSFNameVal memVals[] = {
      { "total_rss",0,0 },
      { "hierarchical_memory_limit",0,0},
      { NULL,0,0},
    };
    if(readContainerCounters("memory", container->id, "memory.stat", 2, memVals)) {
      if(memVals[0].nv_found) {
	memElem.counterBlock.host_vrt_mem.memory = memVals[0].nv_val64;
      }
      if(memVals[1].nv_found && memVals[1].nv_val64 != (uint64_t)-1) {
	uint64_t maxMem = memVals[1].nv_val64;
	memElem.counterBlock.host_vrt_mem.maxMemory = maxMem;
	// Apply simple sanity check to see if this matches the
	// container->memoryLimit number that we got from docker-inspect
	if(debug
	   && container->memoryLimit != 0
	   && maxMem != container->memoryLimit) {
	  myLog(LOG_INFO, "warning: container %s memoryLimit=%"PRIu64" but readContainerCounters shows %"PRIu64,
		container->name,
		container->memoryLimit,
		maxMem);
	}
      }
      SFLADD_ELEMENT(cs, &memElem);
    }

    // VM disk I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
    HSFNameVal dskValsB[] = {
      { "Read",0,0 },
      { "Write",0,0},
      { NULL,0,0},
    };
    if(readContainerCountersMulti("blkio", container->id, "blkio.io_service_bytes_recursive", 2, dskValsB)) {
      if(dskValsB[0].nv_found) {
	dskElem.counterBlock.host_vrt_dsk.rd_bytes += dskValsB[0].nv_val64;
      }
      if(dskValsB[1].nv_found) {
	dskElem.counterBlock.host_vrt_dsk.wr_bytes += dskValsB[1].nv_val64;
      }
    }
    
    HSFNameVal dskValsO[] = {
      { "Read",0,0 },
      { "Write",0,0},
      { NULL,0,0},
    };
    
    if(readContainerCountersMulti("blkio", container->id, "blkio.io_serviced_recursive", 2, dskValsO)) {
      if(dskValsO[0].nv_found) {
	dskElem.counterBlock.host_vrt_dsk.rd_req += dskValsO[0].nv_val64;
      }
      if(dskValsO[1].nv_found) {
	dskElem.counterBlock.host_vrt_dsk.wr_req += dskValsO[1].nv_val64;
      }
    }
    // TODO: fill in capacity, allocation, available fields
    SFLADD_ELEMENT(cs, &dskElem);

    // include my slice of the adaptor list (the ones from my private namespace)
    SFLCounters_sample_element adaptorsElem = { 0 };
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    adaptorsElem.counterBlock.adaptors = state->interfaces;
    SFLADD_ELEMENT(cs, &adaptorsElem);
    sfl_poller_writeCountersSample(poller, cs);
  }    
  
  static HSPContainer *getContainer(HSP *sp, char *id, int create) {
    if(id == NULL) return NULL;
    HSPContainer cont = { .id = id };
    HSPContainer *container = UTHashGet(sp->containers, &cont);
    if(container == NULL && create) {
      container = (HSPContainer *)my_calloc(sizeof(HSPContainer));
      container->id = my_strdup(id);
      // turn it into a UUID - just take the first 16 bytes of the id
      parseUUID(id, container->uuid);
      // add to collection
      UTHashAdd(sp->containers, container, NO);
      // point up to vm struct - creating if necessary
      container->vm = getVM(sp, container->uuid, VMTYPE_DOCKER, agentCB_getCounters_DOCKER);
      // add container pointer to vm
      container->vm->container = container;
    }
    return container;
  }

  static void freeContainer(HSPContainer *container) {
    if(container->id) my_free(container->id);
    if(container->name) my_free(container->name);
    if(container->hostname) my_free(container->hostname);
    if(container->vm) container->vm->container = NULL;
    my_free(container);
  }

  static int dockerContainerCB(void *magic, char *line) {
    HSP *sp = (HSP *)magic;
    char id[HSF_DOCKER_MAX_LINELEN];
    if(sscanf(line, "%s\n", id) == 1) {
      getContainer(sp, id, YES);
    }
    return YES;
  }
  
  static int dockerInspectCB(void *magic, char *line) {
    // just append it to the string-buffer
    UTStrBuf *inspectBuf = (UTStrBuf *)magic;
    UTStrBuf_append(inspectBuf, line);
    return YES;
  }

  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */

  void configVMs_DOCKER(HSP *sp) {
    static char *dockerPS[] = { HSF_DOCKER_CMD, "ps", "-q", "--no-trunc=true", NULL };
    char dockerLine[HSF_DOCKER_MAX_LINELEN];
    if(myExec(sp, dockerPS, dockerContainerCB, dockerLine, HSF_DOCKER_MAX_LINELEN, NULL)) {
      // successful, now gather data for each one
      UTStringArray *dockerInspect = strArrayNew();
      strArrayAdd(dockerInspect, HSF_DOCKER_CMD);
      strArrayAdd(dockerInspect, "inspect");
      HSPContainer *container;
      UTHASH_WALK(sp->containers, container) {
	// mark for removal, in case it is no longer current
	container->marked = YES;
	// and add id to command line
	strArrayAdd(dockerInspect, container->id);
      }
      strArrayAdd(dockerInspect, NULL);
      UTStrBuf *inspectBuf = UTStrBuf_new(1024);
      int inspectOK = myExec(inspectBuf,
			     strArray(dockerInspect),
			     dockerInspectCB,
			     dockerLine,
			     HSF_DOCKER_MAX_LINELEN,
			     NULL);
      strArrayFree(dockerInspect);
      char *ibuf = UTStrBuf_unwrap(inspectBuf);
      if(inspectOK) {
	// call was sucessful, so now we should have JSON to parse
	cJSON *jtop = cJSON_Parse(ibuf);
	if(jtop) {
	  // top-level should be array
	  int nc = cJSON_GetArraySize(jtop);
	  if(debug && nc != sp->containers->entries) {
	    // cross-check
	    myLog(LOG_INFO, "warning docker-ps returned %u containers but docker-inspect returned %u", sp->containers->entries, nc);
	  }
	  for(int ii = 0; ii < nc; ii++) {
	    cJSON *jcont = cJSON_GetArrayItem(jtop, ii);
	    if(jcont) {

	      cJSON *jid = cJSON_GetObjectItem(jcont, "Id");
	      if(jid) {
		if(my_strlen(jid->valuestring) >= HSF_DOCKER_SHORTID_LEN) {
		  HSPContainer *container = getContainer(sp, jid->valuestring, NO);
		  if(container) {
		    cJSON *jname = cJSON_GetObjectItem(jcont, "Name");
		    if(my_strequal(jname->valuestring, container->name) == NO) {
		      if(container->name) my_free(container->name);
		      container->name = my_strdup(jname->valuestring);
		    }
		    cJSON *jstate = cJSON_GetObjectItem(jcont, "State");
		    if(jstate) {
		      cJSON *jpid = cJSON_GetObjectItem(jstate, "Pid");
		      if(jpid) {
			container->pid = (pid_t)jpid->valueint;
		      }
		      cJSON *jrun = cJSON_GetObjectItem(jstate, "Running");
		      if(jrun) {
			container->running = (jrun->type == cJSON_True);
			if(container->running) {
			  // Clear the mark - this container is still current
			  container->marked = NO;
			}
		      }
		    }
		    cJSON *jconfig = cJSON_GetObjectItem(jcont, "Config");
		    if(jconfig) {
		      cJSON *jhn = cJSON_GetObjectItem(jconfig, "Hostname");
		      if(jhn) {
			if(container->hostname) my_free(container->hostname);
			container->hostname = my_strdup(jhn->valuestring);
		      }
		      // cJSON *jdn = cJSON_GetObjectItem(jconfig, "Domainname");
		      cJSON *jmem = cJSON_GetObjectItem(jconfig, "Memory");
		      if(jmem) {
			container->memoryLimit = (uint64_t)jmem->valuedouble;
		      }
		    }
		  }
		}
	      }
	    }
	  }
	  cJSON_Delete(jtop);
	}
      }
      my_free(ibuf);
    }
    
    HSPContainer *container;
    UTHASH_WALK(sp->containers, container) {
      if(container->marked) {
	if(debug) myLog(LOG_INFO, "delete container: %s=%s", container->name, container->id);
	if(UTHashDel(sp->containers, container) == NO)
	  myLog(LOG_ERR, "UTHashDel failed: container %s=%s", container->name, container->id);
	freeContainer(container);
      }
      else {
	// container still current
	HSPVMState *state = container->vm;
	if(state) {
	  // clear the mark so it survives
	  state->marked = NO;
	  // and reset the information that we are about to refresh
	  adaptorListMarkAll(state->interfaces);
	  // strArrayReset(state->volumes);
	  // strArrayReset(state->disks);
	  // then refresh it
	  readContainerInterfaces(sp, container);
	  // and clean up
	  deleteMarkedAdaptors_adaptorList(sp, state->interfaces);
	  adaptorListFreeMarked(state->interfaces);
	}
      }
      // we are using sp->num_domains as the portable field across Xen, KVM, Docker
      sp->num_domains = sp->containers->entries;
    }
  }

#endif /* HSF_DOCKER */
#if defined(__cplusplus)
} /* extern "C" */
#endif

