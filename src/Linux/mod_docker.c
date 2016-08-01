/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <sys/prctl.h>
#include <sched.h>

#include "hsflowd.h"
#include "cpu_utils.h"

  // limit the number of chars we will read from each line
  // in /proc/net/dev and /prov/net/vlan/config
  // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 160

#include "cJSON.h"


  typedef struct _HSPVMState_DOCKER {
    HSPVMState vm; // superclass: must come first
    char *id;
    char *name;
    char *hostname;
    pid_t pid;
    uint32_t running:1;
    uint32_t marked:1;
    uint64_t memoryLimit;
  } HSPVMState_DOCKER;
  
#define HSP_DOCKER_CMD "/usr/bin/docker"
#define HSP_NETNS_DIR "/var/run/netns"
#define HSP_IP_CMD "/usr/sbin/ip"
#define HSP_DOCKER_MAX_FNAME_LEN 255
#define HSP_DOCKER_MAX_LINELEN 512
#define HSP_DOCKER_SHORTID_LEN 12

  typedef struct _HSP_mod_DOCKER {
    UTHash *vmsByUUID;
    UTHash *vmsByID;
    UTArray *pollActions;
    SFLCounters_sample_element vnodeElem;
    int num_domains;
    uint32_t refreshVMListSecs;
    uint32_t forgetVMSecs;
  } HSP_mod_DOCKER;

#define HSP_DOCKER_MAX_STATS_LINELEN 512

  /*_________________---------------------------__________________
    _________________     readCgroupCounters    __________________
    -----------------___________________________------------------
  */
  
  static int readCgroupCounters(char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals, int multi) {
    int found = 0;

    char statsFileName[HSP_DOCKER_MAX_FNAME_LEN+1];
#ifdef HSP_SYSTEM_SLICE
    snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, "/sys/fs/cgroup/%s/system.slice/docker-%s.scope/%s",
	     cgroup,
	     longId,
	     fname);
#else
    snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, "/sys/fs/cgroup/%s/docker/%s/%s",
	     cgroup,
	     longId,
	     fname);
#endif
    FILE *statsFile = fopen(statsFileName, "r");
    if(statsFile == NULL) {
      myDebug(2, "cannot open %s : %s", statsFileName, strerror(errno));
    }
    else {
      char line[HSP_DOCKER_MAX_STATS_LINELEN];
      char var[HSP_DOCKER_MAX_STATS_LINELEN];
      uint64_t val64;
      char *fmt = multi ?
	"%*s %s %"SCNu64 :
	"%s %"SCNu64 ;
      while(fgets(line, HSP_DOCKER_MAX_STATS_LINELEN, statsFile)) {
	if(found == nvals && !multi) break;
	if(sscanf(line, fmt, var, &val64) == 2) {
	  for(int ii = 0; ii < nvals; ii++) {
	    char *nm = nameVals[ii].nv_name;
	    if(nm == NULL) break; // null name is double-check
	    if(strcmp(var, nm) == 0)  {
	      nameVals[ii].nv_found = YES;
	      nameVals[ii].nv_val64 += val64;
	      found++;
	    }
	  }
        }
      }
      fclose(statsFile);
    }
    return (found > 0);
  }

  /*_________________---------------------------__________________
    _________________  readContainerCounters    __________________
    -----------------___________________________------------------
  */
  
  static int readContainerCounters(char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals) {
    return readCgroupCounters(cgroup, longId, fname, nvals, nameVals, 0);
  }

  /*_________________-----------------------------__________________
    _________________  readContainerCountersMulti __________________
    -----------------_____________________________------------------
    Variant where the stats file has per-device numbers that need to be summed.
    The device id is assumed to be the first space-separated token on each line.
*/
  
  static int readContainerCountersMulti(char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals) {
    return readCgroupCounters(cgroup, longId, fname, nvals, nameVals, 1);
  }

/*________________---------------------------__________________
  ________________   containerLinkCB         __________________
  ----------------___________________________------------------
  
expecting lines of the form:
VNIC: <ifindex> <device> <mac>
*/

  static int containerLinkCB(HSP *sp, HSPVMState_DOCKER *container, char *line) {
    myDebug(1, "containerLinkCB: line=<%s>", line);
    char deviceName[HSP_DOCKER_MAX_LINELEN];
    char macStr[HSP_DOCKER_MAX_LINELEN];
    uint32_t ifIndex;
    if(sscanf(line, "VNIC: %u %s %s", &ifIndex, deviceName, macStr) == 3) {
      u_char mac[6];
      if(hexToBinary((u_char *)macStr, mac, 6) == 6) {
	SFLAdaptor *adaptor = adaptorListGet(container->vm.interfaces, deviceName);
	if(adaptor == NULL) {
	  adaptor = nioAdaptorNew(deviceName, mac, ifIndex);
	  adaptorListAdd(container->vm.interfaces, adaptor);
	  // add to "all namespaces" collections too
	  if(UTHashAdd(sp->adaptorsByMac, adaptor) != NULL) {
	    myDebug(1, "Warning: container adaptor overwriting adaptorsByMac");
	  }
	  if(UTHashAdd(sp->adaptorsByIndex, adaptor) != NULL) {
	    myDebug(1, "Warning: container adaptor overwriting adaptorsByIndex");
	  }
	  // mark it as a vm/container device
	  ADAPTOR_NIO(adaptor)->vm_or_container = YES;
	}
	// clear the mark so we don't free it below
	adaptor->marked = NO;
      }
    }
    return YES;
  }

/*________________---------------------------__________________
  ________________   readContainerInterfaces __________________
  ----------------___________________________------------------
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

  int readContainerInterfaces(HSP *sp, HSPVMState_DOCKER *container)  {
    pid_t nspid = container->pid;
    myDebug(2, "readContainerInterfaces: pid=%u", nspid);
    if(nspid == 0) return 0;

    // do the dirty work after a fork, so we can just exit afterwards,
    // same as they do in "ip netns exec"
    int pfd[2];
    if(pipe(pfd) == -1) {
      myLog(LOG_ERR, "pipe() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    pid_t cpid;
    if((cpid = fork()) == -1) {
      myLog(LOG_ERR, "fork() failed : %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(cpid == 0) {
      // in child
      close(pfd[0]);   // close read-end
      dup2(pfd[1], 1); // stdout -> write-end
      dup2(pfd[1], 2); // stderr -> write-end
      close(pfd[1]);
      
      // open /proc/<nspid>/ns/net
      char topath[HSP_DOCKER_MAX_FNAME_LEN+1];
      snprintf(topath, HSP_DOCKER_MAX_FNAME_LEN, "/proc/%u/ns/net", nspid);
      int nsfd = open(topath, O_RDONLY | O_CLOEXEC);
      if(nsfd < 0) {
	fprintf(stderr, "cannot open %s : %s", topath, strerror(errno));
	exit(EXIT_FAILURE);
      }
      
      /* set network namespace
	 CLONE_NEWNET means nsfd must refer to a network namespace
      */
      if(MY_SETNS(nsfd, CLONE_NEWNET) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      
      /* From "man 2 unshare":  This flag has the same effect as the clone(2)
	 CLONE_NEWNS flag. Unshare the mount namespace, so that the calling
	 process has a private copy of its namespace which is not shared with
	 any other process. Specifying this flag automatically implies CLONE_FS
	 as well. Use of CLONE_NEWNS requires the CAP_SYS_ADMIN capability. */
      if(unshare(CLONE_NEWNS) < 0) {
	fprintf(stderr, "seting network namespace failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

      int fd = socket(PF_INET, SOCK_DGRAM, 0);
      if(fd < 0) {
	fprintf(stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
	return 0;
      }

      FILE *procFile = fopen("/proc/net/dev", "r");
      if(procFile) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	char line[MAX_PROC_LINE_CHARS];
	int lineNo = 0;
	while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	  if(lineNo++ < 2) continue; // skip headers
	  char buf[MAX_PROC_LINE_CHARS];
	  char *p = line;
	  char *devName = parseNextTok(&p, " \t:", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	  if(devName && my_strlen(devName) < IFNAMSIZ) {
	    strncpy(ifr.ifr_name, devName, sizeof(ifr.ifr_name));
	    // Get the flags for this interface
	    if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	      fprintf(stderr, "container device %s Get SIOCGIFFLAGS failed : %s",
		      devName,
		      strerror(errno));
	    }
	    else {
	      int up = (ifr.ifr_flags & IFF_UP) ? YES : NO;
	      int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? YES : NO;

	      if(up && !loopback) {
		// try to get ifIndex next, because we only care about
		// ifIndex and MAC when looking at container interfaces
		if(ioctl(fd,SIOCGIFINDEX, &ifr) < 0) {
		  // only complain about this if we are debugging
		  myDebug(1, "container device %s Get SIOCGIFINDEX failed : %s",
			  devName,
			  strerror(errno));
		}
		else {
		  int ifIndex = ifr.ifr_ifindex;
		  
		  // Get the MAC Address for this interface
		  if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
		    myDebug(1, "device %s Get SIOCGIFHWADDR failed : %s",
			      devName,
			      strerror(errno));
		  }
		  else {
		    u_char macStr[13];
		    printHex((u_char *)&ifr.ifr_hwaddr.sa_data, 6, macStr, 12, NO);
		    // send this info back up the pipe to my my parent
		    printf("VNIC: %u %s %s\n", ifIndex, devName, macStr);
		  }
		}
	      }
	    }
	  }
	}
      }

      // don't even bother to close file-descriptors,  just bail
      exit(0);
      
    }
    else {
      // in parent
      close(pfd[1]); // close write-end
      // read from read-end
      FILE *ovs;
      if((ovs = fdopen(pfd[0], "r")) == NULL) {
	myLog(LOG_ERR, "readContainerInterfaces: fdopen() failed : %s", strerror(errno));
	return 0;
      }
      char line[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, ovs)) containerLinkCB(sp, container, line);
      fclose(ovs);
      wait(NULL); // block here until child is done
    }

    return container->vm.interfaces->num_adaptors;
  }


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

  static void agentCB_getCounters_DOCKER(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    EVMod *mod = (EVMod *)magic;
    // HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    HSPVMState_DOCKER *container = (HSPVMState_DOCKER *)poller->userData;
    HSPVMState *vm = (HSPVMState *)&container->vm;
    
    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char *hname = my_strnequal(container->hostname, container->id, HSP_DOCKER_SHORTID_LEN) ? container->name : container->hostname;
    hidElem.counterBlock.host_hid.hostname.str = hname;
    hidElem.counterBlock.host_hid.hostname.len = my_strlen(hname);
    memcpy(hidElem.counterBlock.host_hid.uuid, vm->uuid, 16);
 
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
    if(getContainerPeerAdaptors(sp, vm, &peerAdaptors, HSP_MAX_VIFS) > 0) {
      readNioCounters(sp, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio, NULL, &peerAdaptors);
      SFLADD_ELEMENT(cs, &nioElem);
    }
      
    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    HSPNameVal cpuVals[] = {
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
    HSPNameVal memVals[] = {
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
	if(getDebug()
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
    HSPNameVal dskValsB[] = {
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
    
    HSPNameVal dskValsO[] = {
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
    adaptorsElem.counterBlock.adaptors = vm->interfaces;
    SFLADD_ELEMENT(cs, &adaptorsElem);
    SEMLOCK_DO(sp->sync_agent) {
      sfl_poller_writeCountersSample(poller, cs);
    }
  }

  static void agentCB_getCounters_DOCKER_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    EVMod *mod = (EVMod *)poller->magic;
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    UTArrayAdd(mdata->pollActions, poller);
  }
  
  /*_________________---------------------------__________________
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  static void removeAndFreeVM_DOCKER(EVMod *mod, HSPVMState_DOCKER *container) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(getDebug()) {
      myLog(LOG_INFO, "removeAndFreeVM: removing container with dsIndex=%u", container->vm.dsIndex);
    }
    if(container->id) my_free(container->id);
    if(container->name) my_free(container->name);
    if(container->hostname) my_free(container->hostname);
    UTHashDel(mdata->vmsByUUID, container);
    UTHashDel(mdata->vmsByID, container);
    removeAndFreeVM(mod, &container->vm);
  }
  
  static HSPVMState_DOCKER *getContainer(EVMod *mod, char *id, int create) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(id == NULL) return NULL;
    HSPVMState_DOCKER cont = { .id = id };
    HSPVMState_DOCKER *container = UTHashGet(mdata->vmsByID, &cont);
    if(container == NULL
       && create) {
      char uuid[16];
      // turn container ID into a UUID - just take the first 16 bytes of the id
      parseUUID(id, uuid);
      container = (HSPVMState_DOCKER *)getVM(mod, uuid, YES, sizeof(HSPVMState_DOCKER), VMTYPE_DOCKER, agentCB_getCounters_DOCKER_request);
      if(container) {
	container->id = my_strdup(id);
	// add to collections
	UTHashAdd(mdata->vmsByID, container);
	UTHashAdd(mdata->vmsByUUID, container);
      }
    }
    return container;
  }
 
  static int dockerInspectCB(void *magic, char *line) {
    // just append it to the string-buffer
    UTStrBuf *inspectBuf = (UTStrBuf *)magic;
    UTStrBuf_append(inspectBuf, line);
    return YES;
  }

  static void dockerInspectVMs(EVMod *mod) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    char dockerLine[HSP_DOCKER_MAX_LINELEN];
    UTStringArray *dockerInspect = strArrayNew();
    strArrayAdd(dockerInspect, HSP_DOCKER_CMD);
    strArrayAdd(dockerInspect, "inspect");
    HSPVMState_DOCKER *container;
    UTHASH_WALK(mdata->vmsByID, container) {
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
			   HSP_DOCKER_MAX_LINELEN,
			   NULL);
    strArrayFree(dockerInspect);
    char *ibuf = UTStrBuf_unwrap(inspectBuf);
    if(inspectOK) {
      // call was sucessful, so now we should have JSON to parse
      cJSON *jtop = cJSON_Parse(ibuf);
      if(jtop) {
	// top-level should be array
	int nc = cJSON_GetArraySize(jtop);
	if(getDebug() && nc != UTHashN(mdata->vmsByID)) {
	  // cross-check
	  myLog(LOG_INFO, "warning docker-ps returned %u containers but docker-inspect returned %u",
		UTHashN(mdata->vmsByID),
		nc);
	}
	for(int ii = 0; ii < nc; ii++) {
	  cJSON *jcont = cJSON_GetArrayItem(jtop, ii);
	  if(jcont) {

	    cJSON *jid = cJSON_GetObjectItem(jcont, "Id");
	    if(jid) {
	      if(my_strlen(jid->valuestring) >= HSP_DOCKER_SHORTID_LEN) {
		HSPVMState_DOCKER *container = getContainer(mod, jid->valuestring, NO);
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

  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */

  static int dockerContainerCB(void *magic, char *line) {
    UTStringArray *strArray = (UTStringArray *)magic;
    strArrayAdd(strArray, line);
    return YES;
  }

  void configVMs_DOCKER(EVMod *mod) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    static char *dockerPS[] = { HSP_DOCKER_CMD, "ps", "-q", "--no-trunc=true", NULL };
    char dockerLine[HSP_DOCKER_MAX_LINELEN];
    UTStringArray *dockerLines = strArrayNew();
    if(myExec(dockerLines, dockerPS, dockerContainerCB, dockerLine, HSP_DOCKER_MAX_LINELEN, NULL)) {
      // successful - instantiate containers
      for(int ii = 0; ii < strArrayN(dockerLines); ii++) {
	char id[HSP_DOCKER_MAX_LINELEN];
	if(sscanf(strArrayAt(dockerLines, ii), "%s\n", id) == 1) {
	  getContainer(mod, id, YES);
	}
      }
      // gather data for each one
      if(UTHashN(mdata->vmsByID))
	dockerInspectVMs(mod);
    }
    strArrayFree(dockerLines);
    dockerLines = NULL;

    HSPVMState_DOCKER *container;
    UTHASH_WALK(mdata->vmsByID, container) {
      if(container->marked) {
	myDebug(1, "delete container: %s=%s", container->name, container->id);
	if(UTHashDel(mdata->vmsByID, container) == NO)
	  myLog(LOG_ERR, "UTHashDel failed: container %s=%s", container->name, container->id);
	removeAndFreeVM_DOCKER(mod, container);
      }
      else {
	// container still current
	HSPVMState *vm = &container->vm;
	if(vm) {
	  // clear the mark so it survives
	  vm->marked = NO;
	  // and reset the information that we are about to refresh
	  adaptorListMarkAll(vm->interfaces);
	  // strArrayReset(vm->volumes);
	  // strArrayReset(vm->disks);
	  // then refresh it
	  readContainerInterfaces(sp, container);
	  // and clean up
	  deleteMarkedAdaptors_adaptorList(sp, vm->interfaces);
	  adaptorListFreeMarked(vm->interfaces);
	}
      }
      mdata->num_domains = UTHashN(mdata->vmsByID);
    }
  }


  /*_________________---------------------------__________________
    _________________    configVMs              __________________
    -----------------___________________________------------------
  */
  
  static void configVMs(EVMod *mod) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    // mark and sweep
    // 1. mark all the current virtual pollers
    HSPVMState_DOCKER *container;
    UTHASH_WALK(mdata->vmsByUUID, container) {
      container->vm.marked = YES;
    }
    
    // 2. create new VM pollers, or clear the mark on existing ones
    configVMs_DOCKER(mod);

    // 3. remove any VMs (and their pollers) that don't survive
    UTHASH_WALK(mdata->vmsByUUID, container) {
      if(container->vm.marked) {
	removeAndFreeVM(mod, &container->vm);
      }
    }
  }

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if((evt->bus->clk % mdata->refreshVMListSecs) == 0
       && sp->sFlowSettings) {
      configVMs(mod);
    }
  }

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    // now we can execute pollActions without holding on to the semaphore
    for(uint32_t ii = 0; ii < UTArrayN(mdata->pollActions); ii++) {
      SFLPoller *poller = (SFLPoller *)UTArrayAt(mdata->pollActions, ii);
      SFL_COUNTERS_SAMPLE_TYPE cs;
      memset(&cs, 0, sizeof(cs));
      agentCB_getCounters_DOCKER((void *)mod, poller, &cs);
    }
    UTArrayReset(mdata->pollActions);
  }

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = (SFL_COUNTERS_SAMPLE_TYPE *)data;
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->kvm.kvm) {
      // if we make kvm and docker mutually exclusive, this check will be unnecessary
      return;
    }
      
    memset(&mdata->vnodeElem, 0, sizeof(mdata->vnodeElem));
    mdata->vnodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
    mdata->vnodeElem.counterBlock.host_vrt_node.mhz = sp->cpu_mhz;
    mdata->vnodeElem.counterBlock.host_vrt_node.cpus = sp->cpu_cores;
    mdata->vnodeElem.counterBlock.host_vrt_node.num_domains = mdata->num_domains;
    mdata->vnodeElem.counterBlock.host_vrt_node.memory = sp->mem_total;
    mdata->vnodeElem.counterBlock.host_vrt_node.memory_free = sp->mem_free;
    SFLADD_ELEMENT(cs, &mdata->vnodeElem);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_docker(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_DOCKER));
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    mdata->vmsByUUID = UTHASH_NEW(HSPVMState_DOCKER, vm.uuid, UTHASH_DFLT);
    mdata->vmsByID = UTHASH_NEW(HSPVMState_DOCKER, id, YES);
    mdata->pollActions = UTArrayNew(UTARRAY_DFLT);
    mdata->refreshVMListSecs = sp->docker.refreshVMListSecs ?: sp->refreshVMListSecs;
    mdata->forgetVMSecs = sp->docker.forgetVMSecs ?: sp->forgetVMSecs;

    // register call-backs
    EVBus *pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TOCK), evt_tock);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

