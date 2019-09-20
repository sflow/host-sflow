/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/types.h>
#include <sys/prctl.h>
#include <sched.h>

#include "hsflowd.h"
#include "cpu_utils.h"
#include "math.h"

  // limit the number of chars we will read from each line
  // in /proc/net/dev and /prov/net/vlan/config
  // (there can be more than this - my_readline will chop for us)
#define MAX_PROC_LINE_CHARS 320

#include "cJSON.h"

  typedef enum {
    HSP_EV_UNKNOWN=0,
    HSP_EV_create,
    HSP_EV_start,
    HSP_EV_stop,
    HSP_EV_restart,
    HSP_EV_pause,
    HSP_EV_unpause,
    HSP_EV_kill,
    HSP_EV_die,
    HSP_EV_destroy,
    HSP_EV_oom,
    HSP_EV_rm,
    HSP_EV_attach,
    HSP_EV_commit,
    HSP_EV_copy,
    HSP_EV_detach,
    HSP_EV_exec_create,
    HSP_EV_exec_detach,
    HSP_EV_exec_start,
    HSP_EV_export,
    HSP_EV_health_status,
    HSP_EV_rename,
    HSP_EV_resize,
    HSP_EV_top,
    HSP_EV_update,
    HSP_EV_NUM_CODES
  } EnumHSPContainerEvent;

  static const char *HSP_EV_names[] = {
    "unknown",
    "create",
    "start",
    "stop",
    "restart",
    "pause",
    "unpause",
    "kill",
    "die",
    "destroy",
    "oom",
    "rm", // taken out
    "attach", // added for 1.24 vvv
    "commit",
    "copy",
    "detach",
    "exec_create",
    "exec_detach",
    "exec_start",
    "export",
    "health_status",
    "rename",
    "resize",
    "top",
    "update"
  };

  typedef enum {
    HSP_CS_UNKNOWN=0,
    HSP_CS_created,
    HSP_CS_running,
    HSP_CS_paused,
    HSP_CS_stopped,
    HSP_CS_deleted,
    HSP_CS_exited,
    HSP_CS_NUM_CODES
  } EnumHSPContainerState;

  static const char *HSP_CS_names[] = {
    "unknown",
    "created",
    "running",
    "paused",
    "stopped",
    "deleted",
    "exited",
  };

  typedef struct _HSPVMState_DOCKER {
    HSPVMState vm; // superclass: must come first
    char *id;
    char *name;
    char *hostname;
    pid_t pid;
    EnumHSPContainerEvent lastEvent;
    EnumHSPContainerState state;
    uint32_t inspect_tx:1;
    uint32_t inspect_rx:1;
    uint32_t stats_tx:1;
    uint32_t stats_rx:1;
    uint32_t dup_name:1;
    uint32_t dup_hostname:1;
    uint64_t memoryLimit;
    // we now populate stats here too
    uint32_t cpu_count;
    double cpu_count_dbl;
    uint64_t cpu_total;
    uint64_t mem_usage;
    SFLHost_nio_counters net;
    SFLHost_vrt_dsk_counters dsk;
  } HSPVMState_DOCKER;

  struct _HSPDockerRequest; // fwd decl
  typedef void (*HSPDockerCB)(EVMod *mod, UTStrBuf *buf, cJSON *obj, struct _HSPDockerRequest *req);

  typedef enum {
    HSPDOCKERREQ_HEADERS=0,
    HSPDOCKERREQ_LENGTH,
    HSPDOCKERREQ_CONTENT,
    HSPDOCKERREQ_ENDCONTENT,
    HSPDOCKERREQ_ERR
  } HSPDockerRequestState;
    
  typedef struct _HSPDockerRequest {
    struct _HSPDockerRequest *prev;
    struct _HSPDockerRequest *next;
    UTStrBuf *request;
    UTStrBuf *response;
    HSPDockerCB jsonCB;
    bool eventFeed:1;
    HSPDockerRequestState state;
    int contentLength;
    int chunkLength;
    char *id;
  } HSPDockerRequest;

  typedef struct _HSPDockerNameCount {
    char *name;
    uint32_t count;
  } HSPDockerNameCount;

#define HSP_DOCKER_SOCK  VARFS_STR "/run/docker.sock"
#define HSP_DOCKER_MAX_CONCURRENT 3
#define HSP_DOCKER_HTTP " HTTP/1.1\nHost: " HSP_DOCKER_SOCK "\n\n"
#define HSP_DOCKER_API "v1.24"
#define HSP_DOCKER_REQ_EVENTS "GET /" HSP_DOCKER_API "/events?filters={\"type\":[\"container\"]}" HSP_DOCKER_HTTP
#define HSP_DOCKER_REQ_CONTAINERS "GET /" HSP_DOCKER_API "/containers/json" HSP_DOCKER_HTTP
#define HSP_DOCKER_REQ_INSPECT_ID "GET /" HSP_DOCKER_API "/containers/%s/json" HSP_DOCKER_HTTP
#define HSP_DOCKER_REQ_STATS_ID "GET /" HSP_DOCKER_API "/containers/%s/stats?stream=false" HSP_DOCKER_HTTP
#define HSP_CONTENT_LENGTH_REGEX "^Content-Length: ([0-9]+)$"
  
#define HSP_DOCKER_MAX_FNAME_LEN 255
#define HSP_DOCKER_MAX_LINELEN 512
#define HSP_DOCKER_SHORTID_LEN 12

#define HSP_DOCKER_WAIT_NOSOCKET 10
#define HSP_DOCKER_WAIT_EVENTDROP 5
#define HSP_DOCKER_WAIT_STARTUP 2
  
  typedef struct _HSP_mod_DOCKER {
    EVBus *pollBus;
    UTHash *vmsByUUID;
    UTHash *vmsByID;
    UTHash *pollActions;
    SFLCounters_sample_element vnodeElem;
    bool dockerSync:1;
    bool dockerFlush:1;
    UTArray *eventQueue;
    UTQ(HSPDockerRequest) requestQ;
    uint32_t currentRequests;
    regex_t *contentLengthPattern;
    uint32_t countdownToResync;
    int cgroupPathIdx;
    UTHash *nameCount;
    UTHash *hostnameCount;
    uint32_t dup_names;
    uint32_t dup_hostnames;
  } HSP_mod_DOCKER;

#define HSP_DOCKER_MAX_STATS_LINELEN 512

  static void dockerAPIRequest(EVMod *mod, HSPDockerRequest *req);
  static HSPDockerRequest *dockerRequest(EVMod *mod, UTStrBuf *cmd, HSPDockerCB jsonCB, bool eventFeed);
  static void  dockerRequestFree(EVMod *mod, HSPDockerRequest *req);
  static void dockerSynchronize(EVMod *mod);
  static void decNameCount(UTHash *ht, const char *str);
  static void getContainerStats(EVMod *mod, HSPVMState_DOCKER *container);

  /*_________________---------------------------__________________
    _________________    utils to help debug    __________________
    -----------------___________________________------------------
  */

  char *containerStr(HSPVMState_DOCKER *container, char *buf, int bufLen) {
    u_char uuidstr[100];
    printUUID((u_char *)container->vm.uuid, uuidstr, 100);
    snprintf(buf, bufLen, "name: %s hostname: %s uuid: %s id: %s",
	     container->name,
	     container->hostname,
	     container->vm.uuid,
	     container->id);
    return buf;
  }

  void containerHTPrint(UTHash *ht, char *prefix) {
    char buf[1024];
    HSPVMState_DOCKER *container;
    UTHASH_WALK(ht, container)
      myLog(LOG_INFO, "%s: %s", prefix, containerStr(container, buf, 1024));
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
	  // add to "all namespaces" collections too - but only the ones where
	  // the id is really global.  For example,  many containers can have
	  // an "eth0" adaptor so we can't add it to sp->adaptorsByName.

	  // And because the containers are likely to be ephemeral, don't
	  // replace the global adaptor if it's already there.

	  if(UTHashGet(sp->adaptorsByMac, adaptor) == NULL)
	    if(UTHashAdd(sp->adaptorsByMac, adaptor) != NULL)
	      myDebug(1, "Warning: container adaptor overwriting adaptorsByMac");

	  if(UTHashGet(sp->adaptorsByIndex, adaptor) == NULL)
	    if(UTHashAdd(sp->adaptorsByIndex, adaptor) != NULL)
	      myDebug(1, "Warning: container adaptor overwriting adaptorsByIndex");

	  // mark it as a vm/container device
	  ADAPTOR_NIO(adaptor)->vm_or_container = YES;
	}
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

  int readContainerInterfaces(EVMod *mod, HSPVMState_DOCKER *container)  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
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
      snprintf(topath, HSP_DOCKER_MAX_FNAME_LEN, PROCFS_STR "/%u/ns/net", nspid);
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

      FILE *procFile = fopen(PROCFS_STR "/net/dev", "r");
      if(procFile) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	char line[MAX_PROC_LINE_CHARS];
	int lineNo = 0;
	int truncated;
	while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	  if(lineNo++ < 2) continue; // skip headers
	  char buf[MAX_PROC_LINE_CHARS];
	  char *p = line;
	  char *devName = parseNextTok(&p, " \t:", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	  if(devName && my_strlen(devName) < IFNAMSIZ) {
	    strncpy(ifr.ifr_name, devName, sizeof(ifr.ifr_name)-1);
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
      int truncated;
      while(my_readline(ovs, line, MAX_PROC_LINE_CHARS, &truncated) != EOF)
	containerLinkCB(sp, container, line);
      fclose(ovs);
      wait(NULL); // block here until child is done
    }

    return container->vm.interfaces->num_adaptors;
  }

  /*________________---------------------------__________________
    ________________   getCounters_DOCKER      __________________
    ----------------___________________________------------------
  */
  static void getCounters_DOCKER(EVMod *mod, HSPVMState_DOCKER *container)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFL_COUNTERS_SAMPLE_TYPE cs = { 0 };
    HSPVMState *vm = (HSPVMState *)&container->vm;

    if(sp->sFlowSettings == NULL) {
      // do nothing if we haven't settled on the config yet
      return;
    }

    // host ID
    char nameBuf[SFL_MAX_HOSTNAME_CHARS+1];
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char *hname = NULL;
    bool duplicate = NO;
    if(sp->docker.hostname) {
      hname = container->hostname;
      duplicate = container->dup_hostname;
    }
    else {
      hname = container->name;
      duplicate = container->dup_name;
    }
    if(duplicate) {
      // not unique - use <hname>.<short-id> instead
      snprintf(nameBuf, SFL_MAX_HOSTNAME_CHARS, "%s.%s", hname, container->id);
      // chop after short-id chars
      int len2 = strlen(hname) + 1 + HSP_DOCKER_SHORTID_LEN;
      if(len2 > SFL_MAX_HOSTNAME_CHARS)
	len2 = SFL_MAX_HOSTNAME_CHARS;
      nameBuf[len2] = '\0';
      hname = nameBuf;
    }
    hidElem.counterBlock.host_hid.hostname.str = hname;
    hidElem.counterBlock.host_hid.hostname.len = my_strlen(hname);
    memcpy(hidElem.counterBlock.host_hid.uuid, vm->uuid, 16);

    // for containers we can show the same OS attributes as the parent
    hidElem.counterBlock.host_hid.machine_type = sp->machine_type;
    hidElem.counterBlock.host_hid.os_name = SFLOS_linux;
    hidElem.counterBlock.host_hid.os_release.str = sp->os_release;
    hidElem.counterBlock.host_hid.os_release.len = my_strlen(sp->os_release);
    SFLADD_ELEMENT(&cs, &hidElem);

    // host parent
    SFLCounters_sample_element parElem = { 0 };
    parElem.tag = SFLCOUNTERS_HOST_PAR;
    parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
    parElem.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
    SFLADD_ELEMENT(&cs, &parElem);

    // VM Net I/O
    SFLCounters_sample_element nioElem = { 0 };
    nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
    memcpy(&nioElem.counterBlock.host_vrt_nio, &container->net, sizeof(container->net));
    SFLADD_ELEMENT(&cs, &nioElem);

    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    // map container->state into SFLVirDomainState
    enum SFLVirDomainState virState = SFL_VIR_DOMAIN_NOSTATE;
    switch(container->state) {
    case HSP_CS_running:
      virState = SFL_VIR_DOMAIN_RUNNING;
      break;
    case HSP_CS_created:
      virState = SFL_VIR_DOMAIN_NOSTATE;
      break;
    case HSP_CS_paused:
      virState = SFL_VIR_DOMAIN_PAUSED;
      break;
    case HSP_CS_stopped:
      virState = SFL_VIR_DOMAIN_SHUTOFF;
      break;
    case HSP_CS_deleted:
    case HSP_CS_exited:
      virState = SFL_VIR_DOMAIN_SHUTDOWN;
      break;
    case HSP_EV_UNKNOWN:
    default:
      break;
    }
    cpuElem.counterBlock.host_vrt_cpu.state = virState;
    cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = container->cpu_count ?: (uint32_t)round(container->cpu_count_dbl);
    cpuElem.counterBlock.host_vrt_cpu.cpuTime = (uint32_t)(container->cpu_total / 1000000); // convert to mS
    SFLADD_ELEMENT(&cs, &cpuElem);

    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
    memElem.counterBlock.host_vrt_mem.memory = container->mem_usage;
    memElem.counterBlock.host_vrt_mem.maxMemory = container->memoryLimit;
    SFLADD_ELEMENT(&cs, &memElem);

    // VM disk I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
    // TODO: fill in capacity, allocation, available fields
    memcpy(&dskElem.counterBlock.host_vrt_dsk, &container->dsk, sizeof(container->dsk));
    SFLADD_ELEMENT(&cs, &dskElem);

    // include my slice of the adaptor list (the ones from my private namespace)
    SFLCounters_sample_element adaptorsElem = { 0 };
    adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
    adaptorsElem.counterBlock.adaptors = vm->interfaces;
    SFLADD_ELEMENT(&cs, &adaptorsElem);
    SEMLOCK_DO(sp->sync_agent) {
      sfl_poller_writeCountersSample(vm->poller, &cs);
      sp->counterSampleQueued = YES;
      sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES]++;
    }
  }

  static void agentCB_getCounters_DOCKER_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSPVMState_DOCKER *container = (HSPVMState_DOCKER *)poller->userData;
    UTHashAdd(mdata->pollActions, container);
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

    if(UTHashDel(mdata->vmsByID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (vmsByID) failed: container %s=%s", container->name, container->id);
      if(debug(1))
	containerHTPrint(mdata->vmsByID, "vmsByID");
    }

    if(UTHashDel(mdata->vmsByUUID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (vmsByUUID) failed: container %s=%s", container->name, container->id);
      if(debug(1))
	containerHTPrint(mdata->vmsByUUID, "vmsByUUID");
    }

    if(container->id) my_free(container->id);
    if(container->name) {
      decNameCount(mdata->nameCount, container->name);
      my_free(container->name);
    }
    if(container->hostname) {
      decNameCount(mdata->hostnameCount, container->hostname);
      my_free(container->hostname);
    }
    if(container->dup_name) mdata->dup_names--;
    if(container->dup_hostname) mdata->dup_hostnames--;
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
      if(parseUUID(id, uuid) == NO) {
	myLog(LOG_ERR, " parsing container UUID from <%s>", id);
	abort();
      }
      container = (HSPVMState_DOCKER *)getVM(mod, uuid, YES, sizeof(HSPVMState_DOCKER), VMTYPE_DOCKER, agentCB_getCounters_DOCKER_request);
      assert(container != NULL);
      if(container) {
	container->id = my_strdup(id);
	// add to collections
	UTHashAdd(mdata->vmsByID, container);
	UTHashAdd(mdata->vmsByUUID, container);
      }
    }
    return container;
  }

  /*_________________---------------------------__________________
    _________________  updateContainerAdaptors  __________________
    -----------------___________________________------------------
  */

  static void updateContainerAdaptors(EVMod *mod, HSPVMState_DOCKER *container) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPVMState *vm = &container->vm;
    if(vm) {
      // reset the information that we are about to refresh
      adaptorListMarkAll(vm->interfaces);
      // then refresh it
      readContainerInterfaces(mod, container);
      // and clean up
      deleteMarkedAdaptors_adaptorList(sp, vm->interfaces);
      adaptorListFreeMarked(vm->interfaces);
    }
  }

  /*_________________---------------------------__________________
    _________________    tick,tock              __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(mdata->countdownToResync) {
      myDebug(1, "docker resync in %u", mdata->countdownToResync);
      if(--mdata->countdownToResync == 0)
	dockerSynchronize(mod);
    }
  }

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    // now we can execute pollActions without holding on to the semaphore.
    // But each pollAction now needs another step while we request and wait
    // for the container stats query.  So now we initiate the stats query
    // here and finally call getCounters_DOCKER when we have the answer.
    HSPVMState_DOCKER *container;
    UTHASH_WALK(mdata->pollActions, container) {
      // getCounters_DOCKER(mod, container);
      getContainerStats(mod, container);
    }
    UTHashReset(mdata->pollActions);
  }

  /*_________________---------------------------__________________
    _________________   host counter sample     __________________
    -----------------___________________________------------------
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(!hasVNodeRole(mod, HSP_VNODE_PRIORITY_DOCKER))
      return;

    memset(&mdata->vnodeElem, 0, sizeof(mdata->vnodeElem));
    mdata->vnodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
    mdata->vnodeElem.counterBlock.host_vrt_node.mhz = sp->cpu_mhz;
    mdata->vnodeElem.counterBlock.host_vrt_node.cpus = sp->cpu_cores;
    mdata->vnodeElem.counterBlock.host_vrt_node.num_domains = UTHashN(mdata->vmsByID);
    mdata->vnodeElem.counterBlock.host_vrt_node.memory = sp->mem_total;
    mdata->vnodeElem.counterBlock.host_vrt_node.memory_free = sp->mem_free;
    SFLADD_ELEMENT(cs, &mdata->vnodeElem);
  }


  /*_________________---------------------------__________________
    _________________    openDockerSocket       __________________
    -----------------___________________________------------------
  */

  static EnumHSPContainerEvent containerEvent(char *str) {
    for(int ii = 0; ii<HSP_EV_NUM_CODES; ii++) {
      if(str && !strcasecmp(str, HSP_EV_names[ii]))
	return ii;
    }
    return HSP_EV_UNKNOWN;
  }
  
  static EnumHSPContainerState containerState(char *str) {
    for(int ii = 0; ii<HSP_CS_NUM_CODES; ii++) {
      if(str && !strcasecmp(str, HSP_CS_names[ii]))
	return ii;
    }
    return HSP_CS_UNKNOWN;
  }

  static void duplicateName(EVMod *mod, HSPVMState_DOCKER *container) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(!container->dup_name) {
      container->dup_name = YES;
      mdata->dup_names++;
    }
  }

  static void duplicateHostname(EVMod *mod, HSPVMState_DOCKER *container) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(!container->dup_hostname) {
      container->dup_hostname = YES;
      mdata->dup_hostnames++;
    }
  }

  static uint32_t incNameCount(UTHash *ht, const char *str) {
    HSPDockerNameCount search = { .name = (char *)str };
    HSPDockerNameCount *nc = UTHashGet(ht, &search);
    if(nc == NULL) {
      nc = (HSPDockerNameCount *)my_calloc(sizeof(HSPDockerNameCount));
      nc->name = my_strdup(str);
      UTHashAdd(ht, nc);
    }
    return ++nc->count;
  }

  static void decNameCount(UTHash *ht, const char *str) {
    HSPDockerNameCount search = { .name = (char *)str };
    HSPDockerNameCount *nc = UTHashGet(ht, &search);
    if(nc) {
      if(--nc->count == 0) {
	UTHashDel(ht, nc);
	my_free(nc->name);
	my_free(nc);
      }
    }
  }

  static void setContainerName(EVMod *mod, HSPVMState_DOCKER *container, const char *name) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    char *str = (char *)name;
    if(str && str[0] == '/') str++; // consume leading '/'
    if(my_strequal(str, container->name) == NO) {
      if(container->name) {
	decNameCount(mdata->nameCount, container->name);
	my_free(container->name);
      }
      container->name = my_strdup(str);
      if(incNameCount(mdata->nameCount, str) > 1) {
	duplicateName(mod,container);
      }
    }
  }

  static void setContainerHostname(EVMod *mod, HSPVMState_DOCKER *container, const char *hostname) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(my_strequal(hostname, container->hostname) == NO) {
      if(container->hostname) {
	decNameCount(mdata->hostnameCount, container->hostname);
	my_free(container->hostname);
      }
      container->hostname = my_strdup(hostname);
      if(incNameCount(mdata->hostnameCount, hostname) > 1) {
	duplicateHostname(mod, container);
      }
    }
  }

  static void dockerAPI_inspect(EVMod *mod, UTStrBuf *buf, cJSON *jcont, HSPDockerRequest *req) {
    myDebug(1, "dockerAPI_inspect");

    cJSON *jid = cJSON_GetObjectItem(jcont, "Id");
    cJSON *jname = cJSON_GetObjectItem(jcont, "Name");
    cJSON *jstate = cJSON_GetObjectItem(jcont, "State");
    cJSON *jconfig = cJSON_GetObjectItem(jcont, "Config");
    cJSON *jhconfig = cJSON_GetObjectItem(jcont, "HostConfig");

    if(jid == NULL
       || jname == NULL
       || jstate == NULL
       || jconfig == NULL
       || jhconfig == NULL) {
      return;
    }
    
    HSPVMState_DOCKER *container = getContainer(mod, jid->valuestring, NO);
    if(container == NULL)
      return;
    
    setContainerName(mod, container, jname->valuestring);

    cJSON *jpid = cJSON_GetObjectItem(jstate, "Pid");
    if(jpid)
      container->pid = (pid_t)jpid->valueint;

    cJSON *jstatus = cJSON_GetObjectItem(jstate, "Status");
    if(jstatus)
      container->state = containerState(jstatus->valuestring);

    // allow Running: true to override container->state
    cJSON *jrun = cJSON_GetObjectItem(jstate, "Running");
    if(jrun && jrun->type == cJSON_True)
      container->state = HSP_CS_running;
    
    cJSON *jhn = cJSON_GetObjectItem(jconfig, "Hostname");
    if(jhn)
      setContainerHostname(mod, container, jhn->valuestring);

    cJSON *jmem = cJSON_GetObjectItem(jhconfig, "Memory");
    if(jmem)
      container->memoryLimit = (uint64_t)jmem->valuedouble;

    cJSON *jcpus = cJSON_GetObjectItem(jhconfig, "CpuCount");
    if(jcpus)
      container->cpu_count = (uint32_t)jcpus->valuedouble;

    cJSON *jnanocpus = cJSON_GetObjectItem(jhconfig, "NanoCpus");
    if(jnanocpus)
      container->cpu_count_dbl = jnanocpus->valuedouble / 1e9;

    container->inspect_rx = YES;
    // now that we have the pid,  we can probe for the MAC and peer-ifIndex
    updateContainerAdaptors(mod, container);
    // send initial counter-sample immediately...
    // But to do this we call getContainerStats() first
    getContainerStats(mod, container);
  }

  static void inspectContainer(EVMod *mod, HSPVMState_DOCKER *container) {
    UTStrBuf *req = UTStrBuf_new();
    UTStrBuf_printf(req, HSP_DOCKER_REQ_INSPECT_ID, container->id);
    dockerAPIRequest(mod, dockerRequest(mod, req, dockerAPI_inspect, NO));
    UTStrBuf_free(req);
    container->inspect_tx = YES;
  }
  
  static void dockerAPI_stats(EVMod *mod, UTStrBuf *buf, cJSON *jcont, HSPDockerRequest *req) {
    // Example output
    /*
{
    "blkio_stats": {
        "io_merged_recursive": [],
        "io_queue_recursive": [],
        "io_service_bytes_recursive": [
            {
                "major": 8,
                "minor": 48,
                "op": "Read",
                "value": 29769728
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Write",
                "value": 0
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Sync",
                "value": 29769728
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Async",
                "value": 0
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Total",
                "value": 29769728
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Read",
                "value": 29769728
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Write",
                "value": 0
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Sync",
                "value": 29769728
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Async",
                "value": 0
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Total",
                "value": 29769728
            }
        ],
        "io_service_time_recursive": [],
        "io_serviced_recursive": [
            {
                "major": 8,
                "minor": 48,
                "op": "Read",
                "value": 337
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Write",
                "value": 0
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Sync",
                "value": 337
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Async",
                "value": 0
            },
            {
                "major": 8,
                "minor": 48,
                "op": "Total",
                "value": 337
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Read",
                "value": 337
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Write",
                "value": 0
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Sync",
                "value": 337
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Async",
                "value": 0
            },
            {
                "major": 253,
                "minor": 0,
                "op": "Total",
                "value": 337
            }
        ],
        "io_time_recursive": [],
        "io_wait_time_recursive": [],
        "sectors_recursive": []
    },
    "cpu_stats": {
        "cpu_usage": {
            "percpu_usage": [
                379915710187,
                396983734043,
                335805190563,
                254528451875
            ],
            "total_usage": 1367233086668,
            "usage_in_kernelmode": 811190000000,
            "usage_in_usermode": 442110000000
        },
        "system_cpu_usage": 6322464450000000,
        "throttling_data": {
            "periods": 0,
            "throttled_periods": 0,
            "throttled_time": 0
        }
    },
    "id": "2e781c0358b9940f7bc8399903b5af0d2e09f0b60714ef62f961280986467724",
    "memory_stats": {
        "limit": 3973283840,
        "max_usage": 1359872,
        "stats": {
            "active_anon": 4096,
            "active_file": 4096,
            "cache": 4096,
            "hierarchical_memory_limit": 9223372036854771712,
            "hierarchical_memsw_limit": 9223372036854771712,
            "inactive_anon": 131072,
            "inactive_file": 0,
            "mapped_file": 0,
            "pgfault": 1080700,
            "pgmajfault": 0,
            "pgpgin": 236398,
            "pgpgout": 236364,
            "rss": 135168,
            "rss_huge": 0,
            "swap": 0,
            "total_active_anon": 4096,
            "total_active_file": 4096,
            "total_cache": 4096,
            "total_inactive_anon": 131072,
            "total_inactive_file": 0,
            "total_mapped_file": 0,
            "total_pgfault": 1080700,
            "total_pgmajfault": 0,
            "total_pgpgin": 236398,
            "total_pgpgout": 236364,
            "total_rss": 135168,
            "total_rss_huge": 0,
            "total_swap": 0,
            "total_unevictable": 0,
            "unevictable": 0
        },
        "usage": 139264
    },
    "name": "/epic_ritchie",
    "networks": {
        "eth0": {
            "rx_bytes": 656,
            "rx_dropped": 0,
            "rx_errors": 0,
            "rx_packets": 8,
            "tx_bytes": 656,
            "tx_dropped": 0,
            "tx_errors": 0,
            "tx_packets": 8
        }
    },
    "num_procs": 0,
    "pids_stats": {
        "current": 1
    },
    "precpu_stats": {
        "cpu_usage": {
            "percpu_usage": [
                379915710187,
                396983734043,
                335805190563,
                254528451875
            ],
            "total_usage": 1367233086668,
            "usage_in_kernelmode": 811190000000,
            "usage_in_usermode": 442110000000
        },
        "system_cpu_usage": 6322460430000000,
        "throttling_data": {
            "periods": 0,
            "throttled_periods": 0,
            "throttled_time": 0
        }
    },
    "preread": "2019-09-18T18:34:22.922435672Z",
    "read": "2019-09-18T18:34:23.933567531Z",
    "storage_stats": {}
}
    */
    myDebug(1, "dockerAPI_stats");
  
    cJSON *jcpu = cJSON_GetObjectItem(jcont, "cpu_stats");
    cJSON *jmem = cJSON_GetObjectItem(jcont, "memory_stats");
    cJSON *jnet = cJSON_GetObjectItem(jcont, "networks");
    cJSON *jdsk = cJSON_GetObjectItem(jcont, "blkio_stats");

    // since the stats request does not include the container id we
    // stashed it in the request object. We could have stashed the
    // container pointer but that might have been awkward if the
    // container dissappeared in between.
    // Oh - it looks like both the id and name are included
    // in API 1.21 and later. So we could go back to doing it
    // that way.
    HSPVMState_DOCKER *container = getContainer(mod, req->id, NO);
    if(container == NULL)
      return;
  
    // setContainerName(mod, container, jname->valuestring);
  
    if(jcpu) {
      cJSON *jcpu_usage = cJSON_GetObjectItem(jcpu, "cpu_usage");
      cJSON *jcpu_total = cJSON_GetObjectItem(jcpu_usage, "total_usage");
      if(jcpu_total)
	container->cpu_total = (uint64_t)jcpu_total->valuedouble;
    }

    if(jmem) {
      cJSON *jmem_usage = cJSON_GetObjectItem(jmem, "usage");
      if(jmem_usage)
	container->mem_usage = (uint64_t)jmem_usage->valuedouble;
      // memory limit seems to appear here when it doesn't appear in the "inspect" step:
      cJSON *jmem_limit = cJSON_GetObjectItem(jmem, "limit");
      if(jmem_limit)
	container->memoryLimit = (uint64_t)jmem_limit->valuedouble;
    }

    if(jnet) {
      // clear and accumulate over what may be multiple devices
      memset(&container->net, 0, sizeof(container->net));
      for(cJSON *dev = jnet->child; dev; dev = dev->next) {
	cJSON *dev_bytes_in = cJSON_GetObjectItem(dev, "rx_bytes");
	if(dev_bytes_in)
	  container->net.bytes_in += (uint64_t)dev_bytes_in->valuedouble;

	cJSON *dev_pkts_in = cJSON_GetObjectItem(dev, "rx_packets");
	if(dev_pkts_in)
	  container->net.pkts_in += (uint64_t)dev_pkts_in->valuedouble;

	cJSON *dev_drops_in = cJSON_GetObjectItem(dev, "rx_dropped");
	if(dev_drops_in)
	  container->net.drops_in += (uint64_t)dev_drops_in->valuedouble;

	cJSON *dev_errs_in = cJSON_GetObjectItem(dev, "rx_errors");
	if(dev_errs_in)
	  container->net.errs_in += (uint64_t)dev_errs_in->valuedouble;

	cJSON *dev_bytes_out = cJSON_GetObjectItem(dev, "tx_bytes");
	if(dev_bytes_out)
	  container->net.bytes_out += (uint64_t)dev_bytes_out->valuedouble;

	cJSON *dev_pkts_out = cJSON_GetObjectItem(dev, "tx_packets");
	if(dev_pkts_out)
	  container->net.pkts_out += (uint64_t)dev_pkts_out->valuedouble;

	cJSON *dev_drops_out = cJSON_GetObjectItem(dev, "tx_dropped");
	if(dev_drops_out)
	  container->net.drops_out += (uint64_t)dev_drops_out->valuedouble;

	cJSON *dev_errs_out = cJSON_GetObjectItem(dev, "tx_errors");
	if(dev_errs_out)
	  container->net.errs_out += (uint64_t)dev_errs_out->valuedouble;
      }
    }

    if(jdsk) {
      // clear and accumulate over what may be multiple devices
      memset(&container->dsk, 0, sizeof(container->dsk));
      cJSON *jbytesArray = cJSON_GetObjectItem(jdsk, "io_service_bytes_recursive");
      if(jbytesArray) {
	int entries = cJSON_GetArraySize(jbytesArray);
	for(int ii = 0; ii < entries; ii++) {
	  cJSON *jbytes = cJSON_GetArrayItem(jbytesArray, ii);
	  if(jbytes) {
	    cJSON *value = cJSON_GetObjectItem(jbytes, "value");
	    if(value) {
	      uint64_t val64 = (uint64_t)value->valuedouble;
	      if(val64 > 0) {
		cJSON *operation = cJSON_GetObjectItem(jbytes, "op");
		if(operation) {
		  if(my_strequal(operation->valuestring, "Read"))
		    container->dsk.rd_bytes += val64;
		  else if(my_strequal(operation->valuestring, "Write"))
		    container->dsk.wr_bytes += val64;
		  // ignore "Sync" and "Async"
		}
	      }
	    }
	  }
	}
      }
      cJSON *jreqArray = cJSON_GetObjectItem(jdsk, "io_serviced_recursive");
      if(jreqArray) {
	int entries = cJSON_GetArraySize(jreqArray);
	for(int ii = 0; ii < entries; ii++) {
	  cJSON *jreq = cJSON_GetArrayItem(jreqArray, ii);
	  if(jreq) {
	    cJSON *value = cJSON_GetObjectItem(jreq, "value");
	    if(value) {
	      uint64_t val64 = (uint64_t)value->valuedouble;
	      if(val64 > 0) {
		cJSON *operation = cJSON_GetObjectItem(jreq, "op");
		if(operation) {
		  if(my_strequal(operation->valuestring, "Read"))
		    container->dsk.rd_req += val64;
		  else if(my_strequal(operation->valuestring, "Write"))
		    container->dsk.wr_req += val64;
		  // ignore "Sync" and "Async"
		}
	      }
	    }
	  }
	}
      }
    }

    container->stats_rx = YES;
    // now (finally) we get to send the counter sample
    getCounters_DOCKER(mod, container);
  }

  static void getContainerStats(EVMod *mod, HSPVMState_DOCKER *container) {
    UTStrBuf *req = UTStrBuf_new();
    UTStrBuf_printf(req, HSP_DOCKER_REQ_STATS_ID, container->id);
    HSPDockerRequest *reqObj = dockerRequest(mod, req, dockerAPI_stats, NO);
    reqObj->id = my_strdup(container->id);
    dockerAPIRequest(mod, reqObj);
    UTStrBuf_free(req);
    container->stats_tx = YES;
  }

  static void dockerAPI_event(EVMod *mod, UTStrBuf *buf, cJSON *top, HSPDockerRequest *req) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    myDebug(1, "dockerAPI_event");
    if(mdata->dockerSync == NO) {
      // just take a copy and queue it for now
      UTArrayAdd(mdata->eventQueue, UTStrBuf_copy(buf));
      return;
    }
    
    cJSON *status = cJSON_GetObjectItem(top, "status");
    cJSON *id = cJSON_GetObjectItem(top, "id");
    cJSON *actor = cJSON_GetObjectItem(top, "Actor");
    if(status
       && status->valuestring
       && id
       && id->valuestring
       && actor) {
      cJSON *attributes = cJSON_GetObjectItem(actor, "Attributes");
      if(attributes) {
	cJSON *ctname = cJSON_GetObjectItem(attributes, "name");
	if(ctname
	   && ctname->valuestring) {
	  HSPVMState_DOCKER *container;
	  EnumHSPContainerEvent ev = containerEvent(status->valuestring);
	  if(ev == HSP_EV_UNKNOWN) {
	    myDebug(1, "unrecognized event status: %s", status->valuestring);
	    return;
	  }
	  EnumHSPContainerState st = HSP_CS_UNKNOWN;
	  switch(ev) {
	  case HSP_EV_create:
	    st = HSP_CS_created;
	    break;
	  case HSP_EV_start:
	  case HSP_EV_restart:
	  case HSP_EV_unpause:
	    st = HSP_CS_running;
	    break;
	  case HSP_EV_pause:
	    st = HSP_CS_paused;
	    break;
	  case HSP_EV_stop:
	    st = HSP_CS_stopped;
	    break;
	  case HSP_EV_kill:
	  case HSP_EV_die:
	  case HSP_EV_oom:
	  case HSP_EV_rm:
	    st = HSP_CS_exited;
	    break;
	  case HSP_EV_destroy:
	    st = HSP_CS_deleted;
	  case HSP_EV_attach:
	  case HSP_EV_commit:
	  case HSP_EV_copy:
	  case HSP_EV_detach:
	  case HSP_EV_exec_create:
	  case HSP_EV_exec_detach:
	  case HSP_EV_exec_start:
	  case HSP_EV_export:
	  case HSP_EV_health_status:
	  case HSP_EV_rename:
	  case HSP_EV_resize:
	  case HSP_EV_top:
	  case HSP_EV_update:
	  default:
	    // leave as HSP_CS_UNKNOWN so as not to trigger a state-change below,
	    // but still allow for a name update.
	    break;
	  }

	  container = getContainer(mod, id->valuestring, (st == HSP_CS_running));
	  if(container) {
	    if(st != HSP_CS_UNKNOWN
	       && st != container->state) {
	      myDebug(1, "container state %s -> %s",
		      HSP_CS_names[container->state],
		      HSP_CS_names[st]);
	      container->state = st;
	    }
	    container->lastEvent = ev;
	    if(container->state == HSP_CS_running) {
	      // note that "rename" event will get here
	      setContainerName(mod, container, ctname->valuestring);
	      if(!container->inspect_tx) {
		// new entry - get meta-data
		// will send counter-sample when complete
		inspectContainer(mod, container);
	      }
	    }
	    else {
	      // we are going to remove this one
	      // send final counter-sample. Have to
	      // grab this now before the cgroup data
	      // disappears from the filesystem...
	      getCounters_DOCKER(mod, container);
	      UTHashDel(mdata->pollActions, container);
	      removeAndFreeVM_DOCKER(mod, container);
	    }
	  }
	}
      } // attributes
    } // actor
  }
    
  static void dockerAPI_containers(EVMod *mod, UTStrBuf *buf, cJSON *top, HSPDockerRequest *req) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    myDebug(1, "dockerAPI_containers");
    // process containers
    int nc = cJSON_GetArraySize(top);
    for(int ii = 0; ii < nc; ii++) {
      cJSON *ct = cJSON_GetArrayItem(top, ii);
      cJSON *id = cJSON_GetObjectItem(ct, "Id");
      cJSON *names = cJSON_GetObjectItem(ct, "Names");
      cJSON *state = cJSON_GetObjectItem(ct, "State");
					  
      if(!id
	 || !names
	 //|| !networksettings
	 || !state) break;

      cJSON *name0 = cJSON_GetArrayItem(names, 0); // TODO: extra '/' at front?
      if(!name0) break;

      cJSON *networksettings = cJSON_GetObjectItem(ct, "NetworkSettings");
      if(networksettings) {
	// TODO: use these instead of the namespace switch?
	// but we don't get the ifIndex this way.  So now
	// the question is whether we can look up the ifIndex
	// (without switching namespaces) given the mac address.
	cJSON *networks = cJSON_GetObjectItem(networksettings, "Networks");
	for(cJSON *dev = networks->child; dev; dev = dev->next) {
	  cJSON *macaddress = cJSON_GetObjectItem(dev, "MacAddress");
	  cJSON *ip4address = cJSON_GetObjectItem(dev, "IPAddress");
	  cJSON *ip6address = cJSON_GetObjectItem(dev, "GlobalIPv6Address");
	  myDebug(1, "got network %s mac=%s v4=%s v6=%s",
		  dev->valuestring,
		  macaddress ? macaddress->valuestring : "<unknown>",
		  ip4address ? ip4address->valuestring : "<unknown>",
		  ip6address ? ip6address->valuestring : "<unknown>");
	}
      }

      HSPVMState_DOCKER *container = getContainer(mod, id->valuestring, YES);
      container->state = containerState(state->valuestring);
      setContainerName(mod, container, name0->valuestring);
      if(!container->inspect_tx)
	inspectContainer(mod, container);
    }

    // mark as sync'd and replay queued events
    mdata->dockerSync = YES;
    UTStrBuf *qbuf;
    UTARRAY_WALK(mdata->eventQueue, qbuf) {
      cJSON *top = cJSON_Parse(UTSTRBUF_STR(qbuf));
      if(top) {
	dockerAPI_event(mod, qbuf, top, req);
	cJSON_Delete(top);
      }
      UTStrBuf_free(qbuf);
    }
    UTArrayReset(mdata->eventQueue);
  }

  /*_________________---------------------------__________________
    _________________       logJSON             __________________
    -----------------___________________________------------------
  */

  static void logJSON(int debugLevel, char *msg, cJSON *obj)
  {
    if(debug(debugLevel)) {
      char *str = cJSON_Print(obj);
      myLog(LOG_INFO, "%s json=<%s>", msg, str);
      my_free(str); // TODO: get this fn from cJSON hooks
    }
  }

  static void processDockerJSON(EVMod *mod, HSPDockerRequest *req, UTStrBuf *buf) {
    cJSON *top = cJSON_Parse(UTSTRBUF_STR(buf));
    if(top) {
      logJSON(1, "processDockerJSON:", top);
      (*req->jsonCB)(mod, buf, top, req);
      cJSON_Delete(top);
    }
  }

  // Assume headers include:
  // Content-Type: Application/JSON
  // Transfer-Encoding: chunked
  //
  // Assume that the chunks of JSON content do not have CR or LF characters within them
  // (if they ever do then we can add another "within chunk" state and append lines to
  // the response result there).
  static void processDockerResponse(EVMod *mod, EVSocket *sock, HSPDockerRequest *req) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    char *line = UTSTRBUF_STR(sock->ioline);
    myDebug(2, "readDockerAPI got answer: <%s>", line);
    switch(req->state) {

    case HSPDOCKERREQ_HEADERS:
      UTStrBuf_chomp(sock->ioline);
      if(UTRegexExtractInt(mdata->contentLengthPattern, line, 1, &req->contentLength, NULL, NULL)) {
	myDebug(1, "got contentLength=%d", req->contentLength);
      }
      else if(UTSTRBUF_LEN(sock->ioline) == 0) {
	req->state = req->contentLength
	  ? HSPDOCKERREQ_CONTENT
	  : HSPDOCKERREQ_LENGTH;
      }
      break;

    case HSPDOCKERREQ_ENDCONTENT:
      UTStrBuf_chomp(sock->ioline);
      if(UTSTRBUF_LEN(sock->ioline) == 0)
	req->state = HSPDOCKERREQ_LENGTH;
      break;
      
    case HSPDOCKERREQ_LENGTH: {
      UTStrBuf_chomp(sock->ioline);
      char *endp = NULL;
      req->chunkLength = strtol(line, &endp, 16); // hex
      if(*endp != '\0') {
	// failed to consume the whole string - must be an error.
	myDebug(1, "Docker error: <%s> for request: <%s>",
		line, UTSTRBUF_STR(req->request));
	req->state = HSPDOCKERREQ_ERR;
      }
      else {
	req->state = req->chunkLength
	  ? HSPDOCKERREQ_CONTENT
	  : HSPDOCKERREQ_ENDCONTENT;
      }
      break;
    }

    case HSPDOCKERREQ_CONTENT: {
      int clen = req->chunkLength ?: req->contentLength;
      assert(clen == UTSTRBUF_LEN(sock->ioline)); // assume no newlines in chunk
      if(req->eventFeed)
	processDockerJSON(mod, req, sock->ioline);
      else {
	if(req->response == NULL)
	  req->response = UTStrBuf_new();
	UTStrBuf_append_n(req->response, line, UTSTRBUF_LEN(sock->ioline));
      }
      req->state = HSPDOCKERREQ_ENDCONTENT;
      break;
    }
      
    case HSPDOCKERREQ_ERR:
      // TODO: just wait for EOF, or should we force the socket to close?
      break;
    }
  }
  
  static void readDockerCB(EVMod *mod, EVSocket *sock, EnumEVSocketReadStatus status, void *magic) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    HSPDockerRequest *req = (HSPDockerRequest *)magic;
    switch(status) {
    case EVSOCKETREAD_AGAIN:
      break;
    case EVSOCKETREAD_STR:
      if(!mdata->dockerFlush) {
	processDockerResponse(mod, sock, req);
	UTStrBuf_reset(sock->ioline);
      }
      break;
    case EVSOCKETREAD_EOF:
      if(!mdata->dockerFlush) {
	if(req->response)
	  processDockerJSON(mod, req, req->response);
      }
      // fall through
    case EVSOCKETREAD_BADF:
    case EVSOCKETREAD_ERR:
      // clean up
      assert(mdata->currentRequests > 0);
      --mdata->currentRequests;

      if(req->eventFeed) {
	// we lost the event feed - need to flush and resync
	mdata->dockerFlush = YES;
      }

      // free the request - (it's not in any other collection)
      dockerRequestFree(mod, req);
      req = NULL;
      
      if(mdata->dockerFlush &&
	 mdata->currentRequests == 0) {
	// no outstanding requests - flush is done
	mdata->dockerFlush = NO;
	mdata->countdownToResync = HSP_DOCKER_WAIT_EVENTDROP;
      }
      
      // see if we have another request queued
      if(!mdata->dockerFlush
	 && !UTQ_EMPTY(mdata->requestQ)) {
	HSPDockerRequest *nextReq;
	UTQ_REMOVE_HEAD(mdata->requestQ, nextReq);
	dockerAPIRequest(mod, nextReq);
      }
    }
  }
    
  static void readDockerAPI(EVMod *mod, EVSocket *sock, void *magic) {
    EVSocketReadLines(mod, sock, readDockerCB, magic);
  }

  static void dockerAPIRequest(EVMod *mod, HSPDockerRequest *req) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    if(mdata->currentRequests >= HSP_DOCKER_MAX_CONCURRENT) {
      // just queue it
      UTQ_ADD_TAIL(mdata->requestQ, req);
      return;
    }
    char *cmd = UTSTRBUF_STR(req->request);
    ssize_t len = UTSTRBUF_LEN(req->request);
    int fd = UTUnixDomainSocket(HSP_DOCKER_SOCK);
    myDebug(1, "dockerAPIRequest(%s) fd==%d", cmd, fd);
    if(fd < 0)  {
      // looks like docker was stopped
      // wait longer before retrying
      mdata->dockerFlush = YES;
      mdata->countdownToResync = HSP_DOCKER_WAIT_NOSOCKET;
    }
    else {
      EVBusAddSocket(mod, mdata->pollBus, fd, readDockerAPI, req);
      int cc;
      while((cc = write(fd, cmd, len)) != len && errno == EINTR);
      if(cc == len) {
	mdata->currentRequests++;
      }
      else {
	myLog(LOG_ERR, "dockerAPIRequest - write(%s) returned %d != %u: %s",
	      cmd, cc, len, strerror(errno));
      }
    }
  }

  static HSPDockerRequest *dockerRequest(EVMod *mod, UTStrBuf *cmd, HSPDockerCB jsonCB, bool eventFeed) {
    HSPDockerRequest *req = (HSPDockerRequest *)my_calloc(sizeof(HSPDockerRequest));
    req->request = UTStrBuf_copy(cmd);
    req->jsonCB = jsonCB;
    req->eventFeed = eventFeed;
    return req;
  }

  static void  dockerRequestFree(EVMod *mod, HSPDockerRequest *req) {
    UTStrBuf_free(req->request);
    if(req->response) UTStrBuf_free(req->response);
    if(req->id) my_free(req->id);
    my_free(req);
  }

  static void dockerClearAll(EVMod *mod) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    // clear everything out:
    // 1. pollActions
    UTHashReset(mdata->pollActions);
    // 2. containers
    HSPVMState_DOCKER *container;
    UTHASH_WALK(mdata->vmsByID, container)
      removeAndFreeVM_DOCKER(mod, container);
    // 3. event queue
    UTStrBuf *qbuf;
    UTARRAY_WALK(mdata->eventQueue, qbuf)
      UTStrBuf_free(qbuf);
    UTArrayReset(mdata->eventQueue);
    // 4. request queue
    HSPDockerRequest *req, *nx;
    for(req = mdata->requestQ.head; req; ) {
      nx = req->next;
      dockerRequestFree(mod, req);
      req = nx;
    }
    UTQ_CLEAR(mdata->requestQ);
  }
  
  static void dockerSynchronize(EVMod *mod) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    dockerClearAll(mod);
    mdata->dockerSync = NO;
    mdata->dockerFlush = NO;
    mdata->cgroupPathIdx = -1;    
    // start the event monitor before we capture the current state.  Events will be queued until we have
    // read all the current containers, then replayed.  At that point we will be "in sync".
    dockerAPIRequest(mod, dockerRequest(mod, UTStrBuf_wrap(HSP_DOCKER_REQ_EVENTS), dockerAPI_event, YES));
    dockerAPIRequest(mod, dockerRequest(mod, UTStrBuf_wrap(HSP_DOCKER_REQ_CONTAINERS), dockerAPI_containers, NO));
  }

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    mdata->countdownToResync = HSP_DOCKER_WAIT_STARTUP;
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_docker(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_DOCKER));
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;

    // ask to retain root privileges
    retainRootRequest(mod, "needed to access docker.sock");
    retainRootRequest(mod, "needed by mod_docker to probe for adaptors in other namespaces");

    requestVNodeRole(mod, HSP_VNODE_PRIORITY_DOCKER);

    mdata->contentLengthPattern = UTRegexCompile(HSP_CONTENT_LENGTH_REGEX);
    mdata->vmsByUUID = UTHASH_NEW(HSPVMState_DOCKER, vm.uuid, UTHASH_DFLT);
    mdata->vmsByID = UTHASH_NEW(HSPVMState_DOCKER, id, UTHASH_SKEY);
    mdata->nameCount = UTHASH_NEW(HSPDockerNameCount, name, UTHASH_SKEY);
    mdata->hostnameCount = UTHASH_NEW(HSPDockerNameCount, name, UTHASH_SKEY);
    mdata->pollActions = UTHASH_NEW(HSPVMState_DOCKER, id, UTHASH_IDTY);
    mdata->eventQueue = UTArrayNew(UTARRAY_DFLT);
    mdata->cgroupPathIdx = -1;
    
    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TOCK), evt_tock);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_FIRST), evt_config_first);
    mdata->countdownToResync = HSP_DOCKER_WAIT_STARTUP;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
