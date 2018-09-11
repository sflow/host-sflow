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

  // limit the number of chars we will read from each line
  // in /proc/net/dev and /prov/net/vlan/config
  // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 160

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
    "rm"
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

  // patterns to substitute with cgroup, longid and counter-filename
  static const char *HSP_CGROUP_PATHS[] = {
    "/sys/fs/cgroup/%s/docker/%s/%s",
    "/sys/fs/cgroup/%s/system.slice/docker/%s",
    "/sys/fs/cgroup/%s/system.slice/docker-%s.scope/%s",
    NULL
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
    uint64_t memoryLimit;
  } HSPVMState_DOCKER;

  typedef void (*HSPDockerCB)(EVMod *mod, UTStrBuf *buf, cJSON *obj);

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
  } HSPDockerRequest;

#define HSP_DOCKER_SOCK  "/var/run/docker.sock"
#define HSP_DOCKER_MAX_CONCURRENT 3
#define HSP_DOCKER_HTTP " HTTP/1.1\nHost: " HSP_DOCKER_SOCK "\n\n"
#define HSP_DOCKER_API "v1.24"
#define HSP_DOCKER_REQ_EVENTS "GET /" HSP_DOCKER_API "/events?filters={\"type\":[\"container\"]}" HSP_DOCKER_HTTP
#define HSP_DOCKER_REQ_CONTAINERS "GET /" HSP_DOCKER_API "/containers/json" HSP_DOCKER_HTTP
#define HSP_DOCKER_REQ_INSPECT_ID "GET /" HSP_DOCKER_API "/containers/%s/json" HSP_DOCKER_HTTP
#define HSP_CONTENT_LENGTH_REGEX "^Content-Length: ([0-9]+)$"
  
#define HSP_DOCKER_CMD "/usr/bin/docker"
#define HSP_NETNS_DIR "/var/run/netns"
#define HSP_IP_CMD "/usr/sbin/ip"
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
  } HSP_mod_DOCKER;

#define HSP_DOCKER_MAX_STATS_LINELEN 512

  static void dockerAPIRequest(EVMod *mod, HSPDockerRequest *req);
  static HSPDockerRequest *dockerRequest(EVMod *mod, UTStrBuf *cmd, HSPDockerCB jsonCB, bool eventFeed);
  static void  dockerRequestFree(EVMod *mod, HSPDockerRequest *req);
  static void dockerSynchronize(EVMod *mod);

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


  /*_________________---------------------------__________________
    _________________     readCgroupCounters    __________________
    -----------------___________________________------------------
  */

  static bool readCgroupCounters(EVMod *mod, char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals, int multi) {
    HSP_mod_DOCKER *mdata = (HSP_mod_DOCKER *)mod->data;
    
    int found = 0;

    char statsFileName[HSP_DOCKER_MAX_FNAME_LEN+1];
    
    if(mdata->cgroupPathIdx == -1) {
      // iterate to choose path the first time
      for(;;) {
	const char *fmt = HSP_CGROUP_PATHS[++mdata->cgroupPathIdx];
	if(fmt == NULL) {
	  myLog(LOG_ERR, "readCgroupCounters: not found: cgroup=%s container=%s file=%s", cgroup, longId, fname);
	  return NO;
	}
	myDebug(1, "testing cgroup path: %s", fmt);
	snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, fmt, cgroup, longId, fname);
	FILE *statsFile = fopen(statsFileName, "r");
	if(statsFile) {
	  myDebug(1, "success using path pattern: %s", fmt);
	  fclose(statsFile);
	}
	break;
      }
    }	

    const char *fmt = HSP_CGROUP_PATHS[mdata->cgroupPathIdx];
    snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, fmt, cgroup, longId, fname);
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

    static int readContainerCounters(EVMod *mod, char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals) {
      return readCgroupCounters(mod, cgroup, longId, fname, nvals, nameVals, 0);
  }

  /*_________________-----------------------------__________________
    _________________  readContainerCountersMulti __________________
    -----------------_____________________________------------------
    Variant where the stats file has per-device numbers that need to be summed.
    The device id is assumed to be the first space-separated token on each line.
*/

  static int readContainerCountersMulti(EVMod *mod, char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals) {
    return readCgroupCounters(mod, cgroup, longId, fname, nvals, nameVals, 1);
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
      while(fgets(line, MAX_PROC_LINE_CHARS, ovs)) containerLinkCB(sp, container, line);
      fclose(ovs);
      wait(NULL); // block here until child is done
    }

    return container->vm.interfaces->num_adaptors;
  }


  /*________________---------------------------__________________
    ________________   readContainerNIO        __________________
    ----------------___________________________------------------
   used to get these by extracting the totals for the adaptors
   referred to by getContainerPeerAdaptors() -- i.e. the adaptors
   in the global namespace that we know to be connected back to
   that container.  But with Docker swarm we end up missing the
   traffic that goes via the extra namespace that they create.
   Since we have the container Pid,  we can reach in directly
   to /proc/<pid>/net/dev and read from there.
  */
  
#ifdef HSP_DOCKER_PEER_ADAPTORS_OK

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

#else

  static int readContainerNIO(EVMod *mod, HSPVMState_DOCKER *container, SFLHost_nio_counters *nio) {
    char statsFileName[HSP_DOCKER_MAX_FNAME_LEN+1];
    int interfaces = 0;
    snprintf(statsFileName, HSP_DOCKER_MAX_FNAME_LEN, "/proc/%u/net/dev", container->pid);
    FILE *procFile = fopen(statsFileName, "r");
    if(procFile) {
      uint64_t bytes_in = 0;
      uint64_t pkts_in = 0;
      uint64_t errs_in = 0;
      uint64_t drops_in = 0;
      uint64_t bytes_out = 0;
      uint64_t pkts_out = 0;
      uint64_t errs_out = 0;
      uint64_t drops_out = 0;
      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROCDEV_LINE_CHARS 240
      char line[MAX_PROCDEV_LINE_CHARS];
      while(fgets(line, MAX_PROCDEV_LINE_CHARS, procFile)) {
	char deviceName[MAX_PROCDEV_LINE_CHARS];
	// assume the format is:
	// Inter-|   Receive                                                |  Transmit
	//  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	if(sscanf(line, "%[^:]:%"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %*u %*u %*u %*u %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64"",
		  deviceName,
		  &bytes_in,
		  &pkts_in,
		  &errs_in,
		  &drops_in,
		  &bytes_out,
		  &pkts_out,
		  &errs_out,
		  &drops_out) == 9) {
	  if(my_strequal(trimWhitespace(deviceName), "lo") == NO) {
	    interfaces++;
	    nio->bytes_in += bytes_in;
	    nio->pkts_in += pkts_in;
	    nio->errs_in += errs_in;
	    nio->drops_in += drops_in;
	    nio->bytes_out += bytes_out;
	    nio->pkts_out += pkts_out;
	    nio->errs_out += errs_out;
	    nio->drops_out += drops_out;
	  }
	}
      }
      fclose(procFile);
    }
    return interfaces;
  }
#endif
  
  /*________________---------------------------__________________
    ________________   getCounters_DOCKER      __________________
    ----------------___________________________------------------
  */
  static void getCounters_DOCKER(EVMod *mod, HSPVMState_DOCKER *container)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFL_COUNTERS_SAMPLE_TYPE cs = { 0 };
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
    
#ifdef HSP_DOCKER_PEER_ADAPTORS_OK
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
      SFLADD_ELEMENT(&cs, &nioElem);
    }
#else
    if(readContainerNIO(mod, container, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio)) {
      SFLADD_ELEMENT(&cs, &nioElem);
    }
#endif

    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = 0;
    SFL_UNDEF_COUNTER(cpuElem.counterBlock.host_vrt_cpu.cpuTime);

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

    // get cpu time if we can
    HSPNameVal cpuVals[] = {
      { "user",0,0 },
      { "system",0,0},
      { NULL,0,0},
    };
    if(readContainerCounters(mod, "cpuacct", container->id, "cpuacct.stat", 2, cpuVals)) {
      uint64_t cpu_total = 0;
      if(cpuVals[0].nv_found) cpu_total += cpuVals[0].nv_val64;
      if(cpuVals[1].nv_found) cpu_total += cpuVals[1].nv_val64;
      cpuElem.counterBlock.host_vrt_cpu.cpuTime = (uint32_t)(JIFFY_TO_MS(cpu_total));
    }
    // always add this one - even if no counters found - so as to send the container state
    SFLADD_ELEMENT(&cs, &cpuElem);

    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
    HSPNameVal memVals[] = {
      { "total_rss",0,0 },
      { "hierarchical_memory_limit",0,0},
      { NULL,0,0},
    };
    if(readContainerCounters(mod, "memory", container->id, "memory.stat", 2, memVals)) {
      if(memVals[0].nv_found) {
	memElem.counterBlock.host_vrt_mem.memory = memVals[0].nv_val64;
      }
      if(memVals[1].nv_found && memVals[1].nv_val64 != (uint64_t)-1) {
	uint64_t maxMem = memVals[1].nv_val64;
	// allow the limit we got from docker inspect to override if it is lower
	// (but it seems likely that it's always going to be the same number)
	if(container->memoryLimit > 0
	   && container->memoryLimit < maxMem)
	  maxMem = container->memoryLimit;
	memElem.counterBlock.host_vrt_mem.maxMemory = maxMem;
      }
      SFLADD_ELEMENT(&cs, &memElem);
    }

    // VM disk I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
    HSPNameVal dskValsB[] = {
      { "Read",0,0 },
      { "Write",0,0},
      { NULL,0,0},
    };
    if(readContainerCountersMulti(mod, "blkio", container->id, "blkio.io_service_bytes_recursive", 2, dskValsB)) {
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

    if(readContainerCountersMulti(mod, "blkio", container->id, "blkio.io_serviced_recursive", 2, dskValsO)) {
      if(dskValsO[0].nv_found) {
	dskElem.counterBlock.host_vrt_dsk.rd_req += dskValsO[0].nv_val64;
      }
      if(dskValsO[1].nv_found) {
	dskElem.counterBlock.host_vrt_dsk.wr_req += dskValsO[1].nv_val64;
      }
    }
    // TODO: fill in capacity, allocation, available fields
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
    if(container->name) my_free(container->name);
    if(container->hostname) my_free(container->hostname);
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
    // now we can execute pollActions without holding on to the semaphore
    HSPVMState_DOCKER *container;
    UTHASH_WALK(mdata->pollActions, container) {
      getCounters_DOCKER(mod, container);
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

  static void setContainerName(HSPVMState_DOCKER *container, const char *name) {
    char *str = (char *)name;
    if(str && str[0] == '/') str++; // consume leading '/'
    if(my_strequal(str, container->name) == NO) {
      if(container->name) my_free(container->name);
      container->name = my_strdup(str);
    }
  }

  static void setContainerHostname(HSPVMState_DOCKER *container, const char *hostname) {
    if(my_strequal(hostname, container->hostname) == NO) {
      if(container->hostname) my_free(container->hostname);
      container->hostname = my_strdup(hostname);
    }
  }

  static void dockerAPI_inspect(EVMod *mod, UTStrBuf *buf, cJSON *jcont) {
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
    
    setContainerName(container, jname->valuestring);

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
      setContainerHostname(container, jhn->valuestring);

    cJSON *jmem = cJSON_GetObjectItem(jhconfig, "Memory");
    if(jmem)
      container->memoryLimit = (uint64_t)jmem->valuedouble;

    container->inspect_rx = YES;
    // now that we have the pid,  we can probe for the MAC and peer-ifIndex
    updateContainerAdaptors(mod, container);
    // send initial counter-sample immediately
    getCounters_DOCKER(mod, container);
  }

  static void inspectContainer(EVMod *mod, HSPVMState_DOCKER *container) {
    UTStrBuf *req = UTStrBuf_new();
    UTStrBuf_printf(req, HSP_DOCKER_REQ_INSPECT_ID, container->id);
    dockerAPIRequest(mod, dockerRequest(mod, req, dockerAPI_inspect, NO));
    UTStrBuf_free(req);
    container->inspect_tx = YES;
  }

  static void dockerAPI_event(EVMod *mod, UTStrBuf *buf, cJSON *top) {
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
	  default:
	    st = HSP_CS_deleted;
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
	      // TODO: is this name or hostname?
	      setContainerName(container, ctname->valuestring);
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
    
  static void dockerAPI_containers(EVMod *mod, UTStrBuf *buf, cJSON *top) {
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

#if 0
      cJSON *networksettings = cJSON_GetObjectItem(ct, "NetworkSettings");
      if(networksettings) {
	cJSON *networks = cJSON_GetObjectItem(networksettings, "Networks");
	if(networks) {
	  cJSON *bridge = cJSON_GetObjectItem(networks, "bridge");
	  if(bridge) {
	    cJSON *macaddress = cJSON_GetObjectItem(bridge, "MacAddress");
	    cJSON *ipv4address = cJSON_GetObjectItem(bridge, "IPAddress");
	    // "GlobalIPv6Address" too ?
	  }
	}
      }
#endif

      HSPVMState_DOCKER *container = getContainer(mod, id->valuestring, YES);
      container->state = containerState(state->valuestring);
      setContainerName(container, name0->valuestring);
      if(!container->inspect_tx)
	inspectContainer(mod, container);
    }

    // mark as sync'd and replay queued events
    mdata->dockerSync = YES;
    UTStrBuf *qbuf;
    UTARRAY_WALK(mdata->eventQueue, qbuf) {
      cJSON *top = cJSON_Parse(UTSTRBUF_STR(qbuf));
      if(top) {
	dockerAPI_event(mod, qbuf, top);
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
      (*req->jsonCB)(mod, buf, top);
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
    mdata->pollActions = UTHASH_NEW(HSPVMState_DOCKER, id, UTHASH_IDTY);
    mdata->eventQueue = UTArrayNew(UTARRAY_DFLT);
    mdata->cgroupPathIdx = -1;
    
    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TOCK), evt_tock);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_FIRST), evt_config_first);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
