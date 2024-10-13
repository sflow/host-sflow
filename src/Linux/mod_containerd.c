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
#include <openssl/sha.h>

#include "hsflowd.h"
#include "cpu_utils.h"
#include "math.h"

  // limit the number of chars we will read from each line
  // in /proc/net/dev and /prov/net/vlan/config
  // (there can be more than this - my_readline will chop for us)
#define MAX_PROC_LINE_CHARS 320

#include "cJSON.h"

  typedef struct _HSPVMState_CONTAINERD {
    HSPVMState vm; // superclass: must come first
    char *id;
    char *name;
    char *hostname;
    pid_t pid;
    uint32_t state; // SFLVirDomainState
    uint32_t dup_name:1;
    uint32_t dup_hostname:1;
    uint32_t gpu_dev:1;
    uint32_t gpu_env:1;
    uint64_t memoryLimit;
    time_t last_vnic;
    time_t last_cgroup;
    char *cgroup_devices;
    // we now populate stats here too
    uint32_t cpu_count;
    double cpu_count_dbl;
    uint64_t cpu_total;
    uint64_t mem_usage;
    SFLHost_nio_counters net;
    SFLHost_vrt_dsk_counters dsk;
  } HSPVMState_CONTAINERD;

  typedef struct _HSPContainerNameCount {
    char *name;
    uint32_t count;
  } HSPContainerNameCount;

#define HSP_CONTAINERD_READER "/usr/sbin/hsflowd_containerd"
#define HSP_CONTAINERD_DATAPREFIX "data>"

#define HSP_CONTAINERD_MAX_FNAME_LEN 255
#define HSP_CONTAINERD_MAX_LINELEN 512
#define HSP_CONTAINERD_SHORTID_LEN 12

#define HSP_CONTAINERD_WAIT_NOSOCKET 10
#define HSP_CONTAINERD_WAIT_EVENTDROP 5
#define HSP_CONTAINERD_WAIT_STARTUP 2
#define HSP_CONTAINERD_WAIT_RECHECK 120
#define HSP_CONTAINERD_WAIT_STATS 3
#define HSP_CONTAINERD_REQ_TIMEOUT 10

#define HSP_NVIDIA_VIS_DEV_ENV "NVIDIA_VISIBLE_DEVICES"
#define HSP_MAJOR_NVIDIA 195

  typedef struct _HSPVNIC {
    SFLAddress ipAddr;
    uint32_t dsIndex;
    char *c_name;
    char *c_hostname;
    bool unique;
  } HSPVNIC;

#define HSP_VNIC_REFRESH_TIMEOUT 300
#define HSP_CGROUP_REFRESH_TIMEOUT 600

  typedef struct _HSP_mod_CONTAINERD {
    EVBus *pollBus;
    UTHash *vmsByUUID;
    UTHash *vmsByID;
    SFLCounters_sample_element vnodeElem;
    int cgroupPathIdx;
    UTHash *nameCount;
    UTHash *hostnameCount;
    uint32_t dup_names;
    uint32_t dup_hostnames;
    struct stat myNS;
    UTHash *vnicByIP;
    uint32_t configRevisionNo;
    pid_t readerPid;
  } HSP_mod_CONTAINERD;

#define HSP_CONTAINERD_MAX_STATS_LINELEN 512


  /*_________________---------------------------__________________
    _________________    utils to help debug    __________________
    -----------------___________________________------------------
  */

  char *containerStr(HSPVMState_CONTAINERD *container, char *buf, int bufLen) {
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
    HSPVMState_CONTAINERD *container;
    UTHASH_WALK(ht, container)
      myLog(LOG_INFO, "%s: %s", prefix, containerStr(container, buf, 1024));
  }

  /*________________---------------------------__________________
    ________________   containerLinkCB         __________________
    ----------------___________________________------------------
    
    expecting lines of the form:
    VNIC: <ifindex> <device> <mac>
  */

  static int containerLinkCB(EVMod *mod, HSPVMState_CONTAINERD *container, char *line) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    EVDebug(mod, 1, "containerLinkCB: line=<%s>", line);
    char deviceName[HSP_CONTAINERD_MAX_LINELEN];
    char macStr[HSP_CONTAINERD_MAX_LINELEN];
    char ipStr[HSP_CONTAINERD_MAX_LINELEN];
    uint32_t ifIndex;
    if(sscanf(line, "VNIC: %u %s %s %s", &ifIndex, deviceName, macStr, ipStr) == 4) {
      u_char mac[6];
      if(hexToBinary((u_char *)macStr, mac, 6) == 6) {
	SFLAdaptor *adaptor = adaptorListGet(container->vm.interfaces, deviceName);
	if(adaptor == NULL) {
	  adaptor = nioAdaptorNew(mod, deviceName, mac, ifIndex);
	  adaptorListAdd(container->vm.interfaces, adaptor);
	  // add to "all namespaces" collections too - but only the ones where
	  // the id is really global.  For example,  many containers can have
	  // an "eth0" adaptor so we can't add it to sp->adaptorsByName.

	  // And because the containers are likely to be ephemeral, don't
	  // replace the global adaptor if it's already there.

	  if(UTHashGet(sp->adaptorsByMac, adaptor) == NULL)
	    if(UTHashAdd(sp->adaptorsByMac, adaptor) != NULL)
	      EVDebug(mod, 1, "Warning: container adaptor overwriting adaptorsByMac");

	  if(UTHashGet(sp->adaptorsByIndex, adaptor) == NULL)
	    if(UTHashAdd(sp->adaptorsByIndex, adaptor) != NULL)
	      EVDebug(mod, 1, "Warning: container adaptor overwriting adaptorsByIndex");
	}
	else {
	  // clear mark
	  unmarkAdaptor(adaptor);
	}

	// mark it as a vm/container device
	// and record the dsIndex there for easy mapping later
	// provided it is unique.  Otherwise set it to all-ones
	// to indicate that it should not be used to map to container.
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	nio->vm_or_container = YES;
	if(nio->container_dsIndex != container->vm.dsIndex) {
	  if(nio->container_dsIndex == 0)
	    nio->container_dsIndex = container->vm.dsIndex;
	  else {
	    EVDebug(mod, 1, "Warning: NIC already claimed by container with dsIndex==nio->container_dsIndex");
	    // mark is as not a unique mapping
	    nio->container_dsIndex = 0xFFFFFFFF;
	  }
	}
	
	// did we get an ip address too?
	SFLAddress ipAddr = { };
	if(parseNumericAddress(ipStr, NULL, &ipAddr, PF_INET)) {
	  if(!SFLAddress_isZero(&ipAddr)
	     && mdata->vnicByIP) {
	    EVDebug(mod, 1, "VNIC: learned virtual ipAddr: %s", ipStr);
	    // Can use this to associate traffic with this container
	    // if this address appears in sampled packet header as
	    // outer or inner IP
	    ADAPTOR_NIO(adaptor)->ipAddr = ipAddr;
	    HSPVNIC search = { .ipAddr = ipAddr };
	    HSPVNIC *vnic = UTHashGet(mdata->vnicByIP, &search);
	    if(vnic) {
	      // found IP - check for non-unique mapping
	      if(vnic->dsIndex != container->vm.dsIndex) {
		EVDebug(mod, 1, "VNIC: IP %s clash between %s (ds=%u) and %s (ds=%u) -- setting unique=no",
			ipStr,
			vnic->c_hostname,
			vnic->dsIndex,
			container->hostname,
			container->vm.dsIndex);
		vnic->unique = NO;
	      }
	    }
	    else {
	      // add new VNIC entry
	      vnic = (HSPVNIC *)my_calloc(sizeof(HSPVNIC));
	      vnic->ipAddr = ipAddr;
	      vnic->dsIndex = container->vm.dsIndex;
	      vnic->c_name = my_strdup(container->name);
	      vnic->c_hostname = my_strdup(container->hostname);
	      UTHashAdd(mdata->vnicByIP, vnic);
	      vnic->unique = YES;
	      EVDebug(mod, 1, "VNIC: linked to %s (ds=%u)",
		      vnic->c_hostname,
		      vnic->dsIndex);
	    }
	  }
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


  int readContainerInterfaces(EVMod *mod, HSPVMState_CONTAINERD *container)  {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    pid_t nspid = container->pid;
    EVDebug(mod, 2, "readContainerInterfaces: pid=%u", nspid);
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
      char topath[HSP_CONTAINERD_MAX_FNAME_LEN+1];
      snprintf(topath, HSP_CONTAINERD_MAX_FNAME_LEN, PROCFS_STR "/%u/ns/net", nspid);
      int nsfd = open(topath, O_RDONLY | O_CLOEXEC);
      if(nsfd < 0) {
	fprintf(stderr, "cannot open %s : %s", topath, strerror(errno));
	exit(EXIT_FAILURE);
      }

      struct stat statBuf;
      if(fstat(nsfd, &statBuf) == 0) {
	EVDebug(mod, 2, "container namespace dev.inode == %u.%u", statBuf.st_dev, statBuf.st_ino);
	if(statBuf.st_dev == mdata->myNS.st_dev
	   && statBuf.st_ino == mdata->myNS.st_ino) {
	  EVDebug(mod, 1, "skip my own namespace");
	  exit(0);
	}
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
	exit(EXIT_FAILURE);
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
		  EVDebug(mod, 1, "container device %s Get SIOCGIFINDEX failed : %s",
			  devName,
			  strerror(errno));
		}
		else {
		  int ifIndex = ifr.ifr_ifindex;
		  SFLAddress ipAddr = {};

		  // see if we can get an IP address
		  if(ioctl(fd,SIOCGIFADDR, &ifr) < 0) {
		    // only complain about this if we are debugging
		    EVDebug(mod, 1, "device %s Get SIOCGIFADDR failed : %s",
			    devName,
			    strerror(errno));
		  }
		  else {
		    if (ifr.ifr_addr.sa_family == AF_INET) {
		      struct sockaddr_in *s = (struct sockaddr_in *)&ifr.ifr_addr;
		      // IP addr is now s->sin_addr
		      ipAddr.type = SFLADDRESSTYPE_IP_V4;
		      ipAddr.address.ip_v4.addr = s->sin_addr.s_addr;
		    }
		  }

		  // Get the MAC Address for this interface
		  if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
		    EVDebug(mod, 1, "device %s Get SIOCGIFHWADDR failed : %s",
			      devName,
			      strerror(errno));
		  }
		  else {
		    u_char macStr[13];
		    printHex((u_char *)&ifr.ifr_hwaddr.sa_data, 6, macStr, 12, NO);
		    char ipStr[64];
		    SFLAddress_print(&ipAddr, ipStr, 64);
		    // send this info back up the pipe to my my parent
		    printf("VNIC: %u %s %s %s\n", ifIndex, devName, macStr, ipStr);
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
	containerLinkCB(mod, container, line);
      fclose(ovs);
      wait(NULL); // block here until child is done
    }

    return container->vm.interfaces->num_adaptors;
  }

  /*________________---------------------------__________________
    ________________   getCounters_CONTAINERD  __________________
    ----------------___________________________------------------
  */
  static void getCounters_CONTAINERD(EVMod *mod, HSPVMState_CONTAINERD *container)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFL_COUNTERS_SAMPLE_TYPE cs = { 0 };
    HSPVMState *vm = (HSPVMState *)&container->vm;

    if(sp->sFlowSettings == NULL) {
      // do nothing if we haven't settled on the config yet
      return;
    }

    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char *hname = container->hostname ?: container->id; // TODO: consider config setting sp->containerd.hostname
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
    cpuElem.counterBlock.host_vrt_cpu.state = container->state;
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

    // circulate the cs to be annotated by other modules before it is sent out.
    HSPPendingCSample ps = { .poller = vm->poller, .cs = &cs };
    EVEvent *evt_vm_cs = EVGetEvent(sp->pollBus, HSPEVENT_VM_COUNTER_SAMPLE);
    // TODO: can we specify pollBus only? Receiving this on another bus would
    // be a disaster as we would not copy the whole structure here.
    EVEventTx(sp->rootModule, evt_vm_cs, &ps, sizeof(ps));
    if(ps.suppress) {
      sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES_SUPPRESSED]++;
    }
    else {
      sfl_poller_writeCountersSample(vm->poller, &cs);
      sp->counterSampleQueued = YES;
      sp->telemetry[HSP_TELEMETRY_COUNTER_SAMPLES]++;
    }
  }

  static void agentCB_getCounters_CONTAINERD_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    // This is now a no-op.  The Go program determines the counter-reporting schedule.
  }

  /*_________________---------------------------__________________
    _________________    name_uuid              __________________
    -----------------___________________________------------------
    TODO: decide how to share this with mod_systemd.  Requires link with -lcrypto,
    and include <openssl/sha.h>
  */

  static void uuidgen_type5(HSP *sp, u_char *uuid, char *name) {
    // Generate type 5 UUID (rfc 4122)
    SHA_CTX ctx;
    unsigned char sha_bits[SHA_DIGEST_LENGTH];
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, sp->uuid, 16); // use sp->uuid as "namespace UUID"
    SHA1_Update(&ctx, name, my_strlen(name));
    // also hash in agent IP address in case sp->uuid is missing or not unique
    SHA1_Update(&ctx,
		&sp->agentIP.address,
		(sp->agentIP.type == SFLADDRESSTYPE_IP_V6 ? 16 : 4));
    SHA1_Final(sha_bits, &ctx);
    // now generate a type-5 UUID according to the recipe here:
    // http://stackoverflow.com/questions/10867405/generating-v5-uuid-what-is-name-and-namespace
    // SHA1 Digest:   74738ff5 5367 e958 9aee 98fffdcd1876 94028007
    // UUID (v5):     74738ff5-5367-5958-9aee-98fffdcd1876
    //                          ^_low nibble is set to 5 to indicate type 5
    //                                   ^_first two bits set to 1 and 0, respectively
    memcpy(uuid, sha_bits, 16);
    uuid[6] &= 0x0F;
    uuid[6] |= 0x50;
    uuid[8] &= 0x3F;
    uuid[8] |= 0x80;
  }

  /*_________________---------------------------__________________
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  static void removeContainerVNICLookup(EVMod *mod, HSPVMState_CONTAINERD *container) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    SFLAdaptor *ad;
    ADAPTORLIST_WALK(container->vm.interfaces, ad) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(ad);
      if(nio->ipAddr.type != SFLADDRESSTYPE_UNDEFINED) {
	HSPVNIC search = { };
	search.ipAddr = nio->ipAddr;
	HSPVNIC *vnic = UTHashDelKey(mdata->vnicByIP, &search);
	if(vnic) {
	  my_free(vnic->c_name);
	  my_free(vnic->c_hostname);
	  my_free(vnic);
	}
      }
    }
  }

  static void removeAndFreeVM_CONTAINERD(EVMod *mod, HSPVMState_CONTAINERD *container) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;

    EVDebug(mod, 1, "removeAndFreeVM: removing container with dsIndex=%u", container->vm.dsIndex);

    // remove any VNIC lookups by IP
    // (the interfaces will be removed completely in removeAndFreeVM() below)
    if(mdata->vnicByIP)
      removeContainerVNICLookup(mod, container);

    // remove from hash tables
    if(UTHashDel(mdata->vmsByID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (vmsByID) failed: container %s=%s", container->name, container->id);
      if(EVDebug(mod, 1, NULL))
	containerHTPrint(mdata->vmsByID, "vmsByID");
    }

    if(UTHashDel(mdata->vmsByUUID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (vmsByUUID) failed: container %s=%s", container->name, container->id);
      if(EVDebug(mod, 1, NULL))
	containerHTPrint(mdata->vmsByUUID, "vmsByUUID");
    }

    if(container->id) my_free(container->id);
    if(container->name) {
      // decNameCount(mdata->nameCount, container->name);
      my_free(container->name);
    }
    if(container->hostname) {
      // decNameCount(mdata->hostnameCount, container->hostname);
      my_free(container->hostname);
    }
    if(container->dup_name)
      mdata->dup_names--;
    if(container->dup_hostname)
      mdata->dup_hostnames--;
    removeAndFreeVM(mod, &container->vm);
  }

  static HSPVMState_CONTAINERD *getContainer(EVMod *mod, char *id, bool create, bool errorIfMissing) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(id == NULL) return NULL;
    HSPVMState_CONTAINERD cont = { .id = id };
    HSPVMState_CONTAINERD *container = UTHashGet(mdata->vmsByID, &cont);
    if(container == NULL
       && create) {
      char uuid[16];
      // turn container ID into a UUID - just take the first 16 bytes of the id
      if(parseUUID(id, uuid) == NO) {
	myLog(LOG_ERR, "parsing container UUID from <%s> - fall back on auto-generated", id);
	uuidgen_type5(sp, (u_char *)uuid, id);
      }

      // complain if we had to create one that we should have found already
      if(errorIfMissing)
	myLog(LOG_ERR, "found running container not detected by event: <%s>", id);

      container = (HSPVMState_CONTAINERD *)getVM(mod, uuid, YES, sizeof(HSPVMState_CONTAINERD), VMTYPE_CONTAINERD, agentCB_getCounters_CONTAINERD_request);
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

  static bool containerDone(EVMod *mod, HSPVMState_CONTAINERD *container) {
    return (container
	    && container->state != SFL_VIR_DOMAIN_RUNNING);
  }

  /*_________________---------------------------__________________
    _________________  updateContainerAdaptors  __________________
    -----------------___________________________------------------
  */

  static void updateContainerAdaptors(EVMod *mod, HSPVMState_CONTAINERD *container) {
    HSPVMState *vm = &container->vm;
    if(vm) {
      // reset the information that we are about to refresh
      markAdaptors_adaptorList(mod, vm->interfaces);
      // then refresh it
      readContainerInterfaces(mod, container);
      // and clean up
      deleteMarkedAdaptors_adaptorList(mod, vm->interfaces);
      adaptorListFreeMarked(vm->interfaces);
    }
  }

  /*_________________-----------------------------__________________
    _________________  updateContainerCgroupPaths __________________
    -----------------_____________________________------------------
  */

  static void updateContainerCgroupPaths(EVMod *mod, HSPVMState_CONTAINERD *container) {
    HSPVMState *vm = &container->vm;
    if(vm) {
      // open /proc/<pid>/cgroup
      char cgpath[HSP_CONTAINERD_MAX_FNAME_LEN+1];
      snprintf(cgpath, HSP_CONTAINERD_MAX_FNAME_LEN, PROCFS_STR "/%u/cgroup", container->pid);
      FILE *procFile = fopen(cgpath, "r");
      if(procFile) {
	char line[MAX_PROC_LINE_CHARS];
	int truncated;
	while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	  if(!truncated) {
	    // expect lines like 3:devices:<long_path>
	    int entryNo;
	    char type[MAX_PROC_LINE_CHARS];
	    char path[MAX_PROC_LINE_CHARS];
	    if(sscanf(line, "%d:%[^:]:%[^:]", &entryNo, type, path) == 3) {
	      if(my_strequal(type, "devices")) {
		if(!my_strequal(container->cgroup_devices, path)) {
		  if(container->cgroup_devices)
		    my_free(container->cgroup_devices);
		  container->cgroup_devices = my_strdup(path);
		  EVDebug(mod, 1, "containerd: container(%s)->cgroup_devices=%s", container->name, container->cgroup_devices);
		}
	      }
	    }
	  }
	}
	fclose(procFile);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   buildRegexPatterns      __________________
    -----------------___________________________------------------
  */
  static void buildRegexPatterns(EVMod *mod) {
    // HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
  }

  /*_________________---------------------------__________________
    _________________   host counter sample     __________________
    -----------------___________________________------------------
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(!hasVNodeRole(mod, HSP_VNODE_PRIORITY_CONTAINERD))
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
    _________________     container names       __________________
    -----------------___________________________------------------
  */

  static void setContainerName(EVMod *mod, HSPVMState_CONTAINERD *container, const char *name) {
    // HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    char *str = (char *)name;
    if(str && str[0] == '/') str++; // consume leading '/'
    if(my_strequal(str, container->name) == NO) {
      if(container->name) {
	// decNameCount(mdata->nameCount, container->name);
	my_free(container->name);
      }
      container->name = my_strdup(str);
      //if(incNameCount(mdata->nameCount, str) > 1) {
      //duplicateName(mod,container);
      //}
    }
  }
  
  static void setContainerHostname(EVMod *mod, HSPVMState_CONTAINERD *container, const char *hostname) {
    // HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    if(my_strequal(hostname, container->hostname) == NO) {
      if(container->hostname) {
	//decNameCount(mdata->hostnameCount, container->hostname);
	my_free(container->hostname);
      }
      EVDebug(mod, 1, "setContainerHostname assigning hostname=%s", hostname);
      container->hostname = my_strdup(hostname);
      //if(incNameCount(mdata->hostnameCount, hostname) > 1) {
      //	duplicateHostname(mod, container);
      //}
    }
  }

  /*_________________---------------------------__________________
    _________________           GPUs            __________________
    -----------------___________________________------------------
  */

  static void clearContainerGPUs(EVMod *mod, HSPVMState_CONTAINERD *container) {
    // clear out the list - we are single threaded on the
    // poll bus so there is no need for sync
    UTArray *arr = container->vm.gpus;
    HSPGpuID *entry;
    UTARRAY_WALK(arr, entry)
      my_free(entry);
    UTArrayReset(arr);
  }

  static void readContainerGPUsFromEnv(EVMod *mod, HSPVMState_CONTAINERD *container, cJSON *jenv) {
    // look through env vars for evidence of GPUs assigned to this container
    int entries = cJSON_GetArraySize(jenv);
    UTArray *arr = container->vm.gpus;
    for(int ii = 0; ii < entries; ii++) {
      cJSON *varval = cJSON_GetArrayItem(jenv, ii);
      if(varval) {
	char *vvstr = varval->valuestring;
	int vlen = strlen(HSP_NVIDIA_VIS_DEV_ENV);
	if(vvstr
	   && my_strnequal(vvstr, HSP_NVIDIA_VIS_DEV_ENV, vlen)
	   && vvstr[vlen] == '=') {
	  EVDebug(mod, 2, "parsing GPU env: %s", vvstr);
	  char *gpu_uuids = vvstr + vlen + 1;
	  clearContainerGPUs(mod, container);
	  // (re)populate
	  char *str;
	  char buf[128];
	  while((str = parseNextTok(&gpu_uuids, ",", NO, 0, YES, buf, 128)) != NULL) {
	    EVDebug(mod, 2, "parsing GPU uuidstr: %s", str);
	    // expect GPU-<uuid>
	    if(my_strnequal(str, "GPU-", 4)) {
	      HSPGpuID *gpu = my_calloc(sizeof(HSPGpuID));
	      if(parseUUID(str + 4, gpu->uuid)) {
		gpu->has_uuid = YES;
		EVDebug(mod, 2, "adding GPU uuid to container: %s", container->name);
		UTArrayAdd(arr, gpu);
		container->gpu_env = YES;
	      }
	      else {
		EVDebug(mod, 2, "GPU uuid parse failed");
		my_free(gpu);
	      }
	    }
	  }
	}
      }
    }
  }
  

  static void readContainerGPUsFromDev(EVMod *mod, HSPVMState_CONTAINERD *container) {
    // look through devices to see if individial GPUs are exposed
    char path[HSP_MAX_PATHLEN];
    sprintf(path, SYSFS_STR "/fs/cgroup/devices/%s/devices.list", container->cgroup_devices);
    FILE *procFile = fopen(path, "r");
    if(procFile) {
      UTArray *arr = container->vm.gpus;

      // if we already know this is our source of truth
      // for GPUs then clear the array now
      if(container->gpu_dev)
	clearContainerGPUs(mod, container);

      char line[MAX_PROC_LINE_CHARS];
      int truncated;
      while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	if(!truncated) {
	  // expect lines like "c 195:1 rwm"
	  // Note that if we don't have broad capabilities we
	  // will only see "a *:* rwm" here and it won't mean anything. For
	  // example, if hsflowd is running as a container/pod it will probably
	  // need to be invoked with privileged:true for this to work.
	  // TODO: figure out what capabilities are actually required.
	  char chr_blk;
	  int major,minor;
	  char permissions[MAX_PROC_LINE_CHARS];
	  if(sscanf(line, "%c %d:%d %s", &chr_blk, &major, &minor, permissions) == 4) {
	    if(major == HSP_MAJOR_NVIDIA
	       && minor < 255) {

	      if(!container->gpu_dev) {
		// Found one, so this is going to work. Establish
		// this as our source of truth for GPUs and clear
		// out any that might have been found another way.
		container->gpu_dev = YES;
		clearContainerGPUs(mod, container);
	      }
	      HSPGpuID *gpu = my_calloc(sizeof(HSPGpuID));
	      gpu->minor = minor;
	      gpu->has_minor = YES;
	      EVDebug(mod, 2, "adding GPU dev to container: %s", container->name);
	      UTArrayAdd(arr, gpu);
	    }
	  }
	}
      }
      fclose(procFile);
    }
  }

  /*_________________---------------------------__________________
    _________________       logField            __________________
    -----------------___________________________------------------
  */

  static void logField(char *msg, cJSON *obj, char *field)
  {
    cJSON *fieldObj = cJSON_GetObjectItem(obj, field);
    char *str = fieldObj ? cJSON_Print(fieldObj) : NULL;
    myLog(LOG_INFO, "%s %s=%s", msg, field, str ?: "<not found>");
    if(str)
      my_free(str);
  }

  /*_________________---------------------------__________________
    _________________     readContainerJSON     __________________
    -----------------___________________________------------------
  */

  static void readContainerJSON(EVMod *mod, cJSON *top, void *magic) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL) {
      // do nothing if we haven't settled on the config yet
      return;
    }
    HSPVMState_CONTAINERD *container = NULL;
    cJSON *jid = cJSON_GetObjectItem(top, "Id");

    if(jid)
      container = getContainer(mod, jid->valuestring, YES, NO);
    if(container == NULL)
      return;

    cJSON *jpid = cJSON_GetObjectItem(top, "Pid");
    if(jpid)
      container->pid = (pid_t)jpid->valueint;
    
    cJSON *jmetrics = cJSON_GetObjectItem(top, "Metrics");
    if(!jmetrics)
      return;

    bool isSandbox = NO;
    cJSON *jnames = cJSON_GetObjectItem(jmetrics, "Names");
    if(jnames) {
      cJSON *jcgpth = cJSON_GetObjectItem(jnames, "CgroupsPath");
      if(jcgpth) {
	EVDebug(mod, 1, "cgroupspath=%s\n", jcgpth->valuestring);
      }
      if(EVDebug(mod, 1, NULL)) {
	logField(" ", jnames, "Image");
	logField(" ", jnames, "Hostname");
	logField(" ", jnames, "ContainerName");
	logField(" ", jnames, "ContainerType");
	logField(" ", jnames, "SandboxName");
	logField(" ", jnames, "SandboxNamespace");
	logField(" ", jnames, "ImageName");
      }
    }
    
    // TODO: skip "k8s_POD_*" containers
    // (or make that a config setting)
    // But maybe that doesn't happen with containerd?  Not
    // seeing them here.

    setContainerName(mod, container, jid->valuestring);
    
    cJSON *jn = cJSON_GetObjectItem(jnames, "ContainerName");
    cJSON *jt = cJSON_GetObjectItem(jnames, "ContainerType");
    cJSON *jhn = cJSON_GetObjectItem(jnames, "Hostname");
    cJSON *jsn = cJSON_GetObjectItem(jnames, "SandboxName");
    cJSON *jsns = cJSON_GetObjectItem(jnames, "SandboxNamespace");
    if(jhn) {
      // From kubernetes/pgk/kubelet/dockershim/naming.go
      // Sandbox
      // k8s_POD_{s.name}_{s.namespace}_{s.uid}_{s.attempt}
      // Container
      // k8s_{c.name}_{s.name}_{s.namespace}_{s.uid}_{c.attempt}

      // Match the Kubernetes docker_inspect output by combining these strings into
      // the form k8s_<containername>_<sandboxname>_<sandboxnamespace>_<sandboxuser>_<c.attempt>
      // pull out name, hostname, sandboxname and sandboxnamespace
      char *jn_s = (jn && strlen(jn->valuestring)) ? jn->valuestring : NULL;
      char *jt_s = (jt && strlen(jt->valuestring)) ? jt->valuestring : NULL;
      char *jhn_s = (jhn && strlen(jhn->valuestring)) ? jhn->valuestring : NULL;
      char *jsn_s = (jsn && strlen(jsn->valuestring)) ? jsn->valuestring : NULL;
      char *jsns_s = (jsns && strlen(jsns->valuestring)) ? jsns->valuestring : NULL;
      // container name can be empty, so if it ends up being the
      // same as the sandbox name or hostname then we leave it out to save space (and to
      // prevent the combination of namespace.containername from exploding unexpectedly)
      if(my_strequal(jn_s, jsn_s))
	jn_s = NULL;
      if(my_strequal(jn_s, jhn_s))
	jn_s = NULL;
      // assemble,  with fake 'uid' and 'attempt' fields since we don't know them,
      // but trying not to use up all the quota for the sFlow string.
#define MY_MAX_HOSTNAME_CHARS 255 // override sFlow standard of SFL_MAX_HOSTNAME_CHARS (64)
      char compoundName[MY_MAX_HOSTNAME_CHARS+1];
      snprintf(compoundName, MY_MAX_HOSTNAME_CHARS, "k8s_%s_%s_%s_u_a",
	       jn_s ?: "",
	       jsn_s ?: (jhn_s ?: ""),
	       jsns_s ?: "");
      // and assign to hostname
      setContainerHostname(mod, container, compoundName);
      // remember if containerType is sandbox
      if(my_strequal(jt_s, "sandbox"))
	isSandbox = YES;
    }
    
    cJSON *jcpu = cJSON_GetObjectItem(jmetrics, "Cpu");
    if(jcpu) {
      // TODO: get status from data.  With containerd it is the Process Status string
      container->state = SFL_VIR_DOMAIN_RUNNING;
      
      cJSON *jcputime = cJSON_GetObjectItem(jcpu, "CpuTime");
      if(jcputime) {
	container->cpu_total = jcputime->valuedouble;
      }
      cJSON *jcpucount = cJSON_GetObjectItem(jcpu, "CpuCount");
      if(jcpucount)
	container->cpu_count = jcpucount->valueint;
    }
    cJSON *jmem = cJSON_GetObjectItem(jmetrics, "Mem");
    if(jmem) {
      cJSON *jm = cJSON_GetObjectItem(jmem, "Memory");
      if(jm)
	container->mem_usage = jm->valuedouble; // TODO: units?
      cJSON *jmm = cJSON_GetObjectItem(jmem, "MaxMemory");
      if(jmm)
	container->memoryLimit = jmm->valuedouble; // TODO: units?
    }
    
    cJSON *jnet = cJSON_GetObjectItem(jmetrics, "Net");
    if(jnet) {
    }
    cJSON *jdsk = cJSON_GetObjectItem(jmetrics, "Dsk");
    if(jdsk) {
      cJSON *jrd_req = cJSON_GetObjectItem(jdsk, "Rd_req");
      cJSON *jwr_req = cJSON_GetObjectItem(jdsk, "Wr_req");
      cJSON *jrd_bytes = cJSON_GetObjectItem(jdsk, "Rd_bytes");
      cJSON *jwr_bytes = cJSON_GetObjectItem(jdsk, "Wr_bytes");
      if(jrd_req)
	container->dsk.rd_req = jrd_req->valuedouble;
      if(jwr_req)
	container->dsk.wr_req = jwr_req->valuedouble;
      if(jrd_bytes)
	container->dsk.rd_bytes = jrd_bytes->valuedouble;
      if(jwr_bytes)
	container->dsk.wr_bytes = jwr_bytes->valuedouble;
    }

    
    // now that we have the pid,  we can probe for the MAC and peer-ifIndex
    // see if spacing the VNIC refresh reduces load
    time_t now_mono = mdata->pollBus->now.tv_sec;
    if(container->last_vnic == 0
       || (now_mono - container->last_vnic) > HSP_VNIC_REFRESH_TIMEOUT) {
      container->last_vnic = now_mono;
      // Each pod appears to have one container with type "sandbox" and
      // one or more with type "container".  Although it is the containers
      // that send/receive traffic it is potentially expensive to resolve
      // which of them it was on a sample-by-sample basis.  That's because
      // they share the same network namespace so the (inner) IP address
      // is not enough and we would have to look up the container by following
      // the TCP/UDP socket inode to PID (see mod_systemd). If that socket
      // lookup can be done efficiently (e.g. by using a network namespace
      // parameter in the netlink DIAG call) then we can try it,  but for
      // now we will associate traffic with the sandbox container, effectively
      // appointing it as the representative for the pod.
      if(isSandbox)
	updateContainerAdaptors(mod, container);
    }

    if(container->last_cgroup == 0
       || (now_mono - container->last_cgroup) > HSP_CGROUP_REFRESH_TIMEOUT) {
      container->last_cgroup = now_mono;
      updateContainerCgroupPaths(mod, container);
    }

    cJSON *jenv = cJSON_GetObjectItem(top, "Env");
    if(jenv
       && container->gpu_dev == NO)
      readContainerGPUsFromEnv(mod, container, jenv);

    if(container->cgroup_devices)
      readContainerGPUsFromDev(mod, container);

    // and send the counter sample right away
    getCounters_CONTAINERD(mod, container);
    // maybe this was the last one?
    if(containerDone(mod, container))
      removeAndFreeVM_CONTAINERD(mod, container);
  }
  
  static void readContainerData(EVMod *mod, char *str, void *magic) {
    // HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    int prefixLen = strlen(HSP_CONTAINERD_DATAPREFIX);
    if(memcmp(str, HSP_CONTAINERD_DATAPREFIX, prefixLen) == 0) {
      cJSON *top = cJSON_Parse(str + prefixLen);
      readContainerJSON(mod, top, magic);
      cJSON_Delete(top);
    }
  }
  
  static void readContainerCB(EVMod *mod, EVSocket *sock, EnumEVSocketReadStatus status, void *magic) {
    // HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    switch(status) {
    case EVSOCKETREAD_AGAIN:
      break;
    case EVSOCKETREAD_STR:
      // UTStrBuf_chomp(sock->ioline);
      EVDebug(mod, 1, "readContainerCB: %s", UTSTRBUF_STR(sock->ioline));
      readContainerData(mod, UTSTRBUF_STR(sock->ioline), magic);
      UTStrBuf_reset(sock->ioline);
      break;
    case EVSOCKETREAD_EOF:
      EVDebug(mod, 1, "readContainerCB EOF");
      break;
    case EVSOCKETREAD_BADF:
      EVDebug(mod, 1, "readContainerCB BADF");
      break;
    case EVSOCKETREAD_ERR:
      EVDebug(mod, 1, "readContainerCB ERR");
      break;
    }
  }
  
  /*_________________---------------------------__________________
    _________________    evt_flow_sample        __________________
    -----------------___________________________------------------
    Packet Bus
  */

  static uint32_t containerDSByMAC(EVMod *mod, SFLMacAddress *mac) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *adaptor = adaptorByMac(sp, mac);
    if(adaptor) {
      uint32_t c_dsi = ADAPTOR_NIO(adaptor)->container_dsIndex;
      EVDebug(mod, 2, "containerDSByMAC matched %s ds=%u\n", adaptor->deviceName, c_dsi);
      // make sure it wasn't marked as "non-unique"
      if(c_dsi != 0xFFFFFFFF)
	return c_dsi;
    }
    return 0;
  }

  static uint32_t containerDSByIP(EVMod *mod, SFLAddress *ipAddr) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSPVNIC search = { };
    search.ipAddr = *ipAddr;
    HSPVNIC *vnic = UTHashGet(mdata->vnicByIP, &search);
    if(vnic) {
      EVDebug(mod, 2, "VNIC: got src %s (unique=%s, ds=%u)\n",
	      vnic->c_hostname,
	      vnic->unique ? "YES" : "NO",
	      vnic->dsIndex);
      if(vnic->unique)
	return vnic->dsIndex;
    }
    return 0;
  }
  
  static bool lookupContainerDS(EVMod *mod, HSPPendingSample *ps, uint32_t *p_src_dsIndex, uint32_t *p_dst_dsIndex) {
    // start with the one most likely to match
    // e.g. in Kubernetes with Calico IPIP or VXLAN this will be the innerIP:
    if(ps->gotInnerIP) {
      char sbuf[51],dbuf[51];
      *p_src_dsIndex = containerDSByIP(mod, &ps->src_1);
      *p_dst_dsIndex = containerDSByIP(mod, &ps->dst_1);
      
      EVDebug(mod, 3, "lookupContainerDS: search by inner IP: src=%s dst=%s srcDS=%u dstDS=%u",
	      SFLAddress_print(&ps->src_1, sbuf, 50),
	      SFLAddress_print(&ps->dst_1, dbuf, 50),
	      *p_src_dsIndex,
	      *p_dst_dsIndex);
      
      if(*p_src_dsIndex || *p_dst_dsIndex)
	return YES;
    }
    if(ps->gotInnerMAC) {
      *p_src_dsIndex = containerDSByMAC(mod, &ps->macsrc_1);
      *p_dst_dsIndex = containerDSByMAC(mod, &ps->macdst_1);
      if(*p_src_dsIndex || *p_dst_dsIndex)
	return YES;
    }
    if(ps->l3_offset) {
      // outer IP
      *p_src_dsIndex = containerDSByIP(mod, &ps->src);
      *p_dst_dsIndex = containerDSByIP(mod, &ps->dst);
      if(*p_src_dsIndex || *p_dst_dsIndex)
	return YES;
    }
    if(ps->hdr_protocol == SFLHEADER_ETHERNET_ISO8023) {
      // outer MAC
      *p_src_dsIndex = containerDSByMAC(mod, &ps->macsrc);
      *p_dst_dsIndex = containerDSByMAC(mod, &ps->macdst);
      if(*p_src_dsIndex || *p_dst_dsIndex)
	return YES;
    }
    return NO;
  }
  
  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSPPendingSample *ps = (HSPPendingSample *)data;
    decodePendingSample(ps);
    uint32_t src_dsIndex=0, dst_dsIndex=0;
    if(lookupContainerDS(mod, ps, &src_dsIndex, &dst_dsIndex)) {
      SFLFlow_sample_element *entElem = pendingSample_calloc(ps, sizeof(SFLFlow_sample_element));
      entElem->tag = SFLFLOW_EX_ENTITIES;
      if(src_dsIndex
	 && src_dsIndex != 0xFFFFFFFF) {
	entElem->flowType.entities.src_dsClass = SFL_DSCLASS_LOGICAL_ENTITY;
	entElem->flowType.entities.src_dsIndex = src_dsIndex;
      }
      if(dst_dsIndex
	 && dst_dsIndex != 0xFFFFFFFF) {
	entElem->flowType.entities.dst_dsClass = SFL_DSCLASS_LOGICAL_ENTITY;
	entElem->flowType.entities.dst_dsIndex = dst_dsIndex;
      }
      SFLADD_ELEMENT(ps->fs, entElem);
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_cfg_done           __________________
    -----------------___________________________------------------
  */

  static void readCB(EVMod *mod, EVSocket *sock, void *magic) {
    EVSocketReadLines(mod, sock, readContainerCB, NO, magic);
  }

  static void evt_cfg_done(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mdata->configRevisionNo = sp->revisionNo;
  }

  /*_________________---------------------------__________________
    _________________    tick,tock              __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    //HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
  }

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    if(mdata->configRevisionNo
       && mdata->readerPid == 0) {
      // Could pass debugLevel to reader like this:
      // char level[16];
      // snprintf(level, 16, "%u", getDebug());
      // char *cmd[] = { HSP_CONTAINERD_READER, "--debugLevel", level,  NULL };
      // but can always debug reader separately, so just invoke it like this:
      char *cmd[] = { HSP_CONTAINERD_READER, NULL };
      mdata->readerPid = EVBusExec(mod, mdata->pollBus, mdata, cmd, readCB);
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_containerd(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_CONTAINERD));
    HSP_mod_CONTAINERD *mdata = (HSP_mod_CONTAINERD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    struct stat statBuf;
    if(sp->docker.docker == YES
       && stat("/var/run/docker.sock", &statBuf) == 0) {
      EVDebug(mod, 1, "not enabling mod_containerd because mod_docker is running and docker.sock is present");
      return;
    }

    // ask to retain root privileges
    retainRootRequest(mod, "needed to access containerd.sock");
    retainRootRequest(mod, "needed by mod_containerd to probe for adaptors in other namespaces");

    requestVNodeRole(mod, HSP_VNODE_PRIORITY_CONTAINERD);

    buildRegexPatterns(mod);
    mdata->vmsByUUID = UTHASH_NEW(HSPVMState_CONTAINERD, vm.uuid, UTHASH_DFLT);
    mdata->vmsByID = UTHASH_NEW(HSPVMState_CONTAINERD, id, UTHASH_SKEY);
    mdata->nameCount = UTHASH_NEW(HSPContainerNameCount, name, UTHASH_SKEY);
    mdata->hostnameCount = UTHASH_NEW(HSPContainerNameCount, name, UTHASH_SKEY);
    mdata->cgroupPathIdx = -1;
    
    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TOCK), evt_tock);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_DONE), evt_cfg_done);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);

    if(sp->containerd.markTraffic) {
      EVBus *packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
      EVEventRx(mod, EVGetEvent(packetBus, HSPEVENT_FLOW_SAMPLE), evt_flow_sample);
      mdata->vnicByIP = UTHASH_NEW(HSPVNIC, ipAddr, UTHASH_SYNC); // need sync (poll + packet thread)

      // learn my own namespace inode from /proc/self/ns/net
      if(stat("/proc/self/ns/net", &mdata->myNS) == 0)
	EVDebug(mod, 1, "my namespace dev.inode == %u.%u",
		mdata->myNS.st_dev,
		mdata->myNS.st_ino);
    }
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
