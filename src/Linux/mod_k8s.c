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
#include <uuid/uuid.h>
#include <fnmatch.h>

#include "hsflowd.h"
#include "cpu_utils.h"
#include "math.h"
#include "util_netlink.h"

  // limit the number of chars we will read from each line
  // (there can be more than this - my_readline will chop for us)
#define MAX_PROC_LINE_CHARS 320

#include "cJSON.h"

  typedef struct _HSPK8sContainerStats {
    uint32_t state; // SFLVirDomainState
    uint64_t memoryLimit;
    uint32_t cpu_count;
    double cpu_count_dbl;
    uint64_t cpu_total;
    uint64_t mem_usage;
    SFLHost_nio_counters net;
    SFLHost_vrt_dsk_counters dsk;
  } HSPK8sContainerStats;
   
  typedef struct _HSPK8sContainer {
    char *id;
    char *name;
    pid_t pid;
    bool isSandbox;
    HSPK8sContainerStats stats;
  } HSPK8sContainer;

  typedef struct _HSPVMState_POD {
    HSPVMState vm; // superclass: must come first
    char *hostname;
    uint32_t /*pid_t*/ nspid; // selected from containers
    uint32_t state; // SFLVirDomainState - from containers
    bool gpu_dev_tried:1;
    bool gpu_dev:1;
    bool gpu_env_tried:1;
    bool gpu_env:1;
    time_t last_heard;
    time_t last_vnic;
    time_t last_cgroup;
    char *cgroup_devices;
    UTHash *containers;
    uint64_t cgroup_id;
    uint32_t nsid; // network namespace id (for nspid->nsid->dev)
    uint32_t ifIndex; // vport
  } HSPVMState_POD;

#define HSP_K8S_READER "/usr/sbin/hsflowd_containerd"
#define HSP_K8S_DATAPREFIX "data>"
#define HSP_K8S_CTRPREFIX "ctr>"

#define HSP_K8S_MAX_FNAME_LEN 255
#define HSP_K8S_MAX_LINELEN 512
#define HSP_K8S_SHORTID_LEN 12

#define HSP_K8S_WAIT_NOSOCKET 10
#define HSP_K8S_WAIT_EVENTDROP 5
#define HSP_K8S_WAIT_STARTUP 2
#define HSP_K8S_WAIT_RECHECK 120
#define HSP_K8S_WAIT_STATS 3
#define HSP_K8S_REQ_TIMEOUT 10

#define HSP_NVIDIA_VIS_DEV_ENV "NVIDIA_VISIBLE_DEVICES"
#define HSP_MAJOR_NVIDIA 195

#define MY_MAX_HOSTNAME_CHARS 255 // override sFlow standard of SFL_MAX_HOSTNAME_CHARS (64)

  typedef struct _HSPVnicMAC {
    SFLMacAddress mac;
    uint32_t nspid;
    uint32_t ifIndex;
    uint32_t dsIndex;
    UTHash *owners; // set of containers
  } HSPVnicMAC;

  typedef struct _HSPVnicIP {
    SFLAddress ipAddr;
    HSPVnicMAC *vnicMAC;
  } HSPVnicIP;

#define HSP_VNIC_REFRESH_TIMEOUT 300
#define HSP_CGROUP_REFRESH_TIMEOUT 600

  typedef struct _HSP_mod_K8S {
    EVBus *pollBus;
    UTHash *podsByHostname;
    UTHash *podsByCgroupId;
    UTHash *containersByID;
    SFLCounters_sample_element vnodeElem;
    UTHash *vnicByMAC;
    UTHash *vnicByIP;
    uint32_t configRevisionNo;
    pid_t readerPid;
    int idleSweepCountdown;
    char *cgroup_path;
    char *cgroup_devices_path;
    uint32_t ds_byMAC;
    uint32_t ds_byInnerMAC;
    uint32_t ds_byIP;
    uint32_t ds_byInnerIP;
    uint32_t pod_byAddr;
    uint32_t pod_byCgroup;
    EVEvent *rtmetricEvent;
    uint32_t c_readCB;
    uint32_t c_readContainerCB;
    int nl_sock;
    EVSocket *evSoc;
    uint32_t seq_no;
    EVEvent *evt_get_nsid;
    EVEvent *evt_get_tap;
  } HSP_mod_K8S;

  /*_________________---------------------------__________________
    _________________    utils to help debug    __________________
    -----------------___________________________------------------
  */

  char *podStr(HSPVMState_POD *pod, char *buf, int bufLen) {
    u_char uuidstr[100];
    printUUID((u_char *)pod->vm.uuid, uuidstr, 100);
    snprintf(buf, bufLen, "hostname: %s uuid: %s containers: %u",
	     pod->hostname,
	     uuidstr,
	     UTHashN(pod->containers));
    return buf;
  }

  void podHTPrint(UTHash *ht, char *prefix) {
    char buf[1024];
    HSPVMState_POD *pod;
    UTHASH_WALK(ht, pod)
      myLog(LOG_INFO, "%s: %s", prefix, podStr(pod, buf, 1024));
  }

  /*________________---------------------------__________________
    ________________    readCgroupPaths        __________________
    ----------------___________________________------------------
  */

  static void readCgroupPaths(EVMod *mod) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    char mpath[HSP_K8S_MAX_FNAME_LEN+1];
    snprintf(mpath, HSP_K8S_MAX_FNAME_LEN, PROCFS_STR "mounts");
    FILE *procFile = fopen(mpath, "r");
    if(procFile) {
      // limit the number of chars we will read from each line
      // (there can be more than this - my_readline will chop for us)
      char line[MAX_PROC_LINE_CHARS];
      int truncated;
      while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
	char buf[MAX_PROC_LINE_CHARS];
	char *p = line;
	char *fsType = parseNextTok(&p, " ", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	if(my_strequal(fsType, "cgroup2")) {
	  char *fsPath = parseNextTok(&p, " ", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	  if(fsPath) {
	    EVDebug(mod, 1, "found cgroup2 path = %s", fsPath);
	    mdata->cgroup_path = my_strdup(fsPath);
	  }
	}
	// devices controller is still cgroups v1
	if(my_strequal(fsType, "cgroup")) {
	  char *fsPath = parseNextTok(&p, " ", NO, '\0', NO, buf, MAX_PROC_LINE_CHARS);
	  if(fsPath
	     && fnmatch("*/devices", fsPath, 0) == 0) {
	    EVDebug(mod, 1, "found cgroup devices controller path = %s", fsPath);
	    mdata->cgroup_devices_path = my_strdup(fsPath);
	  }
	}
      }
      fclose(procFile);
    }
  }

  /*________________---------------------------__________________
    ________________     podLinkCB             __________________
    ----------------___________________________------------------
  callback from readVNIC.c
  */

  static void mapIPToPod(EVMod *mod, HSPVMState *vm, SFLMacAddress *mac, SFLAddress *ipAddr, uint32_t nspid) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    if(!mdata->vnicByMAC)
      return;
    HSPVMState_POD *pod = (HSPVMState_POD *)vm;
    HSPVnicMAC searchMAC = { .mac = *mac };
    HSPVnicMAC *vnicMAC = UTHashGet(mdata->vnicByMAC, &searchMAC);
    if(vnicMAC) {
      UTHashAdd(vnicMAC->owners, pod);
    }
    else {
      // add new VNIC entry
      vnicMAC = (HSPVnicMAC *)my_calloc(sizeof(HSPVnicMAC));
      vnicMAC->dsIndex = pod->vm.dsIndex;
      // vnicMAC->ifIndex = adaptor->ifIndex; // we now learn this ifIndex later
      vnicMAC->nspid = nspid;
      UTHashAdd(mdata->vnicByMAC, vnicMAC);
      vnicMAC->owners = UTHASH_NEW(HSPVMState_POD, hostname, UTHASH_SKEY);
      UTHashAdd(vnicMAC->owners, pod);
    }
    if(ipAddr) {
      HSPVnicIP searchIP = { .ipAddr = *ipAddr };
      HSPVnicIP *vnicIP = UTHashGet(mdata->vnicByIP, &searchIP);
      if(vnicIP) {
	// TODO: should we be checking for uniqueness of IP to MAC too?
	// And/or uniqueness of IP to container?
      }
      else {
	// add new VnicIP entry
	vnicIP = (HSPVnicIP *)my_calloc(sizeof(HSPVnicIP));
	vnicIP->ipAddr = *ipAddr;
	vnicIP->vnicMAC = vnicMAC;
	UTHashAdd(mdata->vnicByIP, vnicIP);
      }
    }
  }

  /*________________-----------------------__________________
    ________________   getCounters_POD     __________________
    ----------------_______________________------------------
  */
  static void getCounters_POD(EVMod *mod, HSPVMState_POD *pod)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFL_COUNTERS_SAMPLE_TYPE cs = { 0 };
    HSPVMState *vm = (HSPVMState *)&pod->vm;

    if(sp->sFlowSettings == NULL) {
      // do nothing if we haven't settled on the config yet
      return;
    }

    // accumulate CPU, mem, diskI/O counters from containers
    EVDebug(mod, 2, "getCounters_POD(): pod %s has %u containers",
	    pod->hostname,
	    UTHashN(pod->containers));

    HSPK8sContainerStats stats = { 0 };
    HSPK8sContainer *container;
    UTHASH_WALK(pod->containers, container) {
      if(container->stats.state == SFL_VIR_DOMAIN_RUNNING) {
	stats.state = SFL_VIR_DOMAIN_RUNNING;
      }
      stats.cpu_count += container->stats.cpu_count;
      EVDebug(mod, 2, "getCounters_POD(): container %s has cpu_count %u (total now = %u)",
	      container->name,
	      container->stats.cpu_count,
	      stats.cpu_count);
      stats.cpu_total += container->stats.cpu_total;
      stats.mem_usage += container->stats.mem_usage;
      stats.memoryLimit += container->stats.memoryLimit;
      stats.dsk.capacity += container->stats.dsk.capacity;
      stats.dsk.allocation += container->stats.dsk.allocation;
      stats.dsk.available += container->stats.dsk.available;
      stats.dsk.rd_req += container->stats.dsk.rd_req;
      stats.dsk.rd_bytes += container->stats.dsk.rd_bytes;
      stats.dsk.wr_req += container->stats.dsk.wr_req;
      stats.dsk.wr_bytes += container->stats.dsk.wr_bytes;
      stats.dsk.errs += container->stats.dsk.errs;
      // TODO: accumulate net counters too?  (If they appear)
    }

    // TODO: how to detect that a POD has stopped?  No containers running?
    pod->state = stats.state;
    
    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    char *hname = pod->hostname;
    hidElem.counterBlock.host_hid.hostname.str = hname;
    hidElem.counterBlock.host_hid.hostname.len = my_strlen(hname);
    memcpy(hidElem.counterBlock.host_hid.uuid, vm->uuid, 16);

    // for pods we can show the same OS attributes as the parent
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
    memcpy(&nioElem.counterBlock.host_vrt_nio, &stats.net, sizeof(stats.net));
    SFLADD_ELEMENT(&cs, &nioElem);

    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    cpuElem.counterBlock.host_vrt_cpu.state = pod->state;
    cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = stats.cpu_count ?: (uint32_t)round(stats.cpu_count_dbl);
    cpuElem.counterBlock.host_vrt_cpu.cpuTime = (uint32_t)(stats.cpu_total / 1000000); // convert to mS
    SFLADD_ELEMENT(&cs, &cpuElem);

    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
    memElem.counterBlock.host_vrt_mem.memory = stats.mem_usage;
    memElem.counterBlock.host_vrt_mem.maxMemory = stats.memoryLimit;
    SFLADD_ELEMENT(&cs, &memElem);

    // VM disk I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
    // TODO: fill in capacity, allocation, available fields
    memcpy(&dskElem.counterBlock.host_vrt_dsk, &stats.dsk, sizeof(stats.dsk));
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

  static void agentCB_getCounters_POD_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    // this is a no-op, the Go program drives the counter-reporting
  }

  /*_________________---------------------------__________________
    _________________    name_uuid              __________________
    -----------------___________________________------------------
  */

  static void uuidgen_type5(HSP *sp, u_char *uuid, char *name) {
    int len = my_strlen(name);
    // also hash in agent IP address in case sp->uuid is missing or not unique
    int addrLen = sp->agentIP.type == SFLADDRESSTYPE_IP_V6 ? 16 : 4;
    char *buf = (char *)UTHeapQNew(len + addrLen);
    memcpy(buf, name, len);
    memcpy(buf + len, &sp->agentIP.address, addrLen);
    uuid_generate_sha1(uuid, (u_char *)sp->uuid, buf, len + addrLen);
  }

  /*_________________---------------------------__________________
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  static void removePodVNICLookup(EVMod *mod, HSPVMState_POD *pod) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    if(mdata->vnicByMAC) {
      UTArray *macRefs = UTArrayNew(UTARRAY_DFLT);
      HSPVnicMAC *vnicMAC;
      UTHASH_WALK(mdata->vnicByMAC, vnicMAC) {
	if(UTHashDelKey(vnicMAC->owners, pod)) {
	  if(UTHashN(vnicMAC->owners) == 0) {
	    // no owners - mark for removal
	    UTArrayAdd(macRefs, vnicMAC);
	    // but first remove all IP references to it
	    UTArray *ipRefs = UTArrayNew(UTARRAY_DFLT);
	    HSPVnicIP *vnicIP;
	    UTHASH_WALK(mdata->vnicByIP, vnicIP) {
	      if(vnicIP->vnicMAC == vnicMAC)
		UTArrayAdd(ipRefs, vnicIP);
	    }
	    UTARRAY_WALK(ipRefs, vnicIP) {
	      UTHashDelKey(mdata->vnicByIP, vnicIP);
	      my_free(vnicIP);
	    }
	    UTArrayFree(ipRefs);
	  }
	}
      }
      UTARRAY_WALK(macRefs, vnicMAC) {
	UTHashDelKey(mdata->vnicByMAC, vnicMAC);
	UTHashFree(vnicMAC->owners);
	my_free(vnicMAC);
      }
      UTArrayFree(macRefs);
    }
  }

  static void removeAndFreeContainer(EVMod *mod, HSPK8sContainer *container) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    EVDebug(mod, 1, "removeAndFreeContainer: removing container %s=%s", container->name, container->id);
    
    // remove from hash table
    if(UTHashDel(mdata->containersByID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (containerssByID) failed: container %s=%s", container->name, container->id);
    }

    if(container->id)
      my_free(container->id);
    if(container->name)
      my_free(container->name);
    
    my_free(container);
  }

  static void removeAndFreeVM_POD(EVMod *mod, HSPVMState_POD *pod) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    EVDebug(mod, 1, "removeAndFreeVM: removing pod with dsIndex=%u", pod->vm.dsIndex);

    // remove any VNIC lookups by IP (this semaphore-protected hash table is point
    // of contact between poll thread and packet thread).
    // (the interfaces will be removed completely in removeAndFreeVM() below)
    if(mdata->vnicByIP)
      removePodVNICLookup(mod, pod);
    
    HSPK8sContainer *container;
    UTHASH_WALK(pod->containers, container)
      removeAndFreeContainer(mod, container);

    UTHashFree(pod->containers);

    // remove from hash tables
    if(UTHashDel(mdata->podsByHostname, pod) == NULL) {
      myLog(LOG_ERR, "UTHashDel (podsByHostname) failed: pod %s", pod->hostname);
      if(EVDebug(mod, 1, NULL))
	podHTPrint(mdata->podsByHostname, "podsByHostname");
    }
    if(pod->cgroup_id
       && UTHashDel(mdata->podsByCgroupId, pod) == NULL) {
      myLog(LOG_ERR, "UTHashDel (podsByCgroupId) failed: pod %s", pod->hostname);
      if(EVDebug(mod, 1, NULL))
	podHTPrint(mdata->podsByCgroupId, "podsByCgroupId");
    }

    if(pod->hostname)
      my_free(pod->hostname);

    removeAndFreeVM(mod, &pod->vm);
  }

  static HSPVMState_POD *getPod(EVMod *mod, char *hostname, char *cgpath, bool create) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPVMState_POD search = { .hostname = hostname };
    HSPVMState_POD *pod = UTHashGet(mdata->podsByHostname, &search);
    if(pod == NULL
       && create) {
      char uuid[16];
      // turn hostname string into a type 5 UUID
      uuidgen_type5(sp, (u_char *)uuid, hostname);
      // and use that to look up the datasource
      pod = (HSPVMState_POD *)getVM(mod, uuid, YES, sizeof(HSPVMState_POD), VMTYPE_POD, agentCB_getCounters_POD_request);
      assert(pod != NULL);
      if(pod) {
	pod->state = SFL_VIR_DOMAIN_RUNNING;
	pod->hostname = my_strdup(hostname);
	// add to collections
	UTHashAdd(mdata->podsByHostname, pod);
	// collection of child containers
	pod->containers = UTHASH_NEW(HSPK8sContainer, id, UTHASH_SKEY);
	if(cgpath
	   && mdata->cgroup_path) {
	  // get inode that TCP DIAG will report as 'cgroup_id'
	  char path[HSP_K8S_MAX_FNAME_LEN];
	  snprintf(path, HSP_K8S_MAX_FNAME_LEN, "%s/%s", mdata->cgroup_path, cgpath);
	  struct stat statBuf = {};
	  if(stat(path, &statBuf) == 0) {
	    pod->cgroup_id = statBuf.st_ino;
	    EVDebug(mod, 1, "Learned cgroup_id = %"PRIu64" for pod %s",
		    pod->cgroup_id,
		    pod->hostname);
	    // remember this for packet sample lookup
	    UTHashAdd(mdata->podsByCgroupId, pod);
	  }
	}
      }
    }
    return pod;
  }
  
  static bool podDone(EVMod *mod, HSPVMState_POD *pod) {
    return (pod
	    && pod->state != SFL_VIR_DOMAIN_RUNNING);
  }

  /*_________________---------------------------__________________
    _________________  add and remove container __________________
    -----------------___________________________------------------
  */

  static HSPVMState_POD *podAddContainer(EVMod *mod, HSPVMState_POD *pod, HSPK8sContainer *container) {
    return UTHashGetOrAdd(pod->containers, container);
  }

  static HSPK8sContainer *getContainer(EVMod *mod, char *id, bool create) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    if(id == NULL)
      return NULL;
    HSPK8sContainer cont = { .id = id };
    HSPK8sContainer *container = UTHashGet(mdata->containersByID, &cont);
    if(container == NULL
       && create) {
      container = (HSPK8sContainer *)UTHeapQNew(sizeof(HSPK8sContainer));
      container->id = my_strdup(id);
      // add to collection
      UTHashAdd(mdata->containersByID, container);
    }
    return container;
  }

  /*_________________---------------------------__________________
    _________________   updatePodNSID           __________________
    -----------------___________________________------------------
    look up the associated nsid via NETLINK_ROUTE
    (api provided by mod_nlroute)
  */
  
  static void evt_get_nsid_ans(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    EVDebug(mod, 1, "evt_get_nsid_ans: dataLen=%u", dataLen);
    if(dataLen == sizeof(HSPGetNSID)) {
      HSPGetNSID get_nsid;
      memcpy(&get_nsid, data, dataLen);
      if(get_nsid.found) {
	EVDebug(mod, 1, "evt_get_nsid_ans: nspid %u -> nsid %u (ds_index=%u)",
		get_nsid.nspid,
		get_nsid.nsid,
		get_nsid.dsIndex);
	HSPVMState_POD *pod = (HSPVMState_POD *)getVM_byDS(mod, get_nsid.dsIndex);
	if(pod) {
	  EVDebug(mod, 1, "evt_get_nsid_ans: nsid %u->%u to pod %s",
		  pod->nsid,
		  get_nsid.nsid,
		  pod->hostname);
	  pod->nsid = get_nsid.nsid;
	  SFLAdaptor *adaptor = adaptorByNETNSID(sp, pod->nsid);
	  if(adaptor) {
	    // setting the vm_or_container flag triggers "bridgeModel" treatment
	    // when we submit packet samples associated with this adaptor
	    ADAPTOR_NIO(adaptor)->vm_or_container = YES;
	    
	    uint32_t ifIndex = adaptor->ifIndex;
	    pod->ifIndex = ifIndex;
	    EVDebug(mod, 1, "evt_get_nsid_ans: request tap on device %s (ifIndex=%u)", adaptor->deviceName, ifIndex);
	    EVEventTx(mod, mdata->evt_get_tap, &ifIndex, sizeof(ifIndex));
	    // We might still take one more step here and remember that any packets
	    // seen at this adaptor must be to or from that pod,  but we still have
	    // to use the MAC addresses to decide on in/out direction, so I think that means
	    // we rely on the readVNICInterfaces() step to harvest the MACs that will
	    // appear in samples taken there.
	    if(sp->k8s.setIfAlias)
	      setAdaptorAlias(sp, adaptor, pod->hostname, "MOD_K8S");
	    // should emerge as sFlow PORT_NAME if sp->k8s.setIfName is also set.
	    // now find the vnicMAC by nspid, and tell him the ifIndex that we want him
	    // to tag the packet-samples with.
	    HSPVnicMAC *vnicMAC;
	    UTHASH_WALK(mdata->vnicByMAC, vnicMAC) {

	      char buf[32];
	      EVDebug(mod, 2, "evt_get_nsid_ans: consider vnicMAC(mac=%s, nspid=%u)",
		      SFLMacAddress_print(&vnicMAC->mac, buf, 32),
		      vnicMAC->nspid);

	      if(vnicMAC->nspid == pod->nspid) {
		EVDebug(mod, 1, "evt_get_nsid_ans: vnicMAC with nspid %u ifIndex %u -> %u",
			vnicMAC->nspid,
			vnicMAC->ifIndex,
			pod->ifIndex);
		vnicMAC->ifIndex = pod->ifIndex;
		break;
	      }
	    }
	  }
	}
      }
    }
  }

  static void updatePodNSID(EVMod *mod, HSPVMState_POD *pod) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    // vm.ds_index is easier lookup hook that vm.uuid or pod->hostname
    HSPGetNSID get_nsid = { .nspid = pod->nspid, .dsIndex = pod->vm.dsIndex };
    EVEventTx(mod, mdata->evt_get_nsid, &get_nsid, sizeof(get_nsid));
  }

  /*_________________---------------------------__________________
    _________________  updatePodAdaptors        __________________
    -----------------___________________________------------------
  */

  static void updatePodAdaptors(EVMod *mod, HSPVMState_POD *pod) {
    HSPVMState *vm = &pod->vm;
    if(vm) {
      // reset the information that we are about to refresh
      markAdaptors_adaptorList(mod, vm->interfaces);
      // then refresh it
      readVNICInterfaces(mod, &pod->vm, pod->nspid, mapIPToPod);
      // and clean up
      deleteMarkedAdaptors_adaptorList(mod, vm->interfaces);
      adaptorListFreeMarked(vm->interfaces);
      // get pod NSID (asynchronous - not set immediately)
      updatePodNSID(mod, pod);
    }
  }

  /*_________________-----------------------------__________________
    _________________    updatePodCgroupPaths     __________________
    -----------------_____________________________------------------
  */

  static void updatePodCgroupPaths(EVMod *mod, HSPVMState_POD *pod) {
    if(pod->nspid == 0)
      return;
    HSPVMState *vm = &pod->vm;
    if(vm) {
      // open /proc/<pid>/cgroup
      char cgpath[HSP_K8S_MAX_FNAME_LEN+1];
      snprintf(cgpath, HSP_K8S_MAX_FNAME_LEN, PROCFS_STR "/%u/cgroup", pod->nspid);
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
		if(!my_strequal(pod->cgroup_devices, path)) {
		  if(pod->cgroup_devices)
		    my_free(pod->cgroup_devices);
		  pod->cgroup_devices = my_strdup(path);
		  EVDebug(mod, 1, "pod(%s)->cgroup_devices=%s", pod->hostname, pod->cgroup_devices);
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
    _________________   host counter sample     __________________
    -----------------___________________________------------------
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(!hasVNodeRole(mod, HSP_VNODE_PRIORITY_POD))
      return;

    memset(&mdata->vnodeElem, 0, sizeof(mdata->vnodeElem));
    mdata->vnodeElem.tag = SFLCOUNTERS_HOST_VRT_NODE;
    mdata->vnodeElem.counterBlock.host_vrt_node.mhz = sp->cpu_mhz;
    mdata->vnodeElem.counterBlock.host_vrt_node.cpus = sp->cpu_cores;
    mdata->vnodeElem.counterBlock.host_vrt_node.num_domains = UTHashN(mdata->podsByHostname);
    mdata->vnodeElem.counterBlock.host_vrt_node.memory = sp->mem_total;
    mdata->vnodeElem.counterBlock.host_vrt_node.memory_free = sp->mem_free;
    SFLADD_ELEMENT(cs, &mdata->vnodeElem);
  }

  /*_________________---------------------------__________________
    _________________     container names       __________________
    -----------------___________________________------------------
  */

  static void setContainerName(EVMod *mod, HSPK8sContainer *container, const char *name) {
    char *str = (char *)name;
    if(str && str[0] == '/') str++; // consume leading '/'
    if(my_strequal(str, container->name) == NO) {
      if(container->name)
	my_free(container->name);
      container->name = my_strdup(str);
    }
  }

  /*_________________---------------------------__________________
    _________________           GPUs            __________________
    -----------------___________________________------------------
  */

  static void clearPodGPUs(EVMod *mod, HSPVMState_POD *pod) {
    // clear out the list - we are single threaded on the
    // poll bus so there is no need for sync
    UTArray *arr = pod->vm.gpus;
    HSPGpuID *entry;
    UTARRAY_WALK(arr, entry)
      my_free(entry);
    UTArrayReset(arr);
  }

  static void readPodGPUsFromEnv(EVMod *mod, HSPVMState_POD *pod, cJSON *jenv) {
    // look through env vars for evidence of GPUs assigned to this pod
    EVDebug(mod, 1, "readPodGPUsFromEnv(%s)", pod->hostname);
    pod->gpu_env_tried = YES;
    int entries = cJSON_GetArraySize(jenv);
    UTArray *arr = pod->vm.gpus;
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
	  clearPodGPUs(mod, pod);
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
		EVDebug(mod, 2, "adding GPU uuid to pod: %s", pod->hostname);
		UTArrayAdd(arr, gpu);
		pod->gpu_env = YES;
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
  
  static void readPodGPUsFromDev(EVMod *mod, HSPVMState_POD *pod) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    EVDebug(mod, 1, "readPodGPUsFromDev(%s)", pod->hostname);
    pod->gpu_dev_tried = YES;
    // look through devices to see if individial GPUs are exposed
    char path[HSP_MAX_PATHLEN];
    sprintf(path, "%s/%s/devices.list", mdata->cgroup_devices_path, pod->cgroup_devices);
    FILE *procFile = fopen(path, "r");
    if(procFile) {
      UTArray *arr = pod->vm.gpus;

      // if we already know this is our source of truth
      // for GPUs then clear the array now
      if(pod->gpu_dev)
	clearPodGPUs(mod, pod);

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

	      if(!pod->gpu_dev) {
		// Found one, so this is going to work. Establish
		// this as our source of truth for GPUs and clear
		// out any that might have been found another way.
		pod->gpu_dev = YES;
		clearPodGPUs(mod, pod);
	      }
	      HSPGpuID *gpu = my_calloc(sizeof(HSPGpuID));
	      gpu->minor = minor;
	      gpu->has_minor = YES;
	      EVDebug(mod, 2, "adding GPU dev to pod: %s", pod->hostname);
	      UTArrayAdd(arr, gpu);
	    }
	  }
	}
      }
      fclose(procFile);
    }
  }


  /*_________________---------------------------__________________
    _________________    setPodNSPid            __________________
    -----------------___________________________------------------
  */

  static uint32_t setPodNSPid(EVMod *mod, HSPVMState_POD *pod) {
    // pick up an nspid from my list of active containers
    HSPK8sContainer *container;
    UTHASH_WALK(pod->containers, container) {
      if(container->pid) {
	pod->nspid = (uint32_t)container->pid;
	break;
      }
    }
    return pod->nspid;
  }

  /*_________________---------------------------__________________
    _________________       logField            __________________
    -----------------___________________________------------------
  */

  static void logField(int debugLevel, char *msg, cJSON *obj, char *field)
  {
    if(debug(debugLevel)) {
      cJSON *fieldObj = cJSON_GetObjectItem(obj, field);
      char *str = fieldObj ? cJSON_Print(fieldObj) : NULL;
      myLog(LOG_INFO, "%s %s=%s", msg, field, str ?: "<not found>");
      if(str)
	my_free(str);
    }
  }

  /*_________________---------------------------__________________
    _________________     readContainerJSON     __________________
    -----------------___________________________------------------
  */

  static void readContainerJSON(EVMod *mod, cJSON *top, void *magic) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL) {
      // do nothing if we haven't settled on the config yet
      return;
    }
    HSPK8sContainer *container = NULL;
    cJSON *jid = cJSON_GetObjectItem(top, "Id");

    if(jid)
      container = getContainer(mod, jid->valuestring, YES);
    if(container == NULL)
      return;

    cJSON *jpid = cJSON_GetObjectItem(top, "Pid");
    if(jpid)
      container->pid = (pid_t)jpid->valueint;
    
    cJSON *jmetrics = cJSON_GetObjectItem(top, "Metrics");
    if(!jmetrics)
      return;

    cJSON *jnames = cJSON_GetObjectItem(jmetrics, "Names");
    if(jnames) {
      logField(1, " ", jnames, "Image");
      logField(1, " ", jnames, "Hostname");
      logField(1, " ", jnames, "ContainerName");
      logField(1, " ", jnames, "ContainerType");
      logField(1, " ", jnames, "SandboxName");
      logField(1, " ", jnames, "SandboxNamespace");
      logField(1, " ", jnames, "ImageName");
    }
    
    cJSON *jn = cJSON_GetObjectItem(jnames, "ContainerName");
    cJSON *jt = cJSON_GetObjectItem(jnames, "ContainerType");
    cJSON *jhn = cJSON_GetObjectItem(jnames, "Hostname");
    cJSON *jsn = cJSON_GetObjectItem(jnames, "SandboxName");
    cJSON *jsns = cJSON_GetObjectItem(jnames, "SandboxNamespace");
    cJSON *jcgpth = cJSON_GetObjectItem(jnames, "CgroupsPath");
    char *jn_s = (jn && strlen(jn->valuestring)) ? jn->valuestring : NULL;
    char *jt_s = (jt && strlen(jt->valuestring)) ? jt->valuestring : NULL;
    char *jhn_s = (jhn && strlen(jhn->valuestring)) ? jhn->valuestring : NULL;
    char *jsn_s = (jsn && strlen(jsn->valuestring)) ? jsn->valuestring : NULL;
    char *jsns_s = (jsns && strlen(jsns->valuestring)) ? jsns->valuestring : NULL;
    char *jcgpth_s = (jcgpth && strlen(jcgpth->valuestring)) ? jcgpth->valuestring : NULL;
    // containerType indicates sandbox
    container->isSandbox = (my_strequal(jt_s, "sandbox"));

    // record name (really just for debug)
    setContainerName(mod, container, jn_s);

    // next gather the latest metrics for this container
    cJSON *jcpu = cJSON_GetObjectItem(jmetrics, "Cpu");
    if(jcpu) {
      cJSON *jcpustate = cJSON_GetObjectItem(jcpu, "VirDomainState");
      container->stats.state = SFL_VIR_DOMAIN_RUNNING;
      if(jcpustate) {
	container->stats.state = jcpustate->valueint;
	if(container->stats.state != SFL_VIR_DOMAIN_RUNNING)
	  EVDebug(mod, 2, "container (name=%s) state=%u",
		  jn_s,
		  container->stats.state);
      }
      cJSON *jcputime = cJSON_GetObjectItem(jcpu, "CpuTime");
      if(jcputime)
	container->stats.cpu_total = jcputime->valuedouble;
      cJSON *jcpucount = cJSON_GetObjectItem(jcpu, "CpuCount");
      if(jcpucount)
	container->stats.cpu_count = jcpucount->valueint;
    }
    cJSON *jmem = cJSON_GetObjectItem(jmetrics, "Mem");
    if(jmem) {
      cJSON *jm = cJSON_GetObjectItem(jmem, "Memory");
      if(jm)
	container->stats.mem_usage = jm->valuedouble; // TODO: units?
      cJSON *jmm = cJSON_GetObjectItem(jmem, "MaxMemory");
      if(jmm)
	container->stats.memoryLimit = jmm->valuedouble; // TODO: units?
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
	container->stats.dsk.rd_req = jrd_req->valuedouble;
      if(jwr_req)
	container->stats.dsk.wr_req = jwr_req->valuedouble;
      if(jrd_bytes)
	container->stats.dsk.rd_bytes = jrd_bytes->valuedouble;
      if(jwr_bytes)
	container->stats.dsk.wr_bytes = jwr_bytes->valuedouble;
    }

    // set hostname
    // From kubernetes/pgk/kubelet/dockershim/naming.go
    // Sandbox
    // k8s_POD_{s.name}_{s.namespace}_{s.uid}_{s.attempt}
    // Container
    // k8s_{c.name}_{s.name}_{s.namespace}_{s.uid}_{c.attempt}
    
    // Match the Kubernetes docker_inspect output by combining these strings into
    // the form k8s_<containername>_<sandboxname>_<sandboxnamespace>_<sandboxuser>_<c.attempt>
    // but in this case we are only naming the pod,  so we always leave out the containername.
    // assemble,  with fake 'uid' and 'attempt' fields since we don't know them:
    char compoundName[MY_MAX_HOSTNAME_CHARS+1];
    snprintf(compoundName, MY_MAX_HOSTNAME_CHARS, "k8s__%s_%s_u_a",
	     jsn_s ?: (jhn_s ?: ""),
	     jsns_s ?: "");
    // now get the pod, key'd by sandbox name. That means we will allocated
    // it immediately whether this container is the sandbox container or not.
    HSPVMState_POD *pod = getPod(mod, compoundName, jcgpth_s, YES);
    assert(pod != NULL);

    // make sure this container is assigned to this pod.
    podAddContainer(mod, pod, container);
    
    // set/update the pod nspid
    setPodNSPid(mod, pod);

    {
      // probe for the MAC and peer-ifIndex (will only
      // work if we have at least one regular container here
      // since the sandbox has pid==0).
      
      // see if spacing the VNIC refresh reduces load
      time_t now_mono = mdata->pollBus->now.tv_sec;
      pod->last_heard = now_mono;

      if(pod->last_vnic == 0
	 || (now_mono - pod->last_vnic) > HSP_VNIC_REFRESH_TIMEOUT) {
	pod->last_vnic = now_mono;
	updatePodAdaptors(mod, pod);
      }
      
      if(pod->last_cgroup == 0
	 || (now_mono - pod->last_cgroup) > HSP_CGROUP_REFRESH_TIMEOUT) {
	pod->last_cgroup = now_mono;
	updatePodCgroupPaths(mod, pod);
      }
    }
    
    if(!container->isSandbox) {
      // Only try to find the GPU info once, but don't
      // try it on the sandbox container because it won't
      // have the full ENV.
      cJSON *jenv = cJSON_GetObjectItem(top, "Env");
      if(jenv
	 && !pod->gpu_env_tried)
	readPodGPUsFromEnv(mod, pod, jenv);
      
      if(pod->cgroup_devices
	 && !pod->gpu_dev_tried)
	readPodGPUsFromDev(mod, pod);
    }

    if(container->isSandbox) {
      // send the counter sample right away
      // (the Go program has read /etc/hsflowd.auto to get the
      // polling interval, so it is already handling the polling
      // periodicity for us).
      getCounters_POD(mod, pod);
      // maybe this was the last one?
      if(podDone(mod, pod)) {
	EVDebug(mod, 1, "pod done (%s) removeAndFree", pod->hostname);
	removeAndFreeVM_POD(mod, pod);
      }
    }
  }
  
  static void readContainerData(EVMod *mod, char *str, void *magic) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    int prefixLen = strlen(HSP_K8S_DATAPREFIX);
    if(memcmp(str, HSP_K8S_DATAPREFIX, prefixLen) == 0) {
      cJSON *top = cJSON_Parse(str + prefixLen);
      readContainerJSON(mod, top, magic);
      cJSON_Delete(top);
    }
    else if(memcmp(str, HSP_K8S_CTRPREFIX, strlen(HSP_K8S_CTRPREFIX)) == 0) {
      // Go program wants us to share this as an rtmetric in my sFlow feed
      // Expect form: "ctr> counter32 <int>"
      // This would look cleaner if Go program sent JSON msg.
      #define RTMETRIC_JSON_LEN 256
      #define RTMETRIC_KEY_LEN 64
      #define RTMETRIC_TYP_LEN 64
      #define RTMETRIC_VAL_LEN 64
      char rtmBuf[RTMETRIC_JSON_LEN];
      char rtmKey[RTMETRIC_KEY_LEN];
      char rtmTyp[RTMETRIC_TYP_LEN]; // e.g. counter32 or string
      char rtmVal[RTMETRIC_VAL_LEN]; // e.g. 123.0 or "helloworld"
      char *p = str + strlen(HSP_K8S_CTRPREFIX);
      char *sep = "[] \t";
      if(parseNextTok(&p, sep, NO, 0, YES, rtmTyp, RTMETRIC_KEY_LEN))
	if(parseNextTok(&p, sep, NO, 0, YES, rtmKey, RTMETRIC_TYP_LEN))
	  if(parseNextTok(&p, sep, NO, 0, YES, rtmVal, RTMETRIC_VAL_LEN)) {
	    snprintf(rtmBuf, RTMETRIC_JSON_LEN,
		     "{ \"rtmetric\": {"
		     "\"datasource\": \"%s\","
		     "\"%s\":{\"type\":\"%s\", \"value\":%s }"
		     "} }", mod->name, rtmKey, rtmTyp, rtmVal);
	    EVEventTx(mod, mdata->rtmetricEvent, rtmBuf, strlen(rtmBuf));
	  }
    }
  }
  
  static void readContainerCB(EVMod *mod, EVSocket *sock, EnumEVSocketReadStatus status, void *magic) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    mdata->c_readContainerCB++;
    switch(status) {
    case EVSOCKETREAD_AGAIN:
      break;
    case EVSOCKETREAD_STR:
      // UTStrBuf_chomp(sock->ioline);
      EVDebug(mod, 1, "readContainerCB: %s", UTSTRBUF_STR(sock->ioline));
      if(sock->errOut) {
	// this is the stderr socket - log the message
	myLog(LOG_ERR, "readContainerCB errOut: %s", UTSTRBUF_STR(sock->ioline));
      }
      else {
	// stdout
	readContainerData(mod, UTSTRBUF_STR(sock->ioline), magic);
      }
      UTStrBuf_reset(sock->ioline);
      break;
    case EVSOCKETREAD_EOF:
      myLog(LOG_ERR, "readContainerCB EOF");
      // with k8s{eof=on} we will allow mod_k8s to go on
      // even if hsflowd_containerd has terminated and
      // closed the socket.  This is primarity for debug
      // purposes (so we can catch this condition and run
      // tests).
      if(!sp->k8s.eof) {
	// But the default will be to force the whole
	// process to abort.
	abort();
      }
      break;
    case EVSOCKETREAD_BADF:
      myLog(LOG_ERR, "readContainerCB BADF");
      abort();
      break;
    case EVSOCKETREAD_ERR:
      myLog(LOG_ERR, "readContainerCB ERR");
      abort();
      break;
    }
  }
  
  /*_________________---------------------------__________________
    _________________ evt_flow_sample_released  __________________
    -----------------___________________________------------------
    Packet Bus
  */

  static uint32_t containerDSByMAC(EVMod *mod, SFLMacAddress *mac, uint32_t *p_nspid, uint32_t *p_ifIndex) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    if(EVDebug(mod, 2, NULL)) {
      char macstr[64];
      EVDebug(mod, 2, "containerDSByMAC %s",
	      SFLMacAddress_print(mac, macstr, 64));
    }
    HSPVnicMAC searchMAC = { .mac = *mac };
    HSPVnicMAC *vnicMAC = UTHashGet(mdata->vnicByMAC, &searchMAC);
    if(vnicMAC) {
      EVDebug(mod, 2, "containerDSByMAC matched ds=%u nspid=%u ifIndex=%u owners=%u",
	      vnicMAC->dsIndex,
	      vnicMAC->nspid,
	      vnicMAC->ifIndex,
	      UTHashN(vnicMAC->owners));
      // make sure it represents a unique mapping
      if(UTHashN(vnicMAC->owners) == 1) {
	*(p_nspid) = vnicMAC->nspid; // get pod namespace too
	(*p_ifIndex) = vnicMAC->ifIndex; // and ifIndex
	return vnicMAC->dsIndex;
      }
    }
    return 0;
  }

  static uint32_t containerDSByIP(EVMod *mod, SFLAddress *ipAddr, uint32_t *p_nspid, uint32_t *p_ifIndex) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    if(EVDebug(mod, 2, NULL)) {
      char ipstr[64];
      EVDebug(mod, 2, "containerDSByIP %s",
	      SFLAddress_print(ipAddr, ipstr, 64));
    }
    HSPVnicIP searchIP = { .ipAddr = *ipAddr };
    HSPVnicIP *vnicIP = UTHashGet(mdata->vnicByIP, &searchIP);
    if(vnicIP) {
      HSPVnicMAC *vnicMAC = vnicIP->vnicMAC;
      if(EVDebug(mod, 2, NULL)) {
	char ipstr[64];
	EVDebug(mod, 2, "containerDSByIP %s matched VNIC ds=%u ifIndex=%u nspid=%u",
		SFLAddress_print(ipAddr, ipstr, 64),
		vnicMAC->dsIndex,
		vnicMAC->ifIndex,
		vnicMAC->nspid);
      }
      if(UTHashN(vnicMAC->owners) == 1) {
	(*p_nspid) = vnicMAC->nspid; // get pod namespace too
	(*p_ifIndex) = vnicMAC->ifIndex; // and ifIndex
	return vnicMAC->dsIndex;
      }
    }
    return 0;
  }
  
  static bool lookupContainerDatasourceAndNamespace(EVMod *mod, HSPPendingSample *ps) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    // start with the one most likely to match
    // e.g. in Kubernetes with Calico IPIP or VXLAN this will be the innerIP:

    EVDebug(mod, 3, "lookupContainerDS: hdr_prot=%u, l3_offset=%u, l4_offset=%u, ipver=%u, innerMAC=%u, innerIP=%u",
	    ps->hdr_protocol,
	    ps->l3_offset,
	    ps->l4_offset,
	    ps->ipversion,
	    ps->gotInnerMAC,
	    ps->gotInnerIP);

    if(ps->gotInnerIP) {
      ps->src_dsIndex = containerDSByIP(mod, &ps->src_1, &ps->src_nspid, &ps->src_ifIndex);
      ps->dst_dsIndex = containerDSByIP(mod, &ps->dst_1, &ps->dst_nspid, &ps->dst_ifIndex);
      
      if(EVDebug(mod, 3, NULL)) {
	char sbuf[51],dbuf[51];
	EVDebug(mod, 3, "lookupContainerDS: search by inner IP: src=%s dst=%s srcDS=%u dstDS=%u",
		SFLAddress_print(&ps->src_1, sbuf, 50),
		SFLAddress_print(&ps->dst_1, dbuf, 50),
		ps->src_dsIndex,
		ps->dst_dsIndex);
      }
      
      if(ps->src_dsIndex || ps->dst_dsIndex) {
	mdata->ds_byInnerIP++;
	return YES;
      }
    }
    if(ps->gotInnerMAC) {
      ps->src_dsIndex = containerDSByMAC(mod, &ps->macsrc_1, &ps->src_nspid, &ps->src_ifIndex);
      ps->dst_dsIndex = containerDSByMAC(mod, &ps->macdst_1, &ps->dst_nspid, &ps->dst_ifIndex);
      if(ps->src_dsIndex || ps->dst_dsIndex) {
	mdata->ds_byInnerMAC++;
	return YES;
      }
    }
    if(ps->hdr_protocol == SFLHEADER_ETHERNET_ISO8023) {
      // outer MAC
      ps->src_dsIndex = containerDSByMAC(mod, &ps->macsrc, &ps->src_nspid, &ps->src_ifIndex);
      ps->dst_dsIndex = containerDSByMAC(mod, &ps->macdst, &ps->dst_nspid, &ps->dst_ifIndex);
      if(ps->src_dsIndex || ps->dst_dsIndex) {
	mdata->ds_byMAC++;
	return YES;
      }
    }
    if(ps->l3_offset) {
      // outer IP
      ps->src_dsIndex = containerDSByIP(mod, &ps->src, &ps->src_nspid, &ps->src_ifIndex);
      ps->dst_dsIndex = containerDSByIP(mod, &ps->dst, &ps->dst_nspid, &ps->dst_ifIndex);
      if(ps->src_dsIndex || ps->dst_dsIndex) {
	mdata->ds_byIP++;
	return YES;
      }
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________    evt_flow_sample        __________________
    -----------------___________________________------------------
  */

  static void addEntitiesElement(EVMod *mod, HSPPendingSample *ps) {
    if(ps->src_dsIndex || ps->dst_dsIndex) {
      SFLFlow_sample_element *entElem = pendingSample_calloc(ps, sizeof(SFLFlow_sample_element));
      entElem->tag = SFLFLOW_EX_ENTITIES;
      if(ps->src_dsIndex
	 && ps->src_dsIndex != 0xFFFFFFFF) {
	entElem->flowType.entities.src_dsClass = SFL_DSCLASS_LOGICAL_ENTITY;
	entElem->flowType.entities.src_dsIndex = ps->src_dsIndex;
      }
      if(ps->dst_dsIndex
	 && ps->dst_dsIndex != 0xFFFFFFFF) {
	entElem->flowType.entities.dst_dsClass = SFL_DSCLASS_LOGICAL_ENTITY;
	entElem->flowType.entities.dst_dsIndex = ps->dst_dsIndex;
      }
      SFLADD_ELEMENT(ps->fs, entElem);
    }
  }
  
  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSPPendingSample *ps = (HSPPendingSample *)data;
    decodePendingSample(ps);
    if(lookupContainerDatasourceAndNamespace(mod, ps)) {
      mdata->pod_byAddr++;
    }
  }

  /*_________________----------------------------___________________
    _________________  evt_flow_sample_released  ___________________
    -----------------____________________________-------------------
    If the sample was held up waiting for a DIAG query then this
    is the point where that query has completed (or timed-out, or failed)
  */

  static void evt_flow_sample_released(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSPPendingSample *ps = (HSPPendingSample *)data;

    // we may already know
    if(ps->src_dsIndex == 0
       && ps->dst_dsIndex == 0) {
      // nope, but INET_DIAG may have reported a cgroup_id associated with the socket
      // so this is another chance to map from packet to pod.  Of course we may have
      // needed to know the namespace for that to work,  and if we knew the namespace
      // then we should already have a dsIndex.  So this step really only helps if
      // the INET_DIAG lookup succeeds in my own namespace even though I didn't
      // recognize the IP/MAC addresses from the packet as belonging to a pod.
      if(ps->cgroup_id) {
	HSPVMState_POD search = { .cgroup_id = ps->cgroup_id };
	HSPVMState_POD *pod = UTHashGet(mdata->podsByCgroupId, &search);
	if(pod) {
	  mdata->pod_byCgroup++;
	  EVDebug(mod, 2, "mod_k8s: cgroup_id(%"PRIu64")->pod(%s) dsIndex=%u",
		  ps->cgroup_id,
		  pod->hostname,
		  pod->vm.dsIndex);
	  if(ps->localSrc)
	    ps->src_dsIndex = pod->vm.dsIndex;
	  else
	    ps->dst_dsIndex = pod->vm.dsIndex;
	}
      }
    }

    // If we mapped the sample, add the "entities" annotation
    addEntitiesElement(mod, ps);
  }

  /*_________________---------------------------__________________
    _________________    evt_cfg_done           __________________
    -----------------___________________________------------------
  */

  static void readCB(EVMod *mod, EVSocket *sock, void *magic) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    mdata->c_readCB++;
    EVSocketReadLines(mod, sock, readContainerCB, NO, magic);
  }

  static void evt_cfg_done(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mdata->configRevisionNo = sp->revisionNo;
  }

  /*_________________---------------------------__________________
    _________________    tick,tock              __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;

    if(EVDebug(mod, 1, NULL)) {
      EVDebug(mod, 1, "ds_byMAC=%u,ds_byInnerMAC=%u,ds_byIP=%u,ds_byInnerIP=%u,pod_byAddr=%u,pod_byCgroup=%u,n_vnicByIP=%u,readCB=%u,readContainerCB=%u",
	      mdata->ds_byMAC,
	      mdata->ds_byInnerMAC,
	      mdata->ds_byIP,
	      mdata->ds_byInnerIP,
	      mdata->pod_byAddr,
	      mdata->pod_byCgroup,
	      UTHashN(mdata->vnicByIP),
	      mdata->c_readCB,
	      mdata->c_readContainerCB);
    }
    // These counters are "total in last second".  They are not universally interesting, just
    // for understanding how this module is interfacing with the hsflowd_containerd.go program.
    mdata->c_readCB = 0;
    mdata->c_readContainerCB=0;

    if(--mdata->idleSweepCountdown <= 0) {
      // rearm
      uint32_t idleTimeout = 1 + (sp->actualPollingInterval * 2);
      mdata->idleSweepCountdown = idleTimeout;
      // look for idle pods
      time_t now_mono = mdata->pollBus->now.tv_sec;
      HSPVMState_POD *pod;
      UTHASH_WALK(mdata->podsByHostname, pod) {
	if(pod->last_heard
	   && (now_mono - pod->last_heard) > idleTimeout) {

	  if(EVDebug(mod, 1, NULL)) {
	    char buf[1024];
	    EVDebug(mod, 1, "Removing idle pod (%s)", podStr(pod, buf, 1024));
	  }

	  removeAndFreeVM_POD(mod, pod);
	}    
      }
    }
  }

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    if(mdata->configRevisionNo
       && mdata->readerPid == 0) {
      // Could pass debugLevel to reader like this:
      // char level[16];
      // snprintf(level, 16, "%u", getDebug());
      // char *cmd[] = { HSP_K8S_READER, "--debugLevel", level,  NULL };
      // but can always debug reader separately, so just invoke it like this:
      char *cmd[] = { HSP_K8S_READER, NULL };
      mdata->readerPid = EVBusExec(mod, mdata->pollBus, mdata, cmd, readCB);
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_k8s(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_K8S));
    HSP_mod_K8S *mdata = (HSP_mod_K8S *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    struct stat statBuf;
    if(sp->docker.docker == YES
       && stat("/var/run/docker.sock", &statBuf) == 0) {
      EVDebug(mod, 1, "not enabling mod_k8s because mod_docker is running and docker.sock is present");
      return;
    }

    // ask to retain root privileges
    retainRootRequest(mod, "needed by mod_k8s to access containerd.sock");
    retainRootRequest(mod, "needed by mod_k8s to probe for adaptors in other namespaces");

    requestVNodeRole(mod, HSP_VNODE_PRIORITY_POD);

    mdata->podsByHostname = UTHASH_NEW(HSPVMState_POD, hostname, UTHASH_SKEY);
    mdata->podsByCgroupId = UTHASH_NEW(HSPVMState_POD, cgroup_id, UTHASH_DFLT);
    mdata->containersByID = UTHASH_NEW(HSPK8sContainer, id, UTHASH_SKEY);
    
    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TOCK), evt_tock);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_DONE), evt_cfg_done);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);

    // GET_NSID api - offered by mod_nlroute
    mdata->evt_get_nsid = EVGetEvent(mdata->pollBus, HSPEVENT_GET_NSID);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_GET_NSID_ANS), evt_get_nsid_ans);

    EVBus *packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);

    // event to ask for sampling on a device
    mdata->evt_get_tap = EVGetEvent(packetBus, HSPEVENT_GET_TAP);

    // Go program may want to send rtmetrics (to mod_json)
    mdata->rtmetricEvent = EVGetEvent(packetBus, HSPEVENT_RTMETRIC_JSON);
    
    if(sp->k8s.markTraffic) {
      // By requesting HSPEVENT_FLOW_SAMPLE_RELEASED as well as
      // HSPEVENT_FLOW_SAMPLE we ensure that mod_tcp (if loaded)
      // will have completed it's annotation of the sample first.
      EVEventRx(mod, EVGetEvent(packetBus, HSPEVENT_FLOW_SAMPLE), evt_flow_sample);
      EVEventRx(mod, EVGetEvent(packetBus, HSPEVENT_FLOW_SAMPLE_RELEASED), evt_flow_sample_released);
      mdata->vnicByMAC = UTHASH_NEW(HSPVnicMAC, mac, UTHASH_SYNC); // need sync (poll + packet thread)
      mdata->vnicByIP = UTHASH_NEW(HSPVnicIP, ipAddr, UTHASH_SYNC); // need sync (poll + packet thread)
    }

    readCgroupPaths(mod);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
