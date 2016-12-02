/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

/* with grateful reference to:
 * http://www.matthew.ath.cx/misc/dbus
 * https://www.freedesktop.org/wiki/Software/systemd/dbus/
 * https://github.com/brianmcgillion/DBus/blob/master/tools/dbus-monitor.c
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
#include <dbus/dbus.h>
#include "hsflowd.h"
#include "cpu_utils.h"

  // limit the number of chars we will read from each line in /proc
#define MAX_PROC_LINELEN 256
#define MAX_PROC_TOKLEN 32

#define HSP_DBUS_MAX_FNAME_LEN 255
#define HSP_DBUS_MAX_STATS_LINELEN 512
#define HSP_DBUS_WAIT_STARTUP 2


#define HSP_DBUS_SERVICE_REGEX "\\.service$"
#define HSP_DBUS_SYSTEM_SLICE_REGEX "system\\.slice"

  typedef void (*HSPDBusHandler)(EVMod *mod, DBusMessage *dbm, void *magic);
  
  typedef struct _HSPDBusRequest {
    int serial;
    HSPDBusHandler handler;
    void *magic;
  } HSPDBusRequest;

  typedef struct _HSPDBusUnit {
    char *name;
    char *obj;
    char *cgroup;
    char uuid[16];
    UTArray *pids;
    bool marked:1;
  } HSPDBusUnit;
  
  typedef struct _HSPVMState_DBUS {
    HSPVMState vm; // superclass: must come first
    char *id;
    uint64_t memoryLimit; // TODO: read this from unit properties?
  } HSPVMState_DBUS;

  typedef struct _HSP_mod_DBUS {
    DBusConnection *connection;
    DBusError error;
    int dbus_soc;
    UTHash *dbusRequests;
    UTHash *units;
    EVBus *pollBus;
    UTHash *vmsByUUID;
    UTHash *vmsByID;
    UTHash *pollActions;
    SFLCounters_sample_element vnodeElem;
    bool dbusSync:1;
    // bool dbusFlush:1;
    uint32_t countdownToResync;
    int cgroupPathIdx;
    uint32_t serial_ListUnits;
    regex_t *service_regex;
    regex_t *system_slice_regex;
  } HSP_mod_DBUS;

  static void dbusSynchronize(EVMod *mod);
  static void removeAndFreeVM_DBUS(EVMod *mod, HSPVMState_DBUS *container);

  /*_________________---------------------------__________________
    _________________    utils to help debug    __________________
    -----------------___________________________------------------
  */

  static const char *messageTypeStr(int mtype)  {
    switch (mtype) {
    case DBUS_MESSAGE_TYPE_SIGNAL: return "signal";
    case DBUS_MESSAGE_TYPE_METHOD_CALL: return "method_call";
    case DBUS_MESSAGE_TYPE_METHOD_RETURN: return "method_return";
    case DBUS_MESSAGE_TYPE_ERROR:  return "error";
    default: return "(unknown message type)";
    }
  }

  char *containerStr(HSPVMState_DBUS *container, char *buf, int bufLen) {
    u_char uuidstr[100];
    printUUID((u_char *)container->vm.uuid, uuidstr, 100);
    snprintf(buf, bufLen, "uuid: %s id: %s",
	     container->vm.uuid,
	     container->id);
    return buf;
  }

  void containerHTPrint(UTHash *ht, char *prefix) {
    char buf[1024];
    HSPVMState_DBUS *container;
    UTHASH_WALK(ht, container)
      myLog(LOG_INFO, "%s: %s", prefix, containerStr(container, buf, 1024));
  }

  /*_________________---------------------------__________________
    _________________    HSPDBusUnit            __________________
    -----------------___________________________------------------
  */
  
  static HSPDBusUnit *HSPDBusUnitNew(EVMod *mod, char *name) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPDBusUnit *unit = (HSPDBusUnit *)my_calloc(sizeof(HSPDBusUnit));
    unit->name = my_strdup(name);
    unit->pids = UTArrayNew(UTARRAY_DFLT);
    // TODO: make this UUID properly by creating one for the namespace
    // key'd by sp->agentIP and then generating new ones for each
    // unit name from that (setting the bit as described in rfc 4122)
    char ipbuf[51];
    SFLAddress_print(&sp->agentIP, ipbuf, 50);
    uint32_t addr_hash32 = my_strhash(ipbuf);
    uint32_t name_hash32 = my_strhash(name);
    memcpy(unit->uuid + 8, &addr_hash32, 4);
    memcpy(unit->uuid + 12, &name_hash32, 4);
    return unit;
  }

  static void HSPDBusUnitFree(HSPDBusUnit *unit) {
    my_free(unit->name);
    my_free(unit->obj);
    my_free(unit->cgroup);
    UTArrayFree(unit->pids);
    my_free(unit);
  }

  /*_________________---------------------------__________________
    _________________    parseDbusElem          __________________
    -----------------___________________________------------------
  */

  static void indent(UTStrBuf *buf, int depth) {
    for(int ii = 0; ii < depth; ii++)
      UTStrBuf_append(buf, "  ");
  }

#define PARSE_DBUS_VAR(it,type,format,buf) do {	\
    type val;					\
    dbus_message_iter_get_basic(it, &val);	\
    UTStrBuf_printf(buf, format, val);		\
} while(0)
  
  static void parseDBusElem(DBusMessageIter *it, UTStrBuf *buf, bool ind, int depth, char *suffix) {
    if(ind) indent(buf, depth);
    int atype = dbus_message_iter_get_arg_type(it);
    switch(atype) {
    case DBUS_TYPE_INVALID: break;
    case DBUS_TYPE_STRING: PARSE_DBUS_VAR(it, char *, "\"%s\"", buf); break;
    case DBUS_TYPE_OBJECT_PATH: PARSE_DBUS_VAR(it, char *, "obj=%s", buf); break;
    case DBUS_TYPE_BYTE: PARSE_DBUS_VAR(it, uint8_t, "0x%02x", buf); break;
    case DBUS_TYPE_INT16: PARSE_DBUS_VAR(it, int16_t, "%d", buf); break;
    case DBUS_TYPE_INT32: PARSE_DBUS_VAR(it, int32_t, "%d", buf); break;
    case DBUS_TYPE_INT64: PARSE_DBUS_VAR(it, int64_t, "%"PRId64, buf); break;
    case DBUS_TYPE_UINT16: PARSE_DBUS_VAR(it, uint16_t, "%u", buf); break;
    case DBUS_TYPE_UINT32: PARSE_DBUS_VAR(it, uint32_t, "%u", buf); break;
    case DBUS_TYPE_UINT64: PARSE_DBUS_VAR(it, uint64_t, "%"PRIu64, buf); break;
    case DBUS_TYPE_DOUBLE: PARSE_DBUS_VAR(it, double, "%f", buf); break;
    case DBUS_TYPE_BOOLEAN: { 
      dbus_bool_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%s", val ? "true":"false");
      break;
    }
    case DBUS_TYPE_VARIANT: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      UTStrBuf_printf(buf, "(");
      parseDBusElem(&sub, buf, NO, depth+1, ")");
      break;
    }
    case DBUS_TYPE_ARRAY: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      // handle empty array
      int elemType = dbus_message_iter_get_arg_type(&sub);
      if(elemType == DBUS_TYPE_INVALID) {
	UTStrBuf_printf(buf, "[]");
      }
      else {
	UTStrBuf_printf(buf, "[\n");
	do parseDBusElem(&sub, buf, YES, depth+1, ",\n");
	while (dbus_message_iter_next(&sub));
	indent(buf, depth);
	UTStrBuf_printf(buf, "]");
      }
      break;
    }
    case DBUS_TYPE_DICT_ENTRY: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      // iterate over key-value pairs (usually only one pair)
      do {
	parseDBusElem(&sub, buf, NO, depth+1, " => ");
	dbus_message_iter_next(&sub);
	parseDBusElem(&sub, buf, NO, depth+1, NULL);
      }
      while (dbus_message_iter_next(&sub));
      break;
    }
    case DBUS_TYPE_STRUCT: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      UTStrBuf_printf(buf, "struct {\n");
      do parseDBusElem(&sub, buf, YES, depth+1, ",\n");
      while (dbus_message_iter_next(&sub));
      indent(buf, depth);
      UTStrBuf_printf(buf, "}");
      break;
    }
    default:
      UTStrBuf_printf(buf, "unknown-type=%d", atype);
      break;
    }
    if(suffix) UTStrBuf_append(buf, suffix);
  }


  /*_________________---------------------------__________________
    _________________    parseDbusMessage       __________________
    -----------------___________________________------------------
  */

  static void parseDBusMessage(EVMod *mod, DBusMessage *msg) {
    // HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    myLog(LOG_INFO, "DBUS: dbusCB got message");
    int mtype = dbus_message_get_type(msg);
    const char *src = dbus_message_get_sender(msg);
    const char *dst = dbus_message_get_destination(msg);
    UTStrBuf *buf = UTStrBuf_new();
    UTStrBuf_printf(buf, "DBUS %s->%s %s(",
		    src?:"<no src>", 
		    dst?:"<no dst>", 
		    messageTypeStr(mtype));
    UTStrBuf_printf(buf, "(");
    switch(mtype) {
    case DBUS_MESSAGE_TYPE_METHOD_CALL:
    case DBUS_MESSAGE_TYPE_SIGNAL:
      UTStrBuf_printf(buf, "serial=%u,path=%s,interface=%s,member=%s",
		      dbus_message_get_serial(msg),
		      dbus_message_get_path(msg),
		      dbus_message_get_interface(msg),
		      dbus_message_get_member(msg));
      break;
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
      UTStrBuf_printf(buf, "reply_serial=%u",
		      dbus_message_get_reply_serial(msg));
      break;
    case DBUS_MESSAGE_TYPE_ERROR:
      UTStrBuf_printf(buf, "error_name=%s,reply_serial=%u",
		      dbus_message_get_error_name(msg),
		      dbus_message_get_reply_serial(msg));
      break;
    default:
      break;
    }
    UTStrBuf_printf(buf, ") {");
    DBusMessageIter iterator;
    if(dbus_message_iter_init(msg, &iterator)) {
      do parseDBusElem(&iterator, buf, YES, 1, "\n");
      while (dbus_message_iter_next(&iterator));
    }
    UTStrBuf_append(buf, "}\n");
    myDebug(1, "DBUS message: %s", buf->buf);
    UTStrBuf_free(buf);
  }
  
  /*________________---------------------------__________________
    ________________    readProcessCPU         __________________
    ----------------___________________________------------------
  */
  
  static uint64_t readProcessCPU(EVMod *mod, pid_t pid) {
    // HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    uint64_t cpu_total = 0;
    // compare with the reading of /proc/stat in readCpuCounters.c 
    char path[HSP_DBUS_MAX_FNAME_LEN+1];
    sprintf(path, "/proc/%u/stat", pid);
    FILE *statFile = fopen(path, "r");
    if(statFile == NULL) {
      myDebug(2, "cannot open %s : %s", path, strerror(errno));
    }
    else {
      char line[MAX_PROC_LINELEN];
      if(fgets(line, MAX_PROC_LINELEN, statFile)) {
	char *p = line;
	char buf[MAX_PROC_TOKLEN];
	int tok = 0;
	while(parseNextTok(&p, " ", NO, 0, NO, buf, MAX_PROC_TOKLEN)) {
	  switch(++tok) {
	  case 14: // utime
	  case 15: // stime
	  case 16: // cutime
	  case 17: // cstime
	    cpu_total += strtoll(buf, NULL, 0);
	  }
	}
      }
      fclose(statFile);
    }
    return cpu_total;
  }
  
  /*________________---------------------------__________________
    ________________   accumulateProcessCPU    __________________
    ----------------___________________________------------------
  */
  
  static uint64_t accumulateProcessCPU(EVMod *mod, HSPDBusUnit *unit) {
    // HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    uint64_t cpu_total = 0;
    uint64_t pid64;
    UTARRAY_WALK(unit->pids, pid64) {
      cpu_total += readProcessCPU(mod, (pid_t)pid64);
    }
    return cpu_total;
  }
  
  /*________________---------------------------__________________
    ________________    readProcessRAM         __________________
    ----------------___________________________------------------
  */
  
  static uint64_t readProcessRAM(EVMod *mod, pid_t pid) {
    uint64_t rss = 0;
    char path[HSP_DBUS_MAX_FNAME_LEN+1];
    sprintf(path, "/proc/%u/statm", pid);
    FILE *statFile = fopen(path, "r");
    if(statFile == NULL) {
      myDebug(2, "cannot open %s : %s", path, strerror(errno));
    }
    else {
      char line[MAX_PROC_LINELEN];
      if(fgets(line, MAX_PROC_LINELEN, statFile)) {
	char *p = line;
	char buf[MAX_PROC_TOKLEN];
	int tok = 0;
	while(parseNextTok(&p, " ", NO, 0, NO, buf, MAX_PROC_TOKLEN)) {
	  switch(++tok) {
	  case 2: // resident
	    rss += strtoll(buf, NULL, 0);
	  }
	}
      }
      fclose(statFile);
    }
    return rss;
  }
  
  /*________________---------------------------__________________
    ________________   accumulateProcessRAM    __________________
    ----------------___________________________------------------
  */
  
  static uint64_t accumulateProcessRAM(EVMod *mod, HSPDBusUnit *unit) {
    // HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    uint64_t rss = 0;
    uint64_t pid64;
    UTARRAY_WALK(unit->pids, pid64) {
      rss += readProcessRAM(mod, (pid_t)pid64);
    }
    return rss;
  }
  
  /*________________---------------------------__________________
    ________________    readProcessIO          __________________
    ----------------___________________________------------------
  */
  
  static bool readProcessIO(EVMod *mod, pid_t pid, SFLHost_vrt_dsk_counters *dskio) {
    int found = NO;
    char path[HSP_DBUS_MAX_FNAME_LEN+1];
    sprintf(path, "/proc/%u/io", pid);
    FILE *statFile = fopen(path, "r");
    if(statFile == NULL) {
      myDebug(2, "cannot open %s : %s", path, strerror(errno));
    }
    else {
      found = YES;
      char line[MAX_PROC_LINELEN];
      while(fgets(line, MAX_PROC_LINELEN, statFile)) {
	char var[MAX_PROC_TOKLEN];
	uint64_t val64;
	if(sscanf(line, "%s: %"SCNu64, var, &val64) == 2) {
	  if(!strcmp(var, "read_bytes"))
	    dskio->rd_bytes += val64;
	  else if(!strcmp(var, "write_bytes"))
	    dskio->wr_bytes += val64;
	}
      }
      fclose(statFile);
    }
    return found;
  }
  
  /*________________---------------------------__________________
    ________________   accumulateProcessIO     __________________
    ----------------___________________________------------------
  */
  
  static bool accumulateProcessIO(EVMod *mod, HSPDBusUnit *unit, SFLHost_vrt_dsk_counters *dskio) {
    // HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    bool gotData = NO;
    uint64_t pid64;
    UTARRAY_WALK(unit->pids, pid64) {
      gotData |= readProcessIO(mod, (pid_t)pid64, dskio);
    }
    return gotData;
  }
  
  /*________________---------------------------__________________
    ________________   getCounters_DBUS        __________________
    ----------------___________________________------------------
  */
  static void getCounters_DBUS(EVMod *mod, HSPVMState_DBUS *container)
  {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPDBusUnit search = { .name = container->id };
    HSPDBusUnit *unit = UTHashGet(mdata->units, &search);
    // TODO: duplicate of login in getCounters_DBUS_request
    if(unit == NULL
       || unit->cgroup == NULL
       || UTArrayN(unit->pids) == 0) {
      return;
    }
    
    SFL_COUNTERS_SAMPLE_TYPE cs = { 0 };
    HSPVMState *vm = (HSPVMState *)&container->vm;
    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    hidElem.counterBlock.host_hid.hostname.str = container->id;
    hidElem.counterBlock.host_hid.hostname.len = my_strlen(container->id);
    memcpy(hidElem.counterBlock.host_hid.uuid, vm->uuid, 16);

    // we can show the same OS attributes as the parent
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

    // TODO: can we gather NIO stats by PID?  It looks like maybe not.  The numbers
    // in /proc/<pid>/net/dev are the same as in /proc/net/dev.  mod_docker gets the
    // numbers because veth devices are used to connect between network namespaces
    // but with no cgroup network accounting we would have to follow the links in
    // /proc/<pid>/fd/* and accumuate the list of socket inodes,  then query those
    // inodes for the counters -- assuming that sockets are not shared between processes
    // in different cgroups.  The fact that sockets can appear and disappear in a
    // short timeframe makes this hard to deal with accurately.  Collecting the listen
    // ports (SAPs) for a service would make more sense.  Then that list could be
    // exported,  and packet-samples could be annotated with service name if they
    // were to or from one of those SAPs.
    // VM Net I/O
    // SFLCounters_sample_element nioElem = { 0 };
    // nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
    // accumulateProcessNIO(mod, unit, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio);
    // SFLADD_ELEMENT(&cs, &nioElem);

    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = 0;
    SFL_UNDEF_COUNTER(cpuElem.counterBlock.host_vrt_cpu.cpuTime);

    // TODO: map service state into virState
    enum SFLVirDomainState virState = SFL_VIR_DOMAIN_NOSTATE;
    cpuElem.counterBlock.host_vrt_cpu.state = virState;
    
    // TODO: get from cpuAcct if there - otherwise:
    uint64_t cpu_total = accumulateProcessCPU(mod, unit);
    cpuElem.counterBlock.host_vrt_cpu.cpuTime = (uint32_t)(JIFFY_TO_MS(cpu_total));
      
    // always add this one - even if no counters found - so as to send the container state
    SFLADD_ELEMENT(&cs, &cpuElem);

    SFLCounters_sample_element memElem = { 0 };
    memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
    // TODO: get from memoryAcct if there - otherwise:
    uint64_t rss = accumulateProcessRAM(mod, unit);
    memElem.counterBlock.host_vrt_mem.memory = rss * 1024;
    // TODO: get max memory from DBUS
    // memElem.counterBlock.host_vrt_mem.maxMemory = maxMem;
    SFLADD_ELEMENT(&cs, &memElem);

    // VM disk I/O counters
    SFLCounters_sample_element dskElem = { 0 };
    dskElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
    // TODO: cgroup io accounting or:
    accumulateProcessIO(mod, unit, &dskElem.counterBlock.host_vrt_dsk);
    // TODO: fill in capacity, allocation, available fields
    SFLADD_ELEMENT(&cs, &dskElem);

    SEMLOCK_DO(sp->sync_agent) {
      sfl_poller_writeCountersSample(vm->poller, &cs);
      sp->counterSampleQueued = YES;
    }
  }

  static void agentCB_getCounters_DBUS_request(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    HSPVMState_DBUS *container = (HSPVMState_DBUS *)poller->userData;
    // TODO: is there a race where we might remove a unit here while we are rebuilding the units?
    // and then add it back again immediately?  The creation of the unit lookup happens synchronously
    // but the gathering of cgroup and pid data happens piecemeal.  May need a mark-and-sweep there.
    HSPDBusUnit search = { .name = container->id };
    HSPDBusUnit *unit = UTHashGet(mdata->units, &search);
    if(unit == NULL
       || unit->cgroup == NULL
       || UTArrayN(unit->pids) == 0) {
      removeAndFreeVM_DBUS(mod, container);
      return;
    }
    // unit still current - proceed
    UTHashAdd(mdata->pollActions, container);
  }

  /*_________________---------------------------__________________
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  static void removeAndFreeVM_DBUS(EVMod *mod, HSPVMState_DBUS *container) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    if(getDebug()) {
      myLog(LOG_INFO, "removeAndFreeVM: removing service with dsIndex=%u", container->vm.dsIndex);
    }

    if(UTHashDel(mdata->vmsByID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (vmsByID) failed: service %s", container->id);
      if(debug(1))
	containerHTPrint(mdata->vmsByID, "vmsByID");
    }

    if(UTHashDel(mdata->vmsByUUID, container) == NULL) {
      myLog(LOG_ERR, "UTHashDel (vmsByUUID) failed: service %s", container->id);
      if(debug(1))
	containerHTPrint(mdata->vmsByUUID, "vmsByUUID");
    }

    if(container->id) my_free(container->id);
    removeAndFreeVM(mod, &container->vm);
  }

  static HSPVMState_DBUS *getContainer(EVMod *mod, HSPDBusUnit *unit, int create) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    HSPVMState_DBUS cont = { .id = unit->name };
    HSPVMState_DBUS *container = UTHashGet(mdata->vmsByID, &cont);
    if(container == NULL
       && create) {
      container = (HSPVMState_DBUS *)getVM(mod, unit->uuid, YES, sizeof(HSPVMState_DBUS), VMTYPE_DBUS, agentCB_getCounters_DBUS_request);
      assert(container != NULL);
      if(container) {
	container->id = my_strdup(unit->name);
	// add to collections
	UTHashAdd(mdata->vmsByID, container);
	UTHashAdd(mdata->vmsByUUID, container);
      }
    }
    return container;
  }

  /*_________________---------------------------__________________
    _________________    tick,tock              __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    if(mdata->countdownToResync) {
      myDebug(1, "dbus resync in %u", mdata->countdownToResync);
      if(--mdata->countdownToResync == 0)
    	dbusSynchronize(mod);
    }
  }

  static void evt_tock(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    // now we can execute pollActions without holding on to the semaphore
    HSPVMState_DBUS *container;
    UTHASH_WALK(mdata->pollActions, container) {
      getCounters_DBUS(mod, container);
    }
    UTHashReset(mdata->pollActions);
  }

  /*_________________---------------------------__________________
    _________________   host counter sample     __________________
    -----------------___________________________------------------
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->kvm.kvm) {
      // TODO: untangle this
      // if we make kvm and dbus mutually exclusive, this check will be unnecessary
      return;
    }

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
    _________________     dbusMethod            __________________
    -----------------___________________________------------------
  */

#define HSP_dbusMethod_endargs DBUS_TYPE_INVALID,NULL
  
  static void dbusMethod(EVMod *mod, HSPDBusHandler reqCB, void *magic, char *target, char  *obj, char *interface, char *method, ...) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    DBusMessage *msg = dbus_message_new_method_call(target, obj, interface, method);
    // append arguments
    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);
    va_list args;
    va_start(args, method);
    for(;;) {
      int type = va_arg(args, int);
      void *arg = va_arg(args, void *);
      if(type == DBUS_TYPE_INVALID || arg == NULL) break;
      dbus_message_iter_append_basic(&iter, type, &arg);
    }
    va_end(args);
    // send the message
    uint32_t serial = 0;
    if(!dbus_connection_send(mdata->connection, msg, &serial)) {
      myLog(LOG_ERR, "dbus_connection_send() failed!");
    }
    // dbus_message_unref(msg); TODO: put this back?
    // register the handler
    HSPDBusRequest *req = (HSPDBusRequest *)my_calloc(sizeof(HSPDBusRequest));
    req->serial = serial;
    req->handler = reqCB;
    req->magic = magic;
    UTHashAdd(mdata->dbusRequests, req);
  }

  /*_________________---------------------------__________________
    _________________     db_get, db_next       __________________
    -----------------___________________________------------------
    When decoding a particular method response we know what we are
    willing to accept,  so the parsing is much simpler.  Because the
    iterator starts with the first element already "loaded" and
    libdbus exits if we try to walk off the end of an array, we have
    to be careful how we walk.  Patterns that work are:

    do { if(db_get(it,...)) {...} } while(db_next(it));

    or:

    if(db_get(it...) && db_get_next(it,...) && db_get_next(it, ...))

    or the DB_WALK() macro can be used to walk over a sequence of the same type
    and stop when a different type is found or the iterator is done.
  */

  static bool db_get(DBusMessageIter *it, int expected_type, DBusBasicValue *val) {
    int atype = dbus_message_iter_get_arg_type(it);
    if(atype == DBUS_TYPE_VARIANT) {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      return db_get(&sub, expected_type, val);
    }
    bool expected = (atype == expected_type);
    if(expected
       && val)
      dbus_message_iter_get_basic(it, val);
    return expected;
  }

  static bool db_next(DBusMessageIter *it) {
    return dbus_message_iter_next(it);
  }

  static bool db_get_next(DBusMessageIter *it, int expected_type, DBusBasicValue *val) {
    return db_next(it) && db_get(it, expected_type, val);
  }

#define DB_WALK(it, atype, val)  for(bool _more = YES; _more && db_get((it), (atype), (val)); _more = db_next(it))

  /*_________________---------------------------__________________
    _________________   handler_controlGroup    __________________
    -----------------___________________________------------------
  */

  static void handler_controlGroup(EVMod *mod, DBusMessage *dbm, void *magic) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    HSPDBusUnit *unit = (HSPDBusUnit *)magic;
    DBusMessageIter it;
    if(dbus_message_iter_init(dbm, &it)) {
      DBusBasicValue val;
      if(db_get(&it, DBUS_TYPE_STRING, &val)
	 && val.str
	 && my_strlen(val.str)
	 && regexec(mdata->system_slice_regex, val.str, 0, NULL, 0) == 0) {
	myDebug(1, "UNIT CGROUP[cgroup=\"%s\"]", val.str);
	unit->cgroup = my_strdup(val.str);
	// read the process ids
	char path[HSP_DBUS_MAX_FNAME_LEN+1];
	sprintf(path, "/sys/fs/cgroup/systemd/%s/cgroup.procs", val.str);
	FILE *pidsFile = fopen(path, "r");
	if(pidsFile == NULL) {
	  myDebug(2, "cannot open %s : %s", path, strerror(errno));
	}
	else {
	  char line[MAX_PROC_LINELEN];
	  uint64_t pid64;
	  while(fgets(line, MAX_PROC_LINELEN, pidsFile)) {
	    if(sscanf(line, "%"SCNu64, &pid64) == 1) {
	      myDebug(1, "got PID=%"PRIu64, pid64);
	      UTArrayAdd(unit->pids, (void *)pid64);
	    }
	  }
	  fclose(pidsFile);
	  if(UTArrayN(unit->pids)) {
	    getContainer(mod, unit, YES);

	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   handler_getUnit         __________________
    -----------------___________________________------------------
  */

  static void handler_getUnit(EVMod *mod, DBusMessage *dbm, void *magic) {
    HSPDBusUnit *unit = (HSPDBusUnit *)magic;
    DBusMessageIter it;
    if(dbus_message_iter_init(dbm, &it)) {
      DBusBasicValue val;
      if(db_get(&it, DBUS_TYPE_OBJECT_PATH, &val)
	 && val.str) {
	unit->obj = my_strdup(val.str);
	myDebug(1, "UNIT OBJ[obj=\"%s\"]", val.str);
	dbusMethod(mod,
		   handler_controlGroup,
		   unit,
		   "org.freedesktop.systemd1",
		   val.str,
		   "org.freedesktop.DBus.Properties",
		   "Get",
		   DBUS_TYPE_STRING,
		   "org.freedesktop.systemd1.Service",
		   DBUS_TYPE_STRING,
		   "ControlGroup",
		   HSP_dbusMethod_endargs);
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________   handler_listUnits       __________________
    -----------------___________________________------------------

    expect array of units, where each unit is a struct with ssssssouso
    {
    char *unit_name;
    char *unit_descr;
    char *load_state;
    char *active_state;
    char *sub_state;
    char *following;
    char *obj_path;
    uint32_t job_queued;
    char *job_type;
    char *job_obj_path;
    }
  */

  static void handler_listUnits(EVMod *mod, DBusMessage *dbm, void *magic) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    HSPDBusUnit *unit;

    // mark and sweep - mark here
    UTHASH_WALK(mdata->units, unit)  unit->marked = YES;

    DBusMessageIter it;
    if(dbus_message_iter_init(dbm, &it)) {
      if(db_get(&it, DBUS_TYPE_ARRAY, NULL)) {
	DBusMessageIter it_unit;
	dbus_message_iter_recurse(&it, &it_unit);
	DB_WALK(&it_unit, DBUS_TYPE_STRUCT, NULL) {
	  DBusMessageIter it_field;
	  dbus_message_iter_recurse(&it_unit, &it_field);
	  DBusBasicValue nm, ds, ls, as;
	  if(db_get(&it_field,  DBUS_TYPE_STRING, &nm)
	     && db_get_next(&it_field, DBUS_TYPE_STRING, &ds)
	     && db_get_next(&it_field, DBUS_TYPE_STRING, &ls)
	     && db_get_next(&it_field, DBUS_TYPE_STRING, &as)) {
	    if(nm.str
	       && regexec(mdata->service_regex, nm.str, 0, NULL, 0) == 0) {
	      HSPDBusUnit search = { .name = nm.str };
	      unit = UTHashGet(mdata->units, &search);
	      if(!unit) {
		unit = HSPDBusUnitNew(mod, nm.str);
		UTHashAdd(mdata->units, unit);
	      }
	      myDebug(1, "UNIT[name=\"%s\" descr=\"%s\" load=\"%s\" active=\"%s\"]", nm.str, ds.str, ls.str, as.str);
	      dbusMethod(mod,
			 handler_getUnit,
			 unit,
			 "org.freedesktop.systemd1",
			 "/org/freedesktop/systemd1",
			 "org.freedesktop.systemd1.Manager",
			 "GetUnit",
			 DBUS_TYPE_STRING,
			 nm.str,
			 HSP_dbusMethod_endargs);
	    }
	  }
	}
      }
    }
    // mark and sweep - sweep here
    UTHASH_WALK(mdata->units, unit) {
      if(unit->marked) {
	UTHashDel(mdata->units, unit);
	HSPDBusUnitFree(unit);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   dbusSynchronize         __________________
    -----------------___________________________------------------
  */

  static void dbusSynchronize(EVMod *mod) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    // TODO: dbusClearAll(mod);
    mdata->dbusSync = NO;
    mdata->cgroupPathIdx = -1;
    dbusMethod(mod,
	       NULL,
	       NULL,
	       "org.freedesktop.systemd1",
	       "/org/freedesktop/systemd1",
	       "org.freedesktop.systemd1.Manager",
	       "Subscribe",
	       HSP_dbusMethod_endargs);

    if(0) dbusMethod(mod,
	       handler_listUnits,
	       NULL,
	       "org.freedesktop.systemd1",
	       "/org/freedesktop/systemd1",
	       "org.freedesktop.systemd1.Manager",
	       "ListUnits",
	       HSP_dbusMethod_endargs);


    /* dbusMethod(mod, */
    /* 	       NULL, */
    /* 	       NULL, */
    /* 	       "org.freedesktop.systemd1", */
    /* 	       "/org/freedesktop/systemd1", */
    /* 	       "org.freedesktop.systemd1.Manager", */
    /* 	       "GetUnit", */
    /* 	       DBUS_TYPE_STRING, */
    /* 	       "httpd.service", */
    /* 	       HSP_dbusMethod_endargs); */

    dbusMethod(mod,
	       NULL,
    	       NULL,
    	       "org.freedesktop.systemd1",
    	       "/org/freedesktop/systemd1/unit/httpd_2eservice",
    	       "org.freedesktop.DBus.Properties",
    	       "GetAll",
    	       DBUS_TYPE_STRING,
    	       "org.freedesktop.systemd1.Service",
	       HSP_dbusMethod_endargs);

    /* dbusMethod(mod, */
    /* 	       NULL, */
    /* 	       NULL, */
    /* 	       "org.freedesktop.systemd1", */
    /* 	       "/org/freedesktop/systemd1/unit/httpd_2eservice", */
    /* 	       "org.freedesktop.DBus.Properties", */
    /* 	       "Get", */
    /* 	       DBUS_TYPE_STRING, */
    /* 	       "org.freedesktop.systemd1.Service", */
    /* 	       DBUS_TYPE_STRING, */
    /* 	       "MainPID", */
    /* 	       HSP_dbusMethod_endargs); */

    /* dbusMethod(mod, */
    /* 	       NULL, */
    /* 	       "org.freedesktop.systemd1", */
    /* 	       "/org/freedesktop/systemd1/unit/httpd_2eservice", */
    /* 	       "org.freedesktop.DBus.Properties", */
    /* 	       "Get", */
    /* 	       DBUS_TYPE_STRING, */
    /* 	       "org.freedesktop.systemd1.Service", */
    /* 	       DBUS_TYPE_STRING, */
    /* 	       "ControlGroup"); */
    // could try and get "MemoryCurrent" and "CPUUsageNSec" here, but since they
    // are usually not limited,  these numbers are usually == (uint64_t)-1.  So
    // it looks like we get a more predictable solution by taking the ControlGroup
    // and looking for the list of process IDs under:
    // /sys/fs/cgroup/systemd/system.slice/<service>/cgroup.procs
    // then we can rip through /proc/<pid>/stat and add up the numbers.  The downside
    // is that a service might have pids that come and go,  so we would lose data
    // in that case.
  }


  /*_________________---------------------------__________________
    _________________    evt_config_first       __________________
    -----------------___________________________------------------
  */

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    mdata->countdownToResync = HSP_DBUS_WAIT_STARTUP;
  }
  
  /*_________________---------------------------__________________
    _________________       dbusCB              __________________
    -----------------___________________________------------------
  */

static DBusHandlerResult dbusCB(DBusConnection *connection, DBusMessage *message, void *user_data)
{
  EVMod *mod = user_data;
  HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
  if(debug(1))
    parseDBusMessage(mod, message);
  if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
    int serial = dbus_message_get_reply_serial(message);
    HSPDBusRequest search = { .serial = serial };
    HSPDBusRequest *req = UTHashDelKey(mdata->dbusRequests, &search);
    if(req) {
      if(req->handler)
	(*req->handler)(mod, message, req->magic);
      my_free(req);
    }
  }
  // TODO:
  //if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
  //  myLog(LOG_ERR, "DBUS disconnected");
  //}
  return DBUS_HANDLER_RESULT_HANDLED;
}

  /*_________________---------------------------__________________
    _________________       readDBus            __________________
    -----------------___________________________------------------
  */

  static void readDBUS(EVMod *mod, EVSocket *sock, void *magic)
  {
    myLog(LOG_INFO, "DBUS: readDBUS");
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    dbus_connection_read_write_dispatch(mdata->connection, 0);
  }

  /*_________________---------------------------__________________
    _________________    addMatch               __________________
    -----------------___________________________------------------
  */

  static void addMatch(EVMod *mod, char *type) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    char rule[128];
    sprintf(rule, "eavesdrop=true,type='%s'", type);
    dbus_bus_add_match(mdata->connection, rule, &mdata->error);
    if(dbus_error_is_set(&mdata->error)) {
      myLog(LOG_ERR, "DBUS: addMatch() error adding <%s>", rule);
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_dbus(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_DBUS));
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;

    mdata->vmsByUUID = UTHASH_NEW(HSPVMState_DBUS, vm.uuid, UTHASH_DFLT);
    mdata->vmsByID = UTHASH_NEW(HSPVMState_DBUS, id, UTHASH_SKEY);
    mdata->pollActions = UTHASH_NEW(HSPVMState_DBUS, id, UTHASH_IDTY);
    mdata->dbusRequests = UTHASH_NEW(HSPDBusRequest, serial, UTHASH_DFLT);
    mdata->units = UTHASH_NEW(HSPDBusUnit, name, UTHASH_SKEY);
    mdata->cgroupPathIdx = -1;

    mdata->service_regex = UTRegexCompile(HSP_DBUS_SERVICE_REGEX);
    mdata->system_slice_regex = UTRegexCompile(HSP_DBUS_SYSTEM_SLICE_REGEX);

    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TOCK), evt_tock);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_FIRST), evt_config_first);

    dbus_error_init(&mdata->error);
    if((mdata->connection = dbus_bus_get(DBUS_BUS_SYSTEM, &mdata->error)) == NULL) {
      myLog(LOG_ERR, "dbus_bug_get error");
      // TODO: handle error
    }

    addMatch(mod, "signal");
    addMatch(mod, "method_call");
    addMatch(mod, "method_return");
    addMatch(mod, "error");

    if(!dbus_connection_add_filter(mdata->connection, dbusCB, mod, NULL)) {
      myLog(LOG_ERR, "dbus_connection_add_filter error");
      // TODO: handle error
    }
    if(!dbus_connection_get_unix_fd(mdata->connection, &mdata->dbus_soc)) {
      myLog(LOG_ERR, "dbus_connection_get_unix_fd error");
      // TODO: handle error
    }
    // request name
    dbus_bus_request_name(mdata->connection, "monitor.hsflowd", DBUS_NAME_FLAG_REPLACE_EXISTING, &mdata->error);
    if (dbus_error_is_set(&mdata->error)) { 
      myLog(LOG_ERR, "Name Error (%s)", mdata->error.message); 
      // TODO: must we free this every time? dbus_error_free(&err); 
    }
    // get the signals
    EVBusAddSocket(mod, mdata->pollBus, mdata->dbus_soc, readDBUS, NULL);

    // TODO: dubs_connection_close(mdata->connection);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
