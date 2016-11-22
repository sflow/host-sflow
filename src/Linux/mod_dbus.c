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
#define MAX_PROC_LINE_CHARS 160

#define HSP_DBUS_MAX_FNAME_LEN 255
#define HSP_DBUS_MAX_STATS_LINELEN 512
#define HSP_DBUS_WAIT_STARTUP 2

  // patterns to substitute with cgroup, longid and counter-filename
  static const char *HSP_CGROUP_PATHS[] = {
    "/sys/fs/cgroup/%s/dbus/%s/%s",
    "/sys/fs/cgroup/%s/system.slice/dbus/%s",
    "/sys/fs/cgroup/%s/system.slice/dbus-%s.scope/%s",
    NULL
  };

  typedef struct _HSPVMState_DBUS {
    HSPVMState vm; // superclass: must come first
    char *id;
    char *name;
    pid_t pid;
    uint64_t memoryLimit;
  } HSPVMState_DBUS;

  typedef struct _HSP_mod_DBUS {
    DBusConnection *connection;
    DBusError error;
    int dbus_soc;
    EVBus *pollBus;
    UTHash *vmsByUUID;
    UTHash *vmsByID;
    UTHash *pollActions;
    SFLCounters_sample_element vnodeElem;
    bool dbusSync:1;
    // bool dbusFlush:1;
    uint32_t countdownToResync;
    int cgroupPathIdx;
  } HSP_mod_DBUS;

  static void dbusSynchronize(EVMod *mod);

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
    snprintf(buf, bufLen, "name: %s uuid: %s id: %s",
	     container->name,
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


  static void indent(UTStrBuf *buf, int depth) {
    for(int ii = 0; ii < depth; ii++)
      UTStrBuf_append(buf, " ");
  }

  static void printDBusElem(DBusMessageIter *it, UTStrBuf *buf, int depth, char *suffix) {
    indent(buf, depth);
    int atype = dbus_message_iter_get_arg_type(it);
    switch(atype) {
    case DBUS_TYPE_INVALID:
      break;
    case DBUS_TYPE_STRING: {
      char *val = NULL;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "\"%s\"", val);
      break;
    }
    case DBUS_TYPE_OBJECT_PATH: {
      char *val = NULL;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "obj=%s", val);
      break;
    }
    case DBUS_TYPE_BYTE: {
      uint8_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "0x%02x", val);
      break;
    }
    case DBUS_TYPE_INT16: {
      int16_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%d", val);
      break;
    }
    case DBUS_TYPE_INT32: {
      int32_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%d", val);
      break;
    }
    case DBUS_TYPE_INT64: {
      int64_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%"PRId64, val);
      break;
    }
    case DBUS_TYPE_UINT16: {
      uint16_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%u", val);
      break;
    }
    case DBUS_TYPE_UINT32: {
      uint16_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%u", val);
      break;
    }
    case DBUS_TYPE_UINT64: {
      uint64_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%"PRIu64, val);
      break;
    }
    case DBUS_TYPE_DOUBLE: {
      double val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%f", val);
      break;
    }
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
      printDBusElem(&sub, buf, 0, ")");
      break;
    }
    case DBUS_TYPE_ARRAY: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      UTStrBuf_printf(buf, "[\n");
      do printDBusElem(&sub, buf, depth+2, ",\n");
      while (dbus_message_iter_next(&sub));
      indent(buf, depth);
      UTStrBuf_printf(buf, "]");
      break;
    }
    case DBUS_TYPE_DICT_ENTRY: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      do {
	printDBusElem(&sub, buf, depth+2, " => ");
	dbus_message_iter_next(&sub);
	printDBusElem(&sub, buf, 0, NULL);
      }
      while (dbus_message_iter_next(&sub));
      break;
    }
    case DBUS_TYPE_STRUCT: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      UTStrBuf_printf(buf, "struct {\n");
      do printDBusElem(&sub, buf, depth+2, ",\n");
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

  static void printDBusMessage(EVMod *mod, DBusMessage *msg) {
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
      do printDBusElem(&iterator, buf, 2, "\n");
      while (dbus_message_iter_next(&iterator));
    }
    UTStrBuf_append(buf, "}\n");
    myDebug(1, "DBUS message: %s", buf->buf);
    UTStrBuf_free(buf);
  }

  /*_________________---------------------------__________________
    _________________     readCgroupCounters    __________________
    -----------------___________________________------------------
  */

  static bool readCgroupCounters(EVMod *mod, char *cgroup, char *longId, char *fname, int nvals, HSPNameVal *nameVals, int multi) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    
    int found = 0;

    char statsFileName[HSP_DBUS_MAX_FNAME_LEN+1];
    
    if(mdata->cgroupPathIdx == -1) {
      // iterate to choose path the first time
      for(;;) {
	const char *fmt = HSP_CGROUP_PATHS[++mdata->cgroupPathIdx];
	if(fmt == NULL) {
	  myLog(LOG_ERR, "readCgroupCounters: not found: cgroup=%s container=%s file=%s", cgroup, longId, fname);
	  return NO;
	}
	myDebug(1, "testing cgroup path: %s", fmt);
	snprintf(statsFileName, HSP_DBUS_MAX_FNAME_LEN, fmt, cgroup, longId, fname);
	FILE *statsFile = fopen(statsFileName, "r");
	if(statsFile) {
	  myDebug(1, "success using path pattern: %s", fmt);
	  fclose(statsFile);
	}
	break;
      }
    }	

    const char *fmt = HSP_CGROUP_PATHS[mdata->cgroupPathIdx];
    snprintf(statsFileName, HSP_DBUS_MAX_FNAME_LEN, fmt, cgroup, longId, fname);
    FILE *statsFile = fopen(statsFileName, "r");
    if(statsFile == NULL) {
      myDebug(2, "cannot open %s : %s", statsFileName, strerror(errno));
    }
    else {
      char line[HSP_DBUS_MAX_STATS_LINELEN];
      char var[HSP_DBUS_MAX_STATS_LINELEN];
      uint64_t val64;
      char *fmt = multi ?
	"%*s %s %"SCNu64 :
	"%s %"SCNu64 ;
      while(fgets(line, HSP_DBUS_MAX_STATS_LINELEN, statsFile)) {
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
    ________________   readContainerNIO        __________________
    ----------------___________________________------------------
  */

  static int readContainerNIO(EVMod *mod, HSPVMState_DBUS *container, SFLHost_nio_counters *nio) {
    char statsFileName[HSP_DBUS_MAX_FNAME_LEN+1];
    int interfaces = 0;
    snprintf(statsFileName, HSP_DBUS_MAX_FNAME_LEN, "/proc/%u/net/dev", container->pid);
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
  
  /*________________---------------------------__________________
    ________________   getCounters_DBUS        __________________
    ----------------___________________________------------------
  */
  static void getCounters_DBUS(EVMod *mod, HSPVMState_DBUS *container)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFL_COUNTERS_SAMPLE_TYPE cs = { 0 };
    HSPVMState *vm = (HSPVMState *)&container->vm;

    // host ID
    SFLCounters_sample_element hidElem = { 0 };
    hidElem.tag = SFLCOUNTERS_HOST_HID;
    hidElem.counterBlock.host_hid.hostname.str = container->name;
    hidElem.counterBlock.host_hid.hostname.len = my_strlen(container->name);
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
    
    if(readContainerNIO(mod, container, (SFLHost_nio_counters *)&nioElem.counterBlock.host_vrt_nio)) {
      SFLADD_ELEMENT(&cs, &nioElem);
    }

    // VM cpu counters [ref xenstat.c]
    SFLCounters_sample_element cpuElem = { 0 };
    cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
    cpuElem.counterBlock.host_vrt_cpu.nrVirtCpu = 0;
    SFL_UNDEF_COUNTER(cpuElem.counterBlock.host_vrt_cpu.cpuTime);

    // map container->state into SFLVirDomainState
    enum SFLVirDomainState virState = SFL_VIR_DOMAIN_NOSTATE;
    // TODO: set state
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
	// allow the limit we got from dbus inspect to override if it is lower
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
    UTHashAdd(mdata->pollActions, container);
  }

  /*_________________---------------------------__________________
    _________________   add and remove VM       __________________
    -----------------___________________________------------------
  */

  static void removeAndFreeVM_DBUS(EVMod *mod, HSPVMState_DBUS *container) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
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
    removeAndFreeVM(mod, &container->vm);
  }

  static HSPVMState_DBUS *getContainer(EVMod *mod, char *id, int create) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    if(id == NULL) return NULL;
    HSPVMState_DBUS cont = { .id = id };
    HSPVMState_DBUS *container = UTHashGet(mdata->vmsByID, &cont);
    if(container == NULL
       && create) {
      char uuid[16];
      // turn container ID into a UUID - just take the first 16 bytes of the id
      if(parseUUID(id, uuid) == NO) {
	myLog(LOG_ERR, " parsing container UUID from <%s>", id);
	abort();
      }
      container = (HSPVMState_DBUS *)getVM(mod, uuid, YES, sizeof(HSPVMState_DBUS), VMTYPE_DBUS, agentCB_getCounters_DBUS_request);
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
    _________________    openDbusSocket         __________________
    -----------------___________________________------------------
  */

  static void setContainerName(HSPVMState_DBUS *container, const char *name) {
    char *str = (char *)name;
    if(str && str[0] == '/') str++; // consume leading '/'
    if(my_strequal(str, container->name) == NO) {
      if(container->name) my_free(container->name);
      container->name = my_strdup(str);
    }
  }

  static void dbusListUnits(EVMod *mod) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    DBusPendingCall *pending;
    DBusMessage *msg = dbus_message_new_method_call("org.freedesktop.systemd1", // target for the method call
						    "/org/freedesktop/systemd1", // object to call on
						    "org.freedesktop.systemd1.Manager", // interface to call on
						    "ListUnits" /*"ListJobs"*/); // method name
    if(!msg) {
      myLog(LOG_ERR, "dbus_message_new_method_call() failed");
      return;
    }

    // append arguments
    // send message and get a handle for a reply
    if(!dbus_connection_send_with_reply(mdata->connection, msg, &pending, -1)) { // -1 is default timeout
      myLog(LOG_ERR, "dbus_connection_send_with_reply() failed");
      return;
    }
    if(!pending) { 
      myLog(LOG_ERR, "dbus_connection_send_with_reply() failed - pending == NULL");
      return;
    }

    dbus_connection_flush(mdata->connection);
    // free message
    dbus_message_unref(msg);
    
    // block until we receive a reply
    dbus_pending_call_block(pending);
    
    // get the reply message
    msg = dbus_pending_call_steal_reply(pending);
    if (!msg) {
      myLog(LOG_ERR, "dbus_connection_call_steal_reply() failed");
      return;
    }
    // free the pending message handle
    dbus_pending_call_unref(pending);
    printDBusMessage(mod, msg);
    // free reply and close connection
    dbus_message_unref(msg);   
  }

  static void dbusGetUnit(EVMod *mod, char *unit_name) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    DBusPendingCall *pending;
    DBusMessage *msg = dbus_message_new_method_call("org.freedesktop.systemd1", // target for the method call
						    "/org/freedesktop/systemd1", // object to call on
						    "org.freedesktop.systemd1.Manager", // interface to call on
						    "GetUnit"); // method name
    if(!msg) {
      myLog(LOG_ERR, "dbus_message_new_method_call() failed");
      return;
    }

    // append arguments
    DBusMessageIter args;
    dbus_message_iter_init_append(msg, &args);
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &unit_name)) { 
      myLog(LOG_ERR, "dbus_connection_iter_append_basic() failed");
      return;
    }

    // send message and get a handle for a reply
    if(!dbus_connection_send_with_reply(mdata->connection, msg, &pending, -1)) { // -1 is default timeout
      myLog(LOG_ERR, "dbus_connection_send_with_reply() failed");
      return;
    }
    if(!pending) { 
      myLog(LOG_ERR, "dbus_connection_send_with_reply() failed - pending == NULL");
      return;
    }

    dbus_connection_flush(mdata->connection);
    // free message
    dbus_message_unref(msg);
    // block until we receive a reply
    dbus_pending_call_block(pending);
    // get the reply message
    msg = dbus_pending_call_steal_reply(pending);
    if (!msg) {
      myLog(LOG_ERR, "dbus_connection_call_steal_reply() failed");
      return;
    }
    // free the pending message handle
    dbus_pending_call_unref(pending);
    printDBusMessage(mod, msg);
    // free reply and close connection
    dbus_message_unref(msg);   
  }

  static void dbusSynchronize(EVMod *mod) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    // TODO: dbusClearAll(mod);
    mdata->dbusSync = NO;
    mdata->cgroupPathIdx = -1;
    // send "ListJobs" request
    // TODO: when are we in sync?  And do we need to queue the events while we
    // process the jobs request, or does dbus get everything in the right order?
    // What chance do we have of getting everything in the right order anyway?
    // Perhaps we should just call listJobs every time and not worry about
    // event-driven behavior?
    // TODO: call subscribe
    dbusListUnits(mod);
    dbusGetUnit(mod, "inmsfd.service");
  }

  static void evt_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    mdata->countdownToResync = HSP_DBUS_WAIT_STARTUP;
  }

static DBusHandlerResult dbusCB(DBusConnection *connection, DBusMessage *message, void *user_data)
{
  EVMod *mod = user_data;
  printDBusMessage(mod, message);
  // TODO:
  //if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
  //  myLog(LOG_ERR, "DBUS disconnected");
  //}
  return DBUS_HANDLER_RESULT_HANDLED;
}

  static void readDBUS(EVMod *mod, EVSocket *sock, void *magic)
  {
    myLog(LOG_INFO, "DBUS: readDBUS");
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    dbus_connection_read_write_dispatch(mdata->connection, 0);
  }

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
    mdata->cgroupPathIdx = -1;
    
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
