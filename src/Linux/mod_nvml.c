/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <nvml.h>

  typedef struct _HSP_mod_NVML {
    unsigned int gpu_count;
    uint32_t *gpu_time; // mS. accumulators
    uint32_t *mem_time; // mS. accumulators
    uint32_t *energy;  // mJ. accumulators
    UTHash *byUUID; // look up uuid -> gpu
    UTHash *byMinor; // look up minor -> gpu
    SFLCounters_sample_element nvmlElem;
  } HSP_mod_NVML;

#include <linux/param.h> // for HZ
#include <sys/sysinfo.h> // for get_nprocs()

  /*_________________---------------------------__________________
    _________________     nvml_init             __________________
    -----------------___________________________------------------
    Called at startup
  */
  void nvml_init(EVMod *mod) {
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;

    unsigned int gpuCount;
    if (NVML_SUCCESS != nvmlInit()) {
    return;
    }
    if (NVML_SUCCESS != nvmlDeviceGetCount(&gpuCount)) {
      return;
    }
    mdata->gpu_count = gpuCount;
    // allocate accumulator arrays
    mdata->gpu_time = my_calloc(gpuCount * sizeof(uint32_t));
    mdata->mem_time = my_calloc(gpuCount * sizeof(uint32_t));
    mdata->energy = my_calloc(gpuCount * sizeof(uint32_t));
    // Build hash table to get from UUID to index
    // (yes, library has getDeviceByUUID() but it expects a
    // ascii-hex string and we prefer to keep UUIDs as 16-byte
    // binary objects, so we make our own lookup here).
    mdata->byUUID = UTHASH_NEW(HSPGpuID, uuid, UTHASH_DFLT);
    mdata->byMinor = UTHASH_NEW(HSPGpuID, minor, UTHASH_DFLT);
    for (int ii = 0; ii < mdata->gpu_count; ii++) {
      nvmlDevice_t gpu;
      if (NVML_SUCCESS == nvmlDeviceGetHandleByIndex(ii, &gpu)) {
	char uuidstr[128];
	if(NVML_SUCCESS == nvmlDeviceGetUUID(gpu, uuidstr, 128)) {
	  EVDebug(mod, 2, "deviceGetUUID(index=%u) returned %s", ii, uuidstr);
	  // uuuidstr may have "GPU-" prefix
	  char *uuidstr2 = uuidstr;
	  if(my_strnequal("GPU-", uuidstr2, 4))
	    uuidstr2 += 4;
	  HSPGpuID *id = my_calloc(sizeof(HSPGpuID));
	  id->index = ii;
	  id->has_index = YES;

	  if(parseUUID(uuidstr2, id->uuid)) {
	    id->has_uuid = YES;
	    UTHashAdd(mdata->byUUID, id);
	    EVDebug(mod, 1, "GPU uuid added to lookup table");
	  }
	  else {
	    EVDebug(mod, 1, "failed to parse GPU uuid");
	  }

	  unsigned int minor;
	  if(NVML_SUCCESS == nvmlDeviceGetMinorNumber(gpu, &minor)) {
	    id->minor = minor;
	    id->has_minor = YES;
	    UTHashAdd(mdata->byMinor, id);
	  }
	  else {
	    EVDebug(mod, 1, "failed to retrieve GPU minor number");
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     nvml_stop             __________________
    -----------------___________________________------------------
    Called on graceful exit
  */
  void nvml_stop(EVMod *mod) {
    nvmlShutdown();
  }

  /*_________________---------------------------__________________
    _________________     nvml_tick             __________________
    -----------------___________________________------------------
    Called every second
  */
  void nvml_tick(EVMod *mod) {
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
    for (int ii = 0; ii < mdata->gpu_count; ii++) {
      nvmlDevice_t gpu;
      unsigned int power_mW;
      nvmlUtilization_t util;
      if (NVML_SUCCESS != nvmlDeviceGetHandleByIndex(ii, &gpu)) {
	continue;
      }
      if (NVML_SUCCESS == nvmlDeviceGetUtilizationRates(gpu, &util)) {
	mdata->gpu_time[ii] += util.gpu * 10; // accumulate as mS
	mdata->mem_time[ii] += util.memory * 10; // accumulate as mS
      }
      if (NVML_SUCCESS == nvmlDeviceGetPowerUsage(gpu, &power_mW)) {
	mdata->energy[ii] += power_mW; // accumulate as mJ
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   accumulateGPUCounters   __________________
    -----------------___________________________------------------
  */

  static void accumulateGPUCounters(EVMod *mod, SFLHost_gpu_nvml *nvml, int gpu_index) {
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
    nvmlDevice_t gpu;
    nvmlMemory_t memInfo;
    unsigned long long eccErrors;
    unsigned int temp;
    unsigned int speed;
    unsigned int procs;
    nvmlReturn_t result;

    if (NVML_SUCCESS != nvmlDeviceGetHandleByIndex(gpu_index, &gpu))
      return;

    // accumulate gpu count
    nvml->device_count++;

    // pick up latest value of 'tick' accumulators
    nvml->gpu_time += mdata->gpu_time[gpu_index];
    nvml->mem_time += mdata->mem_time[gpu_index];
    nvml->energy += mdata->energy[gpu_index];

    // sum memory
    if (NVML_SUCCESS == nvmlDeviceGetMemoryInfo(gpu, &memInfo)) {
      nvml->mem_total += memInfo.total;
      nvml->mem_free  += memInfo.free;
    }
    // sum errors
    if (NVML_SUCCESS == nvmlDeviceGetTotalEccErrors(gpu, NVML_DOUBLE_BIT_ECC, NVML_VOLATILE_ECC, &eccErrors)) {
      nvml->ecc_errors += eccErrors;
    }
    // max temperature
    if (NVML_SUCCESS == nvmlDeviceGetTemperature(gpu, NVML_TEMPERATURE_GPU, &temp)) {
      if (nvml->temperature < temp) {
	nvml->temperature = temp;
      }
    }
    // max fan speed
    if (NVML_SUCCESS == nvmlDeviceGetFanSpeed(gpu, &speed)) {
      if (nvml->fan_speed < speed) {
	nvml->fan_speed = speed;
      }
    }
    // sum processes
    procs = 0;
    result = nvmlDeviceGetComputeRunningProcesses(gpu, &procs, NULL);
    if (NVML_SUCCESS == result || NVML_ERROR_INSUFFICIENT_SIZE == result) {
      nvml->processes += procs;
    }
  }

  /*_________________---------------------------__________________
    _________________   init structure          __________________
    -----------------___________________________------------------
    The nvml counter structure is assembled dynamically from the accounting
    data.  This clears and initializes it before iterating over the GPUs.
  */

  static SFLHost_gpu_nvml *init_gpu_nvml(SFLCounters_sample_element *nvmlElem) {
    memset(nvmlElem, 0, sizeof(*nvmlElem));
    nvmlElem->tag = SFLCOUNTERS_HOST_GPU_NVML;
    return &nvmlElem->counterBlock.host_gpu_nvml;
  }

  /*_________________---------------------------__________________
    _________________   counter sample events   __________________
    -----------------___________________________------------------
    Counter samples that are initiated elsewhere are detected here
    and annotated with GPU data where appropriate.
  */

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
    if(mdata->gpu_count) {
      SFLHost_gpu_nvml *nvml = init_gpu_nvml(&mdata->nvmlElem);
      // accumulate over all devices
      for (int ii = 0; ii < mdata->gpu_count; ii++)
	accumulateGPUCounters(mod, nvml, ii);
      SFLADD_ELEMENT(cs, &mdata->nvmlElem);
    }
  }

  static void evt_vm_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSPPendingCSample *ps = (HSPPendingCSample *)data;
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
    // For these events, poller->userData points to
    // HSPVMState_DOCKER/SYSTEMD/KVM/XEN/POD which
    // all start with the HSPVMState structure.
    if(ps->poller
       && ps->poller->userData) {
      HSPVMState *vm = (HSPVMState *)ps->poller->userData;
      if(vm
	 && vm->gpus
	 && UTArrayN(vm->gpus) > 0) {
	EVDebug(mod, 2, "evt_vm_cs() %u vm->gpus", UTArrayN(vm->gpus));
	// VM was assigned one or more GPU devices
	SFLHost_gpu_nvml *nvml = init_gpu_nvml(&mdata->nvmlElem);
	HSPGpuID *vmgpu;
	UTARRAY_WALK(vm->gpus, vmgpu) {

	  if(!vmgpu->has_index) {
	    // look up index by uuid or minor number
	    HSPGpuID *id = NULL;
	    if(vmgpu->has_minor)
	      id = UTHashGet(mdata->byMinor, vmgpu);
	    else if(vmgpu->has_uuid)
	      id = UTHashGet(mdata->byUUID, vmgpu);
	    if(id
	       && id->has_index) {
	      // and fill it in for next time
	      vmgpu->index = id->index;
	      vmgpu->has_index = YES;
	    }
	  }

	  if(vmgpu->has_index) {
	    EVDebug(mod, 2, "evt_vm_cs() accumulate(idx=%u)", vmgpu->index);
	    accumulateGPUCounters(mod, nvml, vmgpu->index);
	  }
	  else {
	    EVDebug(mod, 2, "evt_vm_cs() gpu uuid->id lookup failed");
	  }
	}
	SFLADD_ELEMENT(ps->cs, &mdata->nvmlElem);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   lifecycle bus events    __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    nvml_tick(mod);
  }

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    nvml_stop(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_nvml(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_NVML));
    nvml_init(mod);
    // register call-backs
    EVBus *pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_VM_COUNTER_SAMPLE), evt_vm_cs);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_FINAL), evt_final);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
