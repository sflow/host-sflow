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
    uint32_t nvml_gpu_time; // mS. accumulator
    uint32_t nvml_mem_time; // mS. accumulator
    uint32_t nvml_energy;  // mJ. accumulator
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

    if(mdata->gpu_count > 0) {
      unsigned int i;

      for (i = 0; i < mdata->gpu_count; ++i) {
        nvmlDevice_t gpu;
        unsigned int power_mW;
	nvmlUtilization_t util;

        if (NVML_SUCCESS != nvmlDeviceGetHandleByIndex(i, &gpu)) {
          continue;
        }
        if (NVML_SUCCESS == nvmlDeviceGetUtilizationRates(gpu, &util)) {
	  mdata->nvml_gpu_time += util.gpu * 10; // accumulate as mS
	  mdata->nvml_mem_time += util.memory * 10; // accumulate as mS
        }
        if (NVML_SUCCESS == nvmlDeviceGetPowerUsage(gpu, &power_mW)) {
	  mdata->nvml_energy += power_mW; // accumulate as mJ
        }
      }

    }
  }

  /*_________________---------------------------__________________
    _________________     readNvmlCounters      __________________
    -----------------___________________________------------------
    Called to get latest counters
  */

  int readNvmlCounters(EVMod *mod, SFLHost_gpu_nvml *nvml) {
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
   unsigned int i;

    if(mdata->gpu_count == 0) {
      return NO;
    }

    // pick up latest value of accumulators
    nvml->gpu_time = mdata->nvml_gpu_time;
    nvml->mem_time = mdata->nvml_mem_time;
    nvml->energy = mdata->nvml_energy;

    // and fill in the rest of the counters/gauges too
    nvml->device_count = mdata->gpu_count;

    // zero these, and sum across all GPUs
    nvml->mem_total = 0;
    nvml->mem_free = 0;
    nvml->ecc_errors = 0;
    nvml->processes = 0;

    // use the max across all GPUs
    nvml->temperature = 0;
    nvml->fan_speed = 0;

    for (i = 0; i < mdata->gpu_count; ++i) {
      unsigned long long eccErrors;
      unsigned int temp;
      nvmlDevice_t gpu;
      unsigned int speed;
      unsigned int procs;
      nvmlMemory_t memInfo;
      nvmlReturn_t result;

      if (NVML_SUCCESS != nvmlDeviceGetHandleByIndex(i, &gpu)) {
        return NO;
      }
      if (NVML_SUCCESS == nvmlDeviceGetMemoryInfo(gpu, &memInfo)) {
        nvml->mem_total += memInfo.total;
        nvml->mem_free  += memInfo.free;
      }
      if (NVML_SUCCESS == nvmlDeviceGetTotalEccErrors(gpu, NVML_SINGLE_BIT_ECC, NVML_VOLATILE_ECC, &eccErrors)) {
        nvml->ecc_errors += eccErrors;
      }
      if (NVML_SUCCESS == nvmlDeviceGetTotalEccErrors(gpu, NVML_DOUBLE_BIT_ECC, NVML_VOLATILE_ECC, &eccErrors)) {
        nvml->ecc_errors += eccErrors;
      }
      if (NVML_SUCCESS == nvmlDeviceGetTemperature(gpu, NVML_TEMPERATURE_GPU, &temp)) {
        if (nvml->temperature < temp) {
          nvml->temperature = temp;
        }
      }
      if (NVML_SUCCESS == nvmlDeviceGetFanSpeed(gpu, &speed)) {
        if (nvml->fan_speed < speed) {
          nvml->fan_speed = speed;
        }
      }
      procs = 0;
      result = nvmlDeviceGetComputeRunningProcesses(gpu, &procs, NULL);
      if (NVML_SUCCESS == result || NVML_ERROR_INSUFFICIENT_SIZE == result) {
        nvml->processes += procs;
      }
    }

    return YES;
  }

  static void evt_host_cs(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFL_COUNTERS_SAMPLE_TYPE *cs = *(SFL_COUNTERS_SAMPLE_TYPE **)data;
    HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
    memset(&mdata->nvmlElem, 0, sizeof(mdata->nvmlElem));
    mdata->nvmlElem.tag = SFLCOUNTERS_HOST_GPU_NVML;
    if(readNvmlCounters(mod, &mdata->nvmlElem.counterBlock.host_gpu_nvml)) {
      SFLADD_ELEMENT(cs, &mdata->nvmlElem);
    }
  }

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
    // HSP_mod_NVML *mdata = (HSP_mod_NVML *)mod->data;
    nvml_init(mod);
    // register call-backs
    EVBus *pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_TICK), evt_tick);
    EVEventRx(mod, EVGetEvent(pollBus, HSPEVENT_HOST_COUNTER_SAMPLE), evt_host_cs);
    EVEventRx(mod, EVGetEvent(pollBus, EVEVENT_FINAL), evt_final);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
