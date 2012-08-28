/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef HSF_NVML


#include "hsflowd.h"

#include <linux/param.h> // for HZ
#include <sys/sysinfo.h> // for get_nprocs()

  /*_________________---------------------------__________________
    _________________     nvml_init             __________________
    -----------------___________________________------------------
    Called at startup
  */
  void nvml_init(HSP *sp) {
    unsigned int gpuCount;

    if (NVML_SUCCESS != nvmlInit()) {
      return;
    }
    if (NVML_SUCCESS != nvmlDeviceGetCount(&gpuCount)) {
      return;
    }
    sp->nvml.gpu_count = gpuCount;
  }

  /*_________________---------------------------__________________
    _________________     nvml_stop             __________________
    -----------------___________________________------------------
    Called on graceful exit
  */
  void nvml_stop(HSP *sp) {
    nvmlShutdown();
  }

  /*_________________---------------------------__________________
    _________________     nvml_tick             __________________
    -----------------___________________________------------------
    Called every second
  */
  void nvml_tick(HSP *sp) {
    if(sp->nvml.gpu_count > 0) {
      unsigned int i;

      for (i = 0; i < sp->nvml.gpu_count; ++i) {
        nvmlDevice_t gpu;
        unsigned int power_mW;
	nvmlUtilization_t util;

        if (NVML_SUCCESS != nvmlDeviceGetHandleByIndex(i, &gpu)) {
          continue;
        }
        if (NVML_SUCCESS == nvmlDeviceGetUtilizationRates(gpu, &util)) {
	  sp->nvml.nvml_gpu_time += util.gpu * 10; // accumulate as mS
	  sp->nvml.nvml_mem_time += util.memory * 10; // accumulate as mS
        }
        if (NVML_SUCCESS == nvmlDeviceGetPowerUsage(gpu, &power_mW)) {
	  sp->nvml.nvml_energy += power_mW; // accumulate as mJ
        }
      }

    }
  }
  
  /*_________________---------------------------__________________
    _________________     readNvmlCounters      __________________
    -----------------___________________________------------------
    Called to get latest counters
  */
  
  int readNvmlCounters(HSP *sp, SFLHost_gpu_nvml *nvml) {
    unsigned int i;

    if(sp->nvml.gpu_count == 0) {
      return NO;
    }

    // pick up latest value of accumulators
    nvml->gpu_time = sp->nvml.nvml_gpu_time;
    nvml->mem_time = sp->nvml.nvml_mem_time;
    nvml->energy = sp->nvml.nvml_energy;

    // and fill in the rest of the counters/gauges too
    nvml->device_count = sp->nvml.gpu_count;

    // zero these, and sum across all GPUs
    nvml->mem_total = 0;
    nvml->mem_free = 0;
    nvml->ecc_errors = 0;
    nvml->processes = 0;

    // use the max across all GPUs
    nvml->temperature = 0;
    nvml->fan_speed = 0;

    for (i = 0; i < sp->nvml.gpu_count; ++i) {
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

#endif /* HSF_NVML */

#if defined(__cplusplus)
} /* extern "C" */
#endif

