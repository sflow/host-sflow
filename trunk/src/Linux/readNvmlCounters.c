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
    sp->nvml_handle =  NULL; // TODO:  dlopen(library)
  }

  /*_________________---------------------------__________________
    _________________     nvml_tick             __________________
    -----------------___________________________------------------
    Called every second
  */
  void nvml_tick(HSP *sp) {
    if(sp->nvml_handle) {
      uint32_t gpu_time_pc = 0; // TODO: retrieve from NVML API
      uint32_t mem_time_pc = 0; // TODO: retrieve from NVML API
      uint32_t power_W = 0;  // TODO: retrieve from NVML API
      sp->nvml_gpu_time += gpu_time_pc * 10; // accumulate as mS
      sp->nvml_mem_time += mem_time_pc * 10; // accumulate as mS
      sp->nvml_energy += power_W * 1000;  // accumulate as mJ
    }
  }
  
  /*_________________---------------------------__________________
    _________________     readNvmlCounters      __________________
    -----------------___________________________------------------
    Called to get latest counters
  */
  
  int readNvmlCounters(HSP *sp, SFLHost_gpu_nvml *nvml) {
    if(sp->nvml_handle == NULL) {
      return NO;
    }
    // pick up latest value of accumulators
    nvml->gpu_time = sp->nvml_gpu_time;
    nvml->mem_time = sp->nvml_mem_time;
    nvml->energy = sp->nvml_energy;
    // and fill in the rest of the counters/gauges too
    nvml->device_count = 0; // TODO: retrieve from NVML API
    nvml->processes = 0;  // TODO: retrieve from NVML API
    nvml->mem_total = 0;  // TODO: retrieve from NVML API
    nvml->mem_free = 0;  // TODO: retrieve from NVML API
    nvml->ecc_errors = 0;  // TODO: retrieve from NVML API
    nvml->temperature = 0;   // TODO: retrieve from NVML API
    nvml->fan_speed = 0;  // TODO: retrieve from NVML API
    return YES;
  }

#endif /* HSF_NVML */

#if defined(__cplusplus)
} /* extern "C" */
#endif

