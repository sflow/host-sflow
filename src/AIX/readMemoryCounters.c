/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "libperfstat.h"

  /*_________________---------------------------__________________
    _________________     readMemoryCounters    __________________
    -----------------___________________________------------------
  */
  
  int readMemoryCounters(SFLHost_mem_counters *mem) {
    int gotData = NO;

    perfstat_memory_total_t mem_total;
    if(perfstat_memory_total(NULL, &mem_total, sizeof(mem_total), 1) != -1) {
      gotData = YES;
     mem->mem_total = mem_total.real_total * 4096;
     mem->mem_free = mem_total.real_free * 4096;
     mem->mem_buffers = mem_total.real_system * 4096;
     mem->mem_cached = mem_total.real_pinned * 4096;
     mem->swap_total = mem_total.pgsp_total * 4096;
     mem->swap_free = mem_total.pgsp_free * 4096;
     mem->page_in = mem_total.pgins;
     mem->page_out = mem_total.pgouts;
     mem->swap_in = mem_total.pgspins;
     mem->swap_out = mem_total.pgspouts;
    }

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

