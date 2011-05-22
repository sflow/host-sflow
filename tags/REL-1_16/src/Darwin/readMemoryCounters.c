/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <sys/sysctl.h>
#include <mach/mach.h>

  /*_________________---------------------------__________________
    _________________     getSys64              __________________
    -----------------___________________________------------------
  */

  int getSys64(char *field, uint64_t *val64p) {
    size_t len = sizeof(*val64p);
    if(sysctlbyname(field, val64p, &len, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(%s) failed : %s", field, strerror(errno));
      return NO;
    }
    return YES;
  }

  /*_________________---------------------------__________________
    _________________     readMemoryCounters    __________________
    -----------------___________________________------------------

 	  if(strcmp(var, "MemTotal:") == 0) mem->mem_total = val64 * 1024; 
 	  else if(strcmp(var, "MemFree:") == 0) mem->mem_free = val64 * 1024; 
 	  else if(strcmp(var, "Buffers:") == 0) mem->mem_buffers = val64 * 1024; 
 	  else if(strcmp(var, "Cached:") == 0) mem->mem_cached = val64 * 1024; 
 	  else if(strcmp(var, "SwapTotal:") == 0) mem->swap_total = val64 * 1024; 
 	  else if(strcmp(var, "SwapFree:") == 0) mem->swap_free = val64 * 1024;
  */
  
  int readMemoryCounters(SFLHost_mem_counters *mem) {
    int gotData = NO;
    uint64_t val64;
    if(getSys64("hw.memsize", &val64)) {
      gotData = YES;
      mem->mem_total = val64;
    }
    if(getSys64("hw.physmem", &val64)) {
      gotData = YES;
      // $$$ mem->mem_total = val64;
    }
    if(getSys64("hw.usermem", &val64)) {
      gotData = YES;
      // $$$ mem->mem_total = val64;
    }

    // swap $$$
/* 	  if(strcmp(var, "pgpgin") == 0) mem->page_in = (uint32_t)val64; */
/* 	  else if(strcmp(var, "pgpgout") == 0) mem->page_out = (uint32_t)val64; */
/* 	  else if(strcmp(var, "pswpin") == 0) mem->swap_in = (uint32_t)val64; */
/* 	  else if(strcmp(var, "pswpout") == 0) mem->swap_out = (uint32_t)val64; */
    
    return gotData;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

