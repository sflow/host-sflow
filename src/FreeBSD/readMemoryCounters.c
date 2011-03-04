/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <vm/vm_param.h>

  int getSysvmtotal(struct vmtotal *vmt) 
  {
    int mib[2];
    size_t len;

    mib[0] = CTL_VM;
    mib[1] = VM_TOTAL;
    len = sizeof(struct vmtotal);
    sysctl(mib, 2, vmt, &len, NULL, 0);
    return YES;
  }

  /*_________________---------------------------__________________
    _________________     readMemoryCounters    __________________
    -----------------___________________________------------------
  */
  
  int readMemoryCounters(SFLHost_mem_counters *mem) {
    int gotData = NO;

    uint64_t val64;
    struct vmtotal vmt;
    uint32_t page_size=4096; /* start with a guess */
 
    /* Get the page size */
    if(getSys64("vm.stats.vm.v_page_size", &val64)) {
      gotData = YES;
      page_size = (uint32_t)val64; /* Convert to bytes */
    }

    /* Mem_total */
    /* ... in MB to match what top shows */
    if(getSys64("hw.physmem", &val64)) {
      gotData = YES;
      mem->mem_total = val64;
    }

#if defined(OPTION1)
    /* Mem_cached = cache+inactive ( cached pages + (next)inactive pages ) */
    if(getSys64("vm.stats.vm.v_cache_count", &val64)) {
      gotData = YES;
      mem->mem_cached = (val64 * page_size);
    }
    /* Add to the mem_cached from above */
    if(getSys64("vm.stats.vm.v_inactive_count", &val64)) {
      gotData = YES;
      mem->mem_cached += (val64 * page_size); /* add the inactive mem */
    }
#else
    /* Mem_cached */
    if(getSysvmtotal(&vmt)) {
      gotData = YES;
      mem->mem_cached = ((vmt.t_rm - vmt.t_arm )* page_size);
    }
#endif
    /* Mem_shared */
    if(getSysvmtotal(&vmt)) {
      gotData = YES;
      mem->mem_shared = ((vmt.t_armshr )* page_size);
    }

    /* Page_in */
    if(getSys64("vm.stats.vm.v_vnodein", &val64)) {
      gotData = YES;
      mem->page_in = val64;
    }

    /* Page_out */
    if(getSys64("vm.stats.vm.v_vnodeout", &val64)) {
      gotData = YES;
      mem->page_out = val64;
    }

    /* Swap_total */
    if(getSys64("vm.swap_total", &val64)) {
      gotData = YES;
      mem->swap_total = val64;
    }

    /* Swap_free */
    if(getSys64("vm.stats.vm.v_swappgsout", &val64)) {
      gotData = YES;
      mem->swap_free = mem->swap_total - (val64 * page_size);
    }

    /* Swap_in */
    if(getSys64("vm.stats.vm.v_swapin", &val64)) {
      gotData = YES;
      mem->swap_in = val64;
    }

    /* Swap_out */
    if(getSys64("vm.stats.vm.v_swapout", &val64)) {
      gotData = YES;
      mem->swap_out = val64;
    }

    /* Mem_free .. in MB */
    if(getSysvmtotal(&vmt)) {
      gotData = YES;
      mem->mem_free = vmt.t_free * page_size;
    }

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

