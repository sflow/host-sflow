/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;

  /*_________________---------------------------__________________
    _________________     readMemoryCounters    __________________
    -----------------___________________________------------------
  */
  
  int readMemoryCounters(SFLHost_mem_counters *mem) {
    int gotData = NO;
	MEMORYSTATUSEX memStat;

	memStat.dwLength = sizeof(memStat);
	if(GlobalMemoryStatusEx(&memStat) == 0){

		myLog(LOG_ERR,"GlobalMemoryStatusEx failed: %d\n",GetLastError());
		return NO;
	}

	mem->mem_total = memStat.ullTotalPhys;
	mem->mem_free = memStat.ullAvailPhys;
	mem->swap_total = memStat.ullTotalPageFile;
	mem->swap_free = memStat.ullAvailPageFile;
	mem->mem_cached = readSingleCounter("\\Memory\\Cache Bytes");
	mem->swap_in = (uint32_t)readSingleCounter("\\Memory\\Pages Input/sec");
	mem->swap_out = (uint32_t)readSingleCounter("\\Memory\\Pages Output/sec");

	//There are no obvious Windows equivalents
	mem->mem_buffers = UNKNOWN_COUNTER_64;
    mem->mem_shared = UNKNOWN_COUNTER_64;
	mem->page_in = UNKNOWN_COUNTER;
	mem->page_out = UNKNOWN_COUNTER;

	gotData = YES;

	myLog(LOG_INFO,"readMemoryCounters:\n\ttotal: %I64d\n\tfree: %I64d\n\tcached: %I64d\n\tswap_in: %d\n\tswap_out: %d\n",
			mem->mem_total,mem->mem_free,mem->mem_cached,mem->swap_in,mem->swap_out);

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif