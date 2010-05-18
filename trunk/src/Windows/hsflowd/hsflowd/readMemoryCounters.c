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
		if(debug){
			printf("GlobalMemoryStatusEx failed: %d\n",GetLastError());
		}
		return NO;
	}

	mem->mem_total = memStat.ullTotalPhys/1024;
	mem->mem_free = memStat.ullAvailPhys/1024;
	mem->swap_total = memStat.ullTotalPageFile/1024;
	mem->swap_free = memStat.ullAvailPageFile/1024;
	mem->mem_cached = readSingleCounter("\\Memory\\Cache Bytes")/1024;
	mem->swap_in = readSingleCounter("\\Memory\\Pages Input/sec");
	mem->swap_out = readSingleCounter("\\Memory\\Pages Output/sec");

	//There are no obvious Windows equivalents
	mem->mem_buffers = UNKNOWN_COUNTER;
    //mem->swap_cached = UNKNOWN_COUNTER;
	//mem->mem_active = UNKNOWN_COUNTER;
	//mem->mem_inactive = UNKNOWN_COUNTER;
	mem->page_in = UNKNOWN_COUNTER;
	mem->page_out = UNKNOWN_COUNTER;

	gotData = YES;

	//if(debug){
	//	printf("readMemoryCounters:\n\ttotal: %lu\n\tfree: %lu\n\tcached: %lu\n\tpage_in: %lu\n\tpage_out: %lu\n",
	//		mem->total,mem->free,mem->cached,mem->page_in,mem->page_out);
	//}
    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif