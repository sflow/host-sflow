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
	mem->page_in = (uint32_t)readSingleCounter("\\Memory\\Pages Input/sec");
	mem->page_out = (uint32_t)readSingleCounter("\\Memory\\Pages Output/sec");

	//There are no obvious Windows equivalents
	mem->mem_buffers = UNKNOWN_GAUGE_64;
    mem->mem_shared = UNKNOWN_GAUGE_64;
	//Memory\Cache Bytes(http://technet.microsoft.com/en-us/library/cc778082(v=ws.10).aspx)
	//is not equivalent to Linux file system cache and there appears to be no
	//equivalent concept to file system cache, so we leave cached as unknown.
	//see discussion at http://sourceforge.net/mailarchive/message.php?msg_id=30319148
	mem->mem_cached = UNKNOWN_GAUGE_64;
	mem->swap_in = UNKNOWN_COUNTER;
	mem->swap_out = UNKNOWN_COUNTER;

	gotData = YES;

	myLog(LOG_INFO,"readMemoryCounters:\n\ttotal: %I64d\n\tfree: %I64d\n\tpage_in: %d\n\tpage_out: %d\n",
			mem->mem_total,mem->mem_free,mem->page_in,mem->page_out);

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif