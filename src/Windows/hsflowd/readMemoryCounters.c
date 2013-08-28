/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"

/**
 * Populates the host_memory structure using data retrieved using
 * GlobalMemoryStatusEx function and the Memory performance counter
 * object.
 * Returns FALSE if call to GlobalMemoryStatusEx produces an error, TRUE otherwise.
 * Note that the Windows use of memory and classification of use does
 * not map cleanly to Linux terms.
 * Windows Resource Monitor reports cached as Standby+Modified this is not the
 * equivalent of Linux file system cache, however it could be viewed as
 * analagous memory usage, and it makes sense to retain some consistency with
 * Windows tools.
 * Windows Resource Monitor reports free memory as free and zero page list bytes,
 * this is used for free memory. There are no obvious equivalents for shared
 * and buffers so these counters are reported as unknown.
 * Windows also does not seem to report swapping (all memory associated with a process
 * swapped in/out of memory). Memory\\Pages Input/sec and Memory\\Pages Output/sec
 * are used for page_in and page_out.
 */
BOOL readMemoryCounters(SFLHost_mem_counters *mem) 
{
	MEMORYSTATUSEX memStat;
	memStat.dwLength = sizeof(memStat);
	if (GlobalMemoryStatusEx(&memStat) == 0){
		myLog(LOG_ERR,"GlobalMemoryStatusEx failed: %d\n",GetLastError());
		return FALSE;
	}
	mem->mem_total = memStat.ullTotalPhys;
	mem->swap_total = memStat.ullTotalPageFile;
	mem->swap_free = memStat.ullAvailPageFile;
	PDH_HQUERY query;
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS) {
		PDH_HCOUNTER free, standbyCore, standbyNormal, standbyReserve, modified, pageIn, pageOut;
		if (addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_FREE, &query, &free) == ERROR_SUCCESS &&
			addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_STANDBY_CORE, &query, &standbyCore) == ERROR_SUCCESS &&
			addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_STANDBY_NORMAL, &query, &standbyNormal) == ERROR_SUCCESS &&
			addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_STANDBY_RESERVE, &query, &standbyReserve) == ERROR_SUCCESS &&
			addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_MODIFIED, &query, &modified) == ERROR_SUCCESS &&
			addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_PAGE_IN, &query, &pageIn) == ERROR_SUCCESS &&
			addCounterToQuery(MEM_COUNTER_OBJECT, NULL, MEM_COUNTER_PAGE_OUT, &query, &pageOut) == ERROR_SUCCESS &&
			PdhCollectQueryData(query) == ERROR_SUCCESS) {
			mem->mem_free = getRawCounterValue(&free);
			mem->mem_cached = getRawCounterValue(&standbyCore) +
				getRawCounterValue(&standbyNormal) +
				getRawCounterValue(&standbyReserve) +
				getRawCounterValue(&modified);
			mem->page_in = (uint32_t)getRawCounterValue(&pageIn);
			mem->page_out = (uint32_t)getRawCounterValue(&pageOut);
		}
		PdhCloseQuery(query);
	}

	//There are no obvious Windows equivalents
    mem->mem_shared = UNKNOWN_GAUGE_64;
	mem->mem_buffers = UNKNOWN_GAUGE_64;
	//using the definition that swapping is when all the memory associated with a
	//process is moved in/out of RAM
	mem->swap_in = UNKNOWN_COUNTER;
	mem->swap_out = UNKNOWN_COUNTER;
	myLog(LOG_INFO,
		"readMemoryCounters:\n\ttotal: \t\t%I64d\n\tfree: \t\t%I64d\n"
		"\tcached: \t%I64d\n\tpage_in: \t%d\n\tpage_out: \t%d\n"
		"\tswap_total: \t%I64d\n\tswap_free: \t%I64d\n",
		mem->mem_total, mem->mem_free,
		mem->mem_cached, mem->page_in, mem->page_out,
		mem->swap_total, mem->swap_free);
	return TRUE;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif