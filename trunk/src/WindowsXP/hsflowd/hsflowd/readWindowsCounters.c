
#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;

uint64_t readSingleCounter(char* path)
{
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_RAW_COUNTER Value;
	LONGLONG ret = 0;

    if(PdhOpenQuery(NULL, 0, &Query) == ERROR_SUCCESS) {
		if(PdhAddCounter(Query, path, 0, &Counter) == ERROR_SUCCESS &&
		   PdhCollectQueryData(Query) == ERROR_SUCCESS &&
		   PdhGetRawCounterValue(Counter, &dwType, &Value) == ERROR_SUCCESS) {
			ret = Value.FirstValue;
		}
        if (Query) PdhCloseQuery(Query);
    }
	return (uint64_t)ret;
}

uint32_t readMultiCounter(char* path, PPDH_RAW_COUNTER_ITEM *ppBuffer)
{
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD bufSize = 0, itemCount = 0;
	uint32_t ret = 0;

    if(PdhOpenQuery(NULL, 0, &Query) == ERROR_SUCCESS) {
		if(PdhAddCounter(Query, path, 0, &Counter) == ERROR_SUCCESS &&
		   PdhCollectQueryData(Query) == ERROR_SUCCESS &&
		   PdhGetRawCounterArray(Counter, &bufSize, &itemCount, NULL) == PDH_MORE_DATA) {
			*ppBuffer = (PPDH_RAW_COUNTER_ITEM)my_calloc(bufSize);
			if(PdhGetRawCounterArray(Counter, &bufSize, &itemCount, *ppBuffer) == ERROR_SUCCESS) {
				ret = itemCount;
				if(ret > 0 && strncmp("_Total",ppBuffer[0][itemCount-1].szName,6) == 0) {
					ret--; // use readSingleCounter if you need _Total;
				}
			}
		}
		if (Query) PdhCloseQuery(Query);
    }
	return (uint32_t)ret;
}

uint64_t readFormattedCounter(char* path)
{
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_FMT_COUNTERVALUE Value;
	LONGLONG ret = 0;

    if(PdhOpenQuery(NULL, 0, &Query) == ERROR_SUCCESS) {
		if(PdhAddCounter(Query, path, 0, &Counter) == ERROR_SUCCESS && 
           PdhCollectQueryData(Query) == ERROR_SUCCESS &&
		   PdhGetFormattedCounterValue(Counter, PDH_FMT_LARGE, &dwType, &Value) == ERROR_SUCCESS) { 
			ret = Value.largeValue;
		}
		if (Query) PdhCloseQuery(Query);
    }
	return (uint64_t)ret;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
