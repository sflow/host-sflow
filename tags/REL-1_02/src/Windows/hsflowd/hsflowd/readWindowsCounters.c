
#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;

uint64_t readSingleCounter(char* path)
{
    PDH_STATUS Status;
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_RAW_COUNTER Value;
	LONGLONG ret = 0;

    Status = PdhOpenQuery(NULL, 0, &Query);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

    Status = PdhAddCounter(Query, path, 0, &Counter);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }


	Status = PdhCollectQueryData(Query);
	if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

	Status = PdhGetRawCounterValue(Counter, &dwType, &Value);
	if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }
	ret = Value.FirstValue;
		
Cleanup:

    if (Query) 
    {
        PdhCloseQuery(Query);
    }

	return (uint64_t)ret;
}

uint32_t readMultiCounter(char* path, PPDH_RAW_COUNTER_ITEM *ppBuffer)
{
    PDH_STATUS Status;
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD bufSize = 0, itemCount = 0;
	uint32_t ret = 0, i = 0;

    Status = PdhOpenQuery(NULL, 0, &Query);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

    Status = PdhAddCounter(Query, path, 0, &Counter);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }


	Status = PdhCollectQueryData(Query);
	if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

	//*ppBuffer = (PPDH_RAW_COUNTER_ITEM)malloc(bufSize);
	Status = PdhGetRawCounterArray(Counter, &bufSize, &itemCount, NULL);  //bufSize contains required buffer length
	if (Status != ERROR_SUCCESS) 
    {
		if(Status == PDH_MORE_DATA){
			*ppBuffer = (PPDH_RAW_COUNTER_ITEM)malloc(bufSize);
			Status = PdhGetRawCounterArray(Counter, &bufSize, &itemCount, *ppBuffer);
			if(Status != ERROR_SUCCESS){
				goto Cleanup;
			}
			ret = itemCount;
			if(strncmp("_Total",ppBuffer[0][itemCount-1].szName,6) == 0){
				ret--; // use readSingleCounter if you need _Total;
			}
		}
        else goto Cleanup;
    }

		
Cleanup:

    if (Query) 
    {
        PdhCloseQuery(Query);
    }

	return (uint32_t)ret;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
