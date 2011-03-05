
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
	CHAR localizedPath[PDH_MAX_COUNTER_PATH];

	strcpy(localizedPath,path);
	localizePath(localizedPath);

    Status = PdhOpenQuery(NULL, 0, &Query);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

    Status = PdhAddCounter(Query, localizedPath, 0, &Counter);
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
	CHAR localizedPath[PDH_MAX_COUNTER_PATH];

	strcpy(localizedPath,path);
	localizePath(localizedPath);

    Status = PdhOpenQuery(NULL, 0, &Query);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

    Status = PdhAddCounter(Query, localizedPath, 0, &Counter);
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

uint64_t readFormattedCounter(char* path)
{
    PDH_STATUS Status;
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_FMT_COUNTERVALUE Value;
	LONGLONG ret = 0;
	CHAR localizedPath[PDH_MAX_COUNTER_PATH];

	strcpy(localizedPath,path);
	localizePath(localizedPath);

    Status = PdhOpenQuery(NULL, 0, &Query);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

    Status = PdhAddCounter(Query, localizedPath, 0, &Counter);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }


	Status = PdhCollectQueryData(Query);
	if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

	Status = PdhGetFormattedCounterValue(Counter, PDH_FMT_LARGE, &dwType, &Value);
	if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }
	ret = Value.largeValue;
		
Cleanup:

    if (Query) 
    {
        PdhCloseQuery(Query);
    }

	return (uint64_t)ret;
}

uint32_t localizePath(char *path)
{
	//See: http://support.microsoft.com/kb/q287159/

	DWORD dwRet = ERROR_SUCCESS;
	DWORD cbPathData = 0;
	PDH_COUNTER_PATH_ELEMENTS *pPathElements = NULL;
	CHAR objectName[PDH_MAX_COUNTER_PATH], counterName[PDH_MAX_COUNTER_PATH];
	LONG idx = 0;

	dwRet = PdhParseCounterPath(path,pPathElements,&cbPathData,0);
	if(dwRet == PDH_MORE_DATA){
		pPathElements = (PDH_COUNTER_PATH_ELEMENTS*)malloc(cbPathData);
		if(!pPathElements){
			goto Cleanup;
		}
		dwRet = PdhParseCounterPath(path,pPathElements,&cbPathData,0);
		if(dwRet != PDH_CSTATUS_VALID_DATA){
			goto Cleanup;
		}
	}else{
		goto Cleanup;
	}

	idx = getPdhIndex(pPathElements->szObjectName);
	cbPathData = PDH_MAX_COUNTER_PATH;
	PdhLookupPerfNameByIndex(NULL,idx,objectName,&cbPathData);
	pPathElements->szObjectName = objectName;

	idx = getPdhIndex(pPathElements->szCounterName);
	cbPathData = PDH_MAX_COUNTER_PATH;
	PdhLookupPerfNameByIndex(NULL,idx,counterName,&cbPathData);
	pPathElements->szCounterName = counterName;

	cbPathData = PDH_MAX_COUNTER_PATH;
	PdhMakeCounterPath(pPathElements,path,&cbPathData,0);

Cleanup:
	if(pPathElements)free(pPathElements);

	return ERROR_SUCCESS;
}

uint32_t getPdhIndex(LPCSTR oName){
	LPBYTE next, data;
	DWORD cbRegData = 1, dwRet = ERROR_SUCCESS;
	LONG idx = 0;

	//fetch english object and counter names and indexes
	data = (LPBYTE)malloc(cbRegData);
	if(!data){
		goto Cleanup;
	}
	dwRet = RegQueryValueEx( HKEY_PERFORMANCE_DATA,
		                     "Counter 009",
		                     NULL,
							 NULL,
		                     (LPBYTE)data,
		                     &cbRegData );
	if(dwRet == ERROR_MORE_DATA){
		free(data);
		data = (LPBYTE)malloc(cbRegData);
		if(!data){
			goto Cleanup;
		}
		dwRet = RegQueryValueEx( HKEY_PERFORMANCE_DATA,
		                     "Counter 009",
		                     NULL,
							 NULL,
		                     (LPBYTE)data,
		                     &cbRegData );
		if(dwRet != ERROR_SUCCESS)
			goto Cleanup;
	}

	next = data;
	while(next < data + cbRegData){
		if(strcmp(oName,next)==0){
			break;
		}
		idx = atol(next);
		next +=strlen(next) + 1;
	}

Cleanup:
	if(data)free(data);

	return idx;
}


#if defined(__cplusplus)
} /* extern "C" */
#endif
