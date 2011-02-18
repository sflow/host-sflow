#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"
#include "loadAverage.h"

//globals
double load_1, load_5, load_15;

extern int debug;

int calcLoad(){
	uint32_t queuelen;
	double cpuload, load;

    queuelen = (uint32_t)readFormattedCounter("\\System\\Processor Queue Length");
    cpuload = getCpuLoad();
    if(queuelen > 2)
        load = cpuload + queuelen - 2;
    else
        load = cpuload;
    load_1 = load_1 * 0.9200 + load * 0.0800;
    load_5 = load_5 * 0.9835 + load * 0.0165;
    load_15 = load_15 * 0.9945 + load * 0.0055;
	return 0;
}

double getCpuLoad(){
	PDH_STATUS Status;
    PDH_HQUERY Query = NULL;
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_FMT_COUNTERVALUE Value;
	double ret = 0;
	int i = 0;

    Status = PdhOpenQuery(NULL, 0, &Query);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

    Status = PdhAddCounter(Query, "\\Processor(_Total)\\% Processor Time", 0, &Counter);
    if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }

	for(i = 0; i < 2; i++){ //this counter requires at least 2 samples
		Status = PdhCollectQueryData(Query);
		if (Status != ERROR_SUCCESS) 
		{
			goto Cleanup;
		}
		Sleep(500);
	}

	Status = PdhGetFormattedCounterValue(Counter, PDH_FMT_DOUBLE, &dwType, &Value);
	if (Status != ERROR_SUCCESS) 
    {
        goto Cleanup;
    }
	ret = Value.doubleValue;
		
Cleanup:

    if (Query) 
    {
        PdhCloseQuery(Query);
    }

	return ret/100.0;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif