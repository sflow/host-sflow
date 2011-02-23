#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"
#include "loadAverage.h"

//globals
double load_1, load_5, load_15;
PDH_HQUERY cpu_load_query = NULL;

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
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_FMT_COUNTERVALUE Value;
	double ret = 0;
	CHAR localizedPath[PDH_MAX_COUNTER_PATH];
	
	if(!cpu_load_query){
		Status = PdhOpenQuery(NULL, 0, &cpu_load_query);
	}

	strcpy(localizedPath,"\\Processor(_Total)\\% Processor Time");
	localizePath(localizedPath);

    Status = PdhAddCounter(cpu_load_query, localizedPath, 0, &Counter);
	Status = PdhCollectQueryData(cpu_load_query);
	Status = PdhGetFormattedCounterValue(Counter, PDH_FMT_DOUBLE, &dwType, &Value);
	ret = Value.doubleValue * getCpuNum();
	return ret/100.0;
}

int getCpuNum(){
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return (int)si.dwNumberOfProcessors;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif