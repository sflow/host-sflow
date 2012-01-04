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
    PDH_HCOUNTER Counter;
	DWORD dwType;
	PDH_FMT_COUNTERVALUE Value;
	double ret = 0;
	PDH_HQUERY cpu_load_query = NULL;
	
	if(PdhOpenQuery(NULL, 0, &cpu_load_query) == ERROR_SUCCESS) {
		if(PdhAddCounter(cpu_load_query, "\\Processor(_Total)\\% Processor Time", 0, &Counter) == ERROR_SUCCESS &&
		PdhCollectQueryData(cpu_load_query) == ERROR_SUCCESS &&
		PdhGetFormattedCounterValue(Counter, PDH_FMT_DOUBLE, &dwType, &Value) == ERROR_SUCCESS) {
			ret = (Value.doubleValue * getCpuNum()) / 100.0;
		}
		if (cpu_load_query) PdhCloseQuery(cpu_load_query);
	}
	return ret;
}

int getCpuNum(){
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return (int)si.dwNumberOfProcessors;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif