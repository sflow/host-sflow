/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"
#include "loadAverage.h"

//globals
double load_1, load_5, load_15;
PDH_HQUERY procQuery;
PDH_HCOUNTER procTimeCounter;

/*
 * Calculates a Unix style exponentially damped/weighted moving average of the load.
 * The load is calculated by sampling the System\Processor Queue Length counter
 * to obtain the instantaneous processor queue length and combining this with
 * the 5 second average (over all processors) CPU utilization obtained from the
 * Processor\% Processor Time counter.
 * If the system is not fully utilized, the length of the processor queue should be 
 * close to 0. 
 * If the system is fully utilized, discount two items on the processor queue: 
 * the system thread and the thread which was displaced to take our measurement. 
 * If there are more than 2 items on the queue, add this to the load average to show 
 * the additional load on the system.
 * From the MS documentation for the Processor Queue Length counter:
 * A sustained processor queue of greater than two threads generally indicates 
 * processor congestion.
 */
void calcLoad()
{
	uint32_t queuelen = 0;
	double cpuload, load;
	PDH_HQUERY query;
	PDH_HCOUNTER counter;
	if (makeSingleCounterQuery(SYS_COUNTER_OBJECT, NULL, SYS_COUNTER_PROC_QLEN, &query, &counter) == ERROR_SUCCESS &&
		PdhCollectQueryData(query) == ERROR_SUCCESS) {
			queuelen = (uint32_t)getRawCounterValue(&counter);
	}
	if (query) {
		PdhCloseQuery(query);
	}
    cpuload = getCpuLoad();
    if (queuelen > 2) {
        load = cpuload + queuelen - 2;
	} else {
        load = cpuload;
	}
    load_1 = load_1 * 0.9200 + load * 0.0800;
    load_5 = load_5 * 0.9835 + load * 0.0165;
    load_15 = load_15 * 0.9945 + load * 0.0055;
}

double getCpuLoad()
{
	PDH_STATUS status;
	if (procQuery == NULL) {
		//This is the first time we've made the query, so initialise and save the query
		//handle and counter handle. Then use to gather the first data sample.
		status = makeSingleCounterQuery(CPU_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, CPU_COUNTER_TIME,
										&procQuery, &procTimeCounter);
		if (status != ERROR_SUCCESS) {
			procQuery = NULL;
		} else {
			PdhCollectQueryData(procQuery);
		}
		return 0;
	} else {
		//We've already got one sample, so use the query and counter handles again to get the
		//next sample and get the formatted value which calculates the average utilization in
		//the period between this and the last sample.
		DWORD dwType;
		PDH_FMT_COUNTERVALUE value;
		PdhCollectQueryData(procQuery);
		status = PdhGetFormattedCounterValue(procTimeCounter, PDH_FMT_DOUBLE, &dwType, &value);
		if (ERROR_SUCCESS == status) {
			//The _Total counter instance gives average time across all processors,
			//so multiply by the number of processors.
			return (value.doubleValue * getCpuNum()) / 100.0;
		} else {
			return 0;
		}
	}
}

int getCpuNum()
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return (int)si.dwNumberOfProcessors;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif