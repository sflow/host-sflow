/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"

extern int debug;
extern int cpu_num;
extern double load_1, load_5, load_15;

/*
 * Uses PDH to obtain the host_cpu counters and populates the
 * SFLHost_spu_counters stucture.
 * Uses Processor, System, and Process performance counter objects
 * for CPU time, interrupts and contexts and registry to obtain CPU speed.
 */ 
void readCpuCounters(SFLHost_cpu_counters *cpu) 
{
	cpu->load_one = (float)load_1;
	cpu->load_five = (float)load_5;
	cpu->load_fifteen = (float)load_15;
	PDH_HQUERY query;
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS) {
		PDH_HCOUNTER userTime, systemTime, idleTime, intrTime, interrupts, contexts, uptime, processes;
		if (addCounterToQuery(CPU_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, CPU_COUNTER_USER, &query, &userTime) == ERROR_SUCCESS &&
			addCounterToQuery(CPU_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, CPU_COUNTER_SYSTEM, &query, &systemTime) == ERROR_SUCCESS &&
			addCounterToQuery(CPU_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, CPU_COUNTER_IDLE, &query, &idleTime) == ERROR_SUCCESS &&
			addCounterToQuery(CPU_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, CPU_COUNTER_INTR, &query, &intrTime) == ERROR_SUCCESS &&
			addCounterToQuery(CPU_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, CPU_COUNTER_INTERRUPTS, &query, &interrupts) == ERROR_SUCCESS &&
			addCounterToQuery(SYS_COUNTER_OBJECT, NULL, SYS_COUNTER_CONTEXTS, &query, &contexts) == ERROR_SUCCESS &&
			addCounterToQuery(SYS_COUNTER_OBJECT, NULL, SYS_COUNTER_UPTIME, &query, &uptime) == ERROR_SUCCESS &&
			addCounterToQuery(SYS_COUNTER_OBJECT, NULL, SYS_COUNTER_PROCESSES, &query, &processes) == ERROR_SUCCESS &&
			PdhCollectQueryData(query) == ERROR_SUCCESS) {
			//CPU time is in 100ns units, divide by 10000 for ms
			cpu->cpu_user = (uint32_t)(getRawCounterValue(&userTime)/tick_to_ms);
			cpu->cpu_system = (uint32_t)(getRawCounterValue(&systemTime)/tick_to_ms);
			cpu->cpu_idle = (uint32_t)(getRawCounterValue(&idleTime)/tick_to_ms);
			cpu->cpu_intr = (uint32_t)(getRawCounterValue(&intrTime)/tick_to_ms);
			cpu->interrupts = (uint32_t)getRawCounterValue(&interrupts);
			cpu->contexts = (uint32_t)getRawCounterValue(&contexts);
			cpu->uptime = (uint32_t)getCookedCounterValue(&uptime);
			cpu->proc_total = (uint32_t)getRawCounterValue(&processes);
		}
		PdhCloseQuery(query);
	}
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS) {
		PDH_HCOUNTER threads;
		if (addCounterToQuery(THR_COUNTER_OBJECT, COUNTER_INSTANCE_ALL, THR_COUNTER_STATE, &query, &threads) == ERROR_SUCCESS &&
			PdhCollectQueryData(query) == ERROR_SUCCESS) {
			PPDH_RAW_COUNTER_ITEM_W values = NULL;
			uint32_t threadCount = getRawCounterValues(&threads, &values);
			if (threadCount > 0) {
				for (uint32_t i = 0; i < threadCount; i++) {
					if (values[i].RawValue.FirstValue == 2 && wcsncmp(L"Idle", values[i].szName, 4) != 0) {
						//count the threads that are running (state==2) and are not owned by the idle process.
						//the name of each thread state counter starts with the process name.
						cpu->proc_run++;
					}
				}
				my_free(values);
			}	
		}
		PdhCloseQuery(query);
	}

	cpu->cpu_num = getCpuNum();

	DWORD dwRet,cbData = sizeof(DWORD);
	HKEY hkey;

	// see http://support.microsoft.com/kb/888282 for ways to determine CPU speed
	dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						"hardware\\description\\system\\centralprocessor\\0",
						0,
						KEY_QUERY_VALUE,
						&hkey);

	if(dwRet == ERROR_SUCCESS) {
		dwRet = RegQueryValueEx( hkey,
			                     "~MHz",
			                     NULL,
								 NULL,
			                     (LPBYTE) &cpu->cpu_speed,
			                     &cbData );
		if(dwRet != ERROR_SUCCESS) cpu->cpu_speed = -1;
		RegCloseKey(hkey);
	}

	//These have no obvious Windows equivalent
	cpu->cpu_sintr = UNKNOWN_COUNTER;
	cpu->cpu_nice = UNKNOWN_COUNTER;
	cpu->cpu_wio = UNKNOWN_COUNTER;
	
	myLog(LOG_INFO,
		"readCpuCounters:\n\tload_one:\t%f\n\tload_five:\t%f\n\tload_fifteen:\t%f\n"
		"\tuptime:\t\t%lus\n\tcpu_num:\t%d\n"
		"\tcpu speed:\t%d MHz\n\tuser:\t\t%lu\n\tsystem:\t\t%lu\n\tidle:\t\t%lu\n\tirq:\t\t%lu\n"
		"\tcontexts:\t%lu\n\tinterrupts:\t%lu\n"
		"\tproc_total:\t%lu\n\tproc_run:\t%lu\n",
		cpu->load_one, cpu->load_five, cpu->load_fifteen,
		cpu->uptime, cpu->cpu_num, cpu->cpu_speed,
		cpu->cpu_user,cpu->cpu_system, cpu->cpu_idle, cpu->cpu_intr,
		cpu->contexts, cpu->interrupts,	cpu->proc_total, cpu->proc_run);
}

#if defined(__cplusplus)
} /* extern "C" */
#endif

