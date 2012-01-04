/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;
extern int cpu_num;
extern double load_1, load_5, load_15;

  /*_________________---------------------------__________________
    _________________     readCpuCounters       __________________
    -----------------___________________________------------------
  */
  
  int readCpuCounters(SFLHost_cpu_counters *cpu) {
    int gotData = NO;
	uint32_t i = 0;
	PPDH_RAW_COUNTER_ITEM thread = NULL;
	DWORD dwRet,cbData = sizeof(DWORD);
	HKEY hkey;

	cpu->load_one = (float)load_1;
	cpu->load_five = (float)load_5;
	cpu->load_fifteen = (float)load_15;
	cpu->cpu_user = (uint32_t)readSingleCounter("\\Processor(_Total)\\% User Time");
	cpu->cpu_system = (uint32_t)readSingleCounter("\\Processor(_Total)\\% Privileged Time");
	cpu->cpu_idle = (uint32_t)readSingleCounter("\\Processor(_Total)\\% Idle Time");
	cpu->cpu_intr = (uint32_t)readSingleCounter("\\Processor(_Total)\\% Interrupt Time");
	cpu->interrupts = (uint32_t)readSingleCounter("\\Processor(_Total)\\Interrupts/sec");
	cpu->contexts = (uint32_t)readSingleCounter("\\System\\Context Switches/sec");
	cpu->uptime = (uint32_t)readFormattedCounter("\\System\\System Up Time");
	cpu->cpu_num = getCpuNum();

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

	cpu->proc_total = readMultiCounter("\\Thread(*)\\Thread State",&thread);
	cpu->proc_run = 0;
	if(thread){
		for(i = 0; i < cpu->proc_total; i++){
			if(thread[i].RawValue.FirstValue == 2 && strncmp("Idle",thread[i].szName,4) != 0){
				cpu->proc_run++;
			}
		}
		my_free(thread);
	}

	//These have no obvious Windows equivalent
	cpu->cpu_sintr = UNKNOWN_COUNTER;
	cpu->cpu_nice = UNKNOWN_COUNTER;
	cpu->cpu_wio = UNKNOWN_COUNTER;
	
	myLog(LOG_INFO,
		"readCpuCounters:\n\tload_one:\t%f\n\tload_five:\t%f\n\tload_fifteen:\t%f\n"
		"\tuptime:\t\t%lus\n\tcpu_num:\t%d\n"
		"\tcpu speed:\t%d MHz\n\tuser: %lu\n\tsystem: %lu\n\tidle: %lu\n\tirq: %lu\n"
		"\tthreads_total: %lu\n\tthreads_running: %lu\n",
		cpu->load_one,cpu->load_five,cpu->load_fifteen,cpu->uptime,cpu->cpu_num,
		cpu->cpu_speed,cpu->cpu_user,cpu->cpu_system,
		cpu->cpu_idle,cpu->cpu_intr,cpu->proc_total,cpu->proc_run);


	gotData = YES;

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

