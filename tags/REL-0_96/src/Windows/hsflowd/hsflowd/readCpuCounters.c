/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;

  /*_________________---------------------------__________________
    _________________     readCpuCounters       __________________
    -----------------___________________________------------------
  */
  
  int readCpuCounters(SFLHost_cpu_counters *cpu) {
    int gotData = NO;
	uint32_t i = 0;
	PPDH_RAW_COUNTER_ITEM thread, processor;

	cpu->cpu_user = (uint32_t)readSingleCounter("\\Processor(_Total)\\% User Time");
	cpu->cpu_system = (uint32_t)readSingleCounter("\\Processor(_Total)\\% Privileged Time");
	cpu->cpu_idle = (uint32_t)readSingleCounter("\\Processor(_Total)\\% Idle Time");
	cpu->cpu_intr = (uint32_t)readSingleCounter("\\Processor(_Total)\\% Interrupt Time");
	cpu->interrupts = (uint32_t)readSingleCounter("\\Processor(_Total)\\Interrupts/sec");
	cpu->contexts = (uint32_t)readSingleCounter("\\System\\Context Switches/sec");
	cpu->uptime = (uint32_t)readSingleCounter("\\System\\System Up Time");  //TODO: convert to UNIX time
	cpu->cpu_num = readMultiCounter("\\Processor(*)\\% Processor Time",&processor);

	cpu->proc_total = readMultiCounter("\\Thread(*)\\Thread State",&thread);
	cpu->proc_run = 0;
	for(i = 0; i < cpu->proc_total; i++){
		if(thread[i].RawValue.FirstValue == 2 && strncmp("Idle",thread[i].szName,4) != 0){
			cpu->proc_run++;
		}
	}

	//These have no obvious Windows equivalent
	cpu->cpu_sintr = UNKNOWN_COUNTER;
	cpu->cpu_nice = UNKNOWN_COUNTER;
	cpu->cpu_wio = UNKNOWN_COUNTER;
	cpu->load_one = UNKNOWN_FLOAT;
	cpu->load_five = UNKNOWN_FLOAT;
	cpu->load_fifteen = UNKNOWN_FLOAT;
	
	MyLog(LOG_INFO,"readCpuCounters:\n\tcpu_num:\t%d\n\tuser: %lu\n\tsystem: %lu\n\tidle: %lu\n\tirq: %lu\n\tthreads_total: %lu\n\tthreads_running: %lu\n",
			cpu->cpu_num,cpu->cpu_user,cpu->cpu_system,cpu->cpu_idle,cpu->cpu_intr,cpu->proc_total,cpu->proc_run);

	if(thread){ 
		free(thread);
	}
	if(processor){
		free(processor);
	}

	gotData = YES;

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

