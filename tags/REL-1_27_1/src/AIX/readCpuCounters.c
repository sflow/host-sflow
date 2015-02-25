/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
// #include <linux/param.h> // for HZ
#include <sys/sysinfo.h> // for get_nprocs()

#include <libperfstat.h>


  /*_________________---------------------------__________________
    _________________     readCpuCounters       __________________
    -----------------___________________________------------------
  */
  
  int readCpuCounters(SFLHost_cpu_counters *cpu) {
    int gotData = NO;


   perfstat_cpu_total_t cpu_total;
   if(perfstat_cpu_total(NULL, &cpu_total, sizeof(cpu_total), 1) != -1) {
      gotData = YES;
      cpu->load_one = (float)cpu_total.loadavg[0]/(float)(1<<SBITS);
      cpu->load_five = (float)cpu_total.loadavg[1]/(float)(1<<SBITS);
      cpu->load_fifteen = (float)cpu_total.loadavg[2]/(float)(1<<SBITS);
      cpu->cpu_num = cpu_total.ncpus;
      cpu->cpu_speed = cpu_total.processorHZ / (1024 * 1024); /* MHz */
      cpu->cpu_user = (cpu_total.user * 1000) / cpu_total.processorHZ;
      SFL_UNDEF_COUNTER(cpu->cpu_nice);
      cpu->cpu_system = (cpu_total.sys * 1000) / cpu_total.processorHZ;
      cpu->cpu_idle = (cpu_total.idle * 1000) / cpu_total.processorHZ;
      cpu->cpu_wio = (cpu_total.wait * 1000) / cpu_total.processorHZ;
      cpu->proc_run = cpu_total.runque /* + cpu_total.swpque */;
      if(cpu->proc_run > 0) {
	// subtract myself from the running process count,
	// otherwise it always shows at least 1.  Thanks to
	// Dave Mangot for pointing this out.
	cpu->proc_run--;
      }
      cpu->interrupts = cpu_total.devintrs /* + cpu_total.softintrs */;
      cpu->contexts = cpu_total.pswitch;
      cpu->uptime = cpu_total.lbolt; /* is this in seconds? */
   }

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

