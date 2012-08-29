/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <sys/sysctl.h>
#include <mach/mach.h>

  /*_________________---------------------------__________________
    _________________     readCpuCounters       __________________
    -----------------___________________________------------------
  */

#define JIFFY_TO_MS(i, hz) (((i) * 1000L) / (hz))
  
  int readCpuCounters(SFLHost_cpu_counters *cpu) {
    mach_port_t machport =  mach_host_self(); // share this at top level like xen handle $$$
    int gotData = NO;

    struct clockinfo ci = { 0 };
    size_t len = sizeof(ci);
    if(sysctlbyname("kern.clockrate", &ci, &len, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(<kern.clockrate>) failed : %s", strerror(errno));
    }
    else {
      // cpu ticks. From ganglia/libmetrics/Darwin/metrics.c:cpu_user_func()
      mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
      host_cpu_load_info_data_t cpuStats;
      kern_return_t ret = host_statistics(machport,
					  HOST_CPU_LOAD_INFO,
					  (host_info_t)&cpuStats,
					  &count);
      if (ret != KERN_SUCCESS) {
	myLog(LOG_ERR, "readCpuCounters: host_statistics() : %s", strerror(errno));
      }
      else {
	gotData = YES;
	cpu->cpu_user = (uint32_t)(JIFFY_TO_MS(cpuStats.cpu_ticks[CPU_STATE_USER], ci.hz));
	cpu->cpu_nice = (uint32_t)(JIFFY_TO_MS(cpuStats.cpu_ticks[CPU_STATE_NICE], ci.hz));
	cpu->cpu_system = (uint32_t)(JIFFY_TO_MS(cpuStats.cpu_ticks[CPU_STATE_SYSTEM], ci.hz));
	cpu->cpu_idle = (uint32_t)(JIFFY_TO_MS(cpuStats.cpu_ticks[CPU_STATE_IDLE], ci.hz));
	// $$$
	// cpu->cpu_wio
	// cpu->cpu_intr
	// cpu->cpu_sintr
      }
    }
     
    double loadavg[3];
    if(getloadavg(loadavg, 3) != -1) {
      gotData = YES;
      cpu->load_one = loadavg[0];
      cpu->load_five = loadavg[1];
      cpu->load_fifteen = loadavg[2];
    }
    
    // $$$
    // cpu->proc_run,
    // cpu->proc_total
    
    // $$$
    // cpu->interrupts
    // cpu->contexts
    
    // cpu->uptime
    
    // num_cpus. From ganglia/libmetrics/Darwin/metrics.c:cpu_num_func()
    {
      int ncpu = 0;
      size_t len = sizeof(ncpu);
      if(sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) != 0) {
	myLog(LOG_ERR, "sysctl(<ncpu>) failed : %s", strerror(errno));
      }
      else {
	gotData = YES;
	cpu->cpu_num = (uint32_t)ncpu;
      }
    }
    
    //cpu_speed. From ganglia/libmetrics/Darwin/metrics.c:cpu_speed_func()
    {
      unsigned long cpu_speed = 0;
      size_t len = sizeof(cpu_speed);
      if(sysctlbyname("hw.cpufrequency", &cpu_speed, &len, NULL, 0) != 0) {
	myLog(LOG_ERR, "sysctl(<cpu_speed>) failed : %s", strerror(errno));
      }
      else {
	gotData = YES;
	cpu->cpu_speed = (uint32_t)(cpu_speed / 1000000); // Hz to MHz
      }
    }
    
    return gotData;
  }
  
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

