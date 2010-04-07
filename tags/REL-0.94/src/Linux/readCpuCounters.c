/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <linux/param.h> // for HZ

  /*_________________---------------------------__________________
    _________________     readCpuCounters       __________________
    -----------------___________________________------------------
  */
  
  int readCpuCounters(SFLHost_cpu_counters *cpu) {
    int gotData = NO;
    FILE *procFile;
    // We assume that the cpu counters struct has been initialized
    // with all zeros.
    procFile= fopen("/proc/loadavg", "r");
    if(procFile) {
      // The docs are pretty clear about %f being "float" rather
      // that "double", so just give the pointers to fscanf.
      if(fscanf(procFile, "%f %f %f %"SCNu32"/%"SCNu32"",
		&cpu->load_one,
		&cpu->load_five,
		&cpu->load_fifteen,
		&cpu->proc_run,
		&cpu->proc_total) == 5) {
	gotData = YES;
      }
      fclose(procFile);
    }

    procFile = fopen("/proc/stat", "r");
    if(procFile) {
      // ASCII numbers in /proc/stat may be 64-bit (if not now
      // then someday), so it seems safer to read into
      // 64-bit ints with scanf first,  then copy them
      // into the host_cpu structure from there. This also
      // allows us to convert "jiffies" to milliseconds.
      uint64_t cpu_user=0;
      uint64_t cpu_nice =0;
      uint64_t cpu_system=0;
      uint64_t cpu_idle=0;
      uint64_t cpu_wio=0;
      uint64_t cpu_intr=0;
      uint64_t cpu_sintr=0;
      uint64_t cpu_interrupts=0;
      uint64_t cpu_contexts=0;

#define JIFFY_TO_MS(i) (((i) * 1000L) / HZ)

      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      uint32_t lineNo = 0;
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	if(++lineNo == 1) {
	  if(sscanf(line, "cpu %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64"",
		    &cpu_user,
		    &cpu_nice,
		    &cpu_system,
		    &cpu_idle,
		    &cpu_wio,
		    &cpu_intr,
		    &cpu_sintr) >= 4) {
	    gotData = YES;
	    cpu->cpu_user = (uint32_t)(JIFFY_TO_MS(cpu_user));
	    cpu->cpu_nice = (uint32_t)(JIFFY_TO_MS(cpu_nice));
	    cpu->cpu_system = (uint32_t)(JIFFY_TO_MS(cpu_system));
	    cpu->cpu_idle = (uint32_t)(JIFFY_TO_MS(cpu_idle));
	    cpu->cpu_wio = (uint32_t)(JIFFY_TO_MS(cpu_wio));
	    cpu->cpu_intr = (uint32_t)(JIFFY_TO_MS(cpu_intr));
	    cpu->cpu_sintr = (uint32_t)(JIFFY_TO_MS(cpu_sintr));
	  }
	}
	else {
	  if(strncmp(line, "cpu", 3) == 0) {
	    gotData = YES;
	    cpu->cpu_num++;
	  }
	  else if(strncmp(line, "intr", 4) == 0) {
	    // total interrupts is the second token on this line
	    if(sscanf(line, "intr %"SCNu64"", &cpu_interrupts) == 1) {
	      gotData = YES;
	      cpu->interrupts = (uint32_t)cpu_interrupts;
	    }
	  }
	  else if(strncmp(line, "ctxt", 4) == 0) {
	    if(sscanf(line, "ctxt %"SCNu64"", &cpu_contexts) == 1) {
	      gotData = YES;
	      cpu->contexts = (uint32_t)cpu_contexts;
	    }
	  }
	}
      }
      fclose(procFile);
    }

    procFile = fopen("/proc/uptime", "r");
    if(procFile) {
      float uptime = 0;
      if(fscanf(procFile, "%f",	&uptime) == 1) {
	gotData = YES;
	cpu->uptime = (uint32_t)uptime;
      }
      fclose(procFile);
    }

    //cpu_speed? $$$

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

