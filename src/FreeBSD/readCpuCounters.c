/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#if !defined(FreeBSD)
#include <sys/sysinfo.h> // for get_nprocs()
#endif

#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/vmmeter.h>
#include <kvm.h>

#ifndef MIN_CPU_POLL_INTERVAL
#define MIN_CPU_POLL_INTERVAL 0.5
#define MAX_G_STRING_SIZE 32

#define timertod(tvp) \
    ((double)(tvp)->tv_sec + (double)(tvp)->tv_usec/(1000*1000))

static kvm_t *kd = NULL;



typedef union {
    int8_t   int8;
   uint8_t  uint8;
   int16_t  int16;
  uint16_t uint16;
   int32_t  int32;
  uint32_t uint32;
   float   f;
   double  d;
   char str[MAX_G_STRING_SIZE];
} g_val_t;

static long percentages(int cnt, int *out, register long *new,
                        register long *old, long *diffs)  {

    register int i;
    register long change;
    register long total_change;
    register long *dp;
    long half_total;

    /* initialization */
    total_change = 0;
    dp = diffs;

    /* calculate changes for each state and the overall change */
    for (i = 0; i < cnt; i++) {
        if ((change = *new - *old) < 0) {
            /* this only happens when the counter wraps */
            change = (int)
                ((unsigned long)*new-(unsigned long)*old);
        }
        total_change += (*dp++ = change);
        *old++ = *new++;
    }
    /* avoid divide by zero potential */
    if (total_change == 0) { total_change = 1; }

    /* calculate percentages based on overall change, rounding up */
    half_total = total_change / 2l;

    /* Do not divide by 0. Causes Floating point exception */
    if(total_change) {
        for (i = 0; i < cnt; i++) {
          *out++ = (int)((*diffs++ * 1000 + half_total) / total_change);
        }
    }

    /* return the total in case the caller wants to use it */
    return(total_change);
}

/* Get the CPU state given by index, from kern.cp_time
 * Use the constants in <sys/dkstat.h>
 * CP_USER=0, CP_NICE=1, CP_SYS=2, CP_INTR=3, CP_IDLE=4
 */
int cpu_state(int which) {

   long cp_time[CPUSTATES];
   long cp_diff[CPUSTATES];
   static long cp_old[CPUSTATES];
   static int cpu_states[CPUSTATES];
   static struct timeval this_time, last_time;
   struct timeval time_diff;
   size_t len = sizeof(cp_time);

   if (which == -1) {
      bzero(cp_old, sizeof(cp_old));
      bzero(&last_time, sizeof(last_time));
      return 0.0;
   }
   gettimeofday(&this_time, NULL);
   timersub(&this_time, &last_time, &time_diff);
   if (timertod(&time_diff) < MIN_CPU_POLL_INTERVAL) {
      goto output;
   }
   last_time = this_time;

   /* puts kern.cp_time array into cp_time */
   if (sysctlbyname("kern.cp_time", &cp_time, &len, NULL, 0) == -1) {
      return 0.0;
   }
   /* Use percentages function lifted from top(1) to figure percentages */
   percentages(CPUSTATES, cpu_states, cp_time, cp_old, cp_diff);
output:
   return cpu_states[which];
}

g_val_t
cpu_user_func( void )
{
   g_val_t val;

   val.f = (float) cpu_state(CP_USER)/10;

   return val;
}

g_val_t
cpu_nice_func ( void )
{
   g_val_t val;

   val.f = (float) cpu_state(CP_NICE)/10;

   return val;
}
g_val_t
cpu_system_func ( void )
{
   g_val_t val;

   val.f = (float) cpu_state(CP_SYS)/10;

   return val;
}

g_val_t
cpu_idle_func ( void )
{
   g_val_t val;

   val.f = (float) cpu_state(CP_IDLE)/10;

   return val;
}

/*
** FIXME - This metric is not valid on FreeBSD.
*/
float
cpu_wio_func ( void )
{
   float val;

   val = 0.0;
   return val;
}
/*
** FIXME - Idle time since startup.  The scheduler apparently knows
** this, but we it's fairly pointless so it's not exported.
*/

g_val_t
cpu_aidle_func ( void )
{
   g_val_t val;
   val.f = 0.0;
   return val;
}

float
cpu_intr_func ( void )
{
   float val;

   val = (float) cpu_state(CP_INTR)/10;

   return val;
}

/*
** FIXME - This metric is not valid on FreeBSD.
*/
uint32_t
cpu_sintr_func ( void )
{
   uint32_t val;
   val = 0;
   return val;
}

float
load_one_func ( void )
{
   double load[3];
   getloadavg(load, 3);
   return load[0];
}

float
load_five_func ( void )
{
   double load[3];

   getloadavg(load, 3);
   return load[1];
}

float
load_fifteen_func ( void )
{
   double load[3];

   getloadavg(load, 3);
   return load[2];
}

uint32_t
proc_run_func( void )
{
   struct kinfo_proc *kp;
   int i;
   int state;
   int nentries;
   int what = KERN_PROC_ALL;
   g_val_t val;

   val.uint32 = 0;

   if (kd == NULL)
      goto output;
#ifdef KERN_PROC_NOTHREADS
   what |= KERN_PROC_NOTHREADS
#endif
   if ((kp = kvm_getprocs(kd, what, 0, &nentries)) == 0 || nentries < 0)
      goto output;

   for (i = 0; i < nentries; kp++, i++) {
#ifdef KINFO_PROC_SIZE
      state = kp->ki_stat;
#else
      state = kp->kp_proc.p_stat;
#endif
      switch(state) {
         case SRUN:
         case SIDL:
            val.uint32++;
            break;
      }
   }

   if (val.uint32 > 0)
      val.uint32--;

output:
   return val.uint32;
}
uint32_t
proc_total_func ( void )
{
   g_val_t val;
   struct vmtotal total;
   size_t len;

   /* computed every 5 seconds */
   len = sizeof(total);
   sysctlbyname("vm.vmtotal", &total, &len, NULL, 0);

   val.uint32 = total.t_rq + \
      total.t_dw + total.t_pw + total.t_sl + total.t_sw;

   return val.uint32;
}

uint16_t
cpu_num_func ( void )
{
   g_val_t val;
   int ncpu;
   size_t len = sizeof (int);
   if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == -1 || !len)
        ncpu = 1;

   val.uint16 = ncpu;
   return val.uint16;
}

uint32_t
cpu_speed_func ( void )
{
   g_val_t val;
   char buf[1024];
   char *curptr;
   size_t len;
   uint32_t freq = 0, tmpfreq;
   uint64_t tscfreq;

   /*
    * If the system supports it, the cpufreq driver provides the best
    * access to CPU frequency.  Since we want a constant value, we're
    * looking for the maximum frequency, not the current one.  We
    * don't know what order the driver will report values in so we
    * search for the highest one by parsing the string returned by the
    * dev.cpu.0.freq_levels sysctl.  The format of the string is a space
    * seperated list of MHz/milliwatts.
    */
   tmpfreq = 0;
   len = sizeof(buf);
   if (sysctlbyname("dev.cpu.0.freq_levels", buf, &len, NULL, 0) == -1)
      buf[0] = '\0';
   curptr = buf;
   while (isdigit(curptr[0])) {
      freq = strtol(curptr, &curptr, 10);
      if (freq > tmpfreq)
         tmpfreq = freq;
      /* Skip the rest of this entry */
      while (!isspace(curptr[0]) && curptr[0] != '\0')
         curptr++;
      /* Find the next entry */
      while (!isdigit(curptr[0]) && curptr[0] != '\0')
         curptr++;
   }
   freq = tmpfreq;
   if (freq != 0)
      goto done;

   /*
    * machdep.tsc_freq exists on some i386/amd64 machines and gives the
    * CPU speed in Hz.  If it exists it's a decent value.
    */
   tscfreq = 0;
   len = sizeof(tscfreq);
   if (sysctlbyname("machdep.tsc_freq", &tscfreq, &len, NULL, 0) != -1) {
      freq = tscfreq / 1e6;
      goto done;
   }

done:
   val.uint32 = freq;

   return val.uint32;
}


#endif

  /*_________________---------------------------__________________
    _________________     readCpuCounters       __________________
    -----------------___________________________------------------
  */
  
  int readCpuCounters(SFLHost_cpu_counters *cpu) {
    int gotData = NO;

#if defined(FreeBSD)
	cpu->load_one = (float)load_one_func();
	cpu->load_five = (float)load_five_func();
	cpu->load_fifteen = (float)load_fifteen_func();
	cpu->proc_run = (uint32_t)proc_run_func();
	cpu->proc_total = (uint32_t)proc_total_func();
	cpu->cpu_num = (uint32_t)cpu_num_func();
	cpu->cpu_speed = (uint32_t) cpu_speed_func();
        cpu ->cpu_wio = (uint32_t)cpu_wio_func();
        cpu->cpu_intr = (uint32_t)cpu_intr_func();
        cpu->cpu_sintr = (uint32_t)cpu_sintr_func();
	gotData = YES;
	
#else
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

#define JIFFY_TO_MS(i) (((i) * 1000L) / hz)

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
	  if(line[0] == 'c' &&
	     line[1] == 'p' &&
	     line[2] == 'u' &&
	     (line[3] >= '0' && line[3] <= '9')) {
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

    // GNU libc knows the number of processors so
    // use this as a cross-check (and take whichever is higher)
    u_int32_t cpus_avail = get_nprocs();
    if(cpus_avail != cpu->cpu_num) {
      static int oneShotWarning = YES;
      if(oneShotWarning) {
	myLog(LOG_ERR, "WARNING: /proc/stat says %u cpus,  but get_nprocs says %u\n",
	      cpu->cpu_num,
	      cpus_avail);
	oneShotWarning = NO;
      }
      if(cpus_avail > cpu->cpu_num) cpu->cpu_num = cpus_avail;
    }

    //cpu_speed.  According to Ganglia/libmetrics we should
    // look first in /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
    // but for now just take the first one from /proc/cpuinfo
    procFile = fopen("/proc/cpuinfo", "r");
    if(procFile) {
#undef MAX_PROC_LINE_CHARS
#define MAX_PROC_LINE_CHARS 80
      char line[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	if(strncmp(line, "cpu MHz", 7) == 0) {
	  double cpu_mhz = 0.0;
	  if(sscanf(line, "cpu MHz : %lf", &cpu_mhz) == 1) {
	    gotData = YES;
	    cpu->cpu_speed = (uint32_t)(cpu_mhz);
	    break;
	  }
	}
      }
      fclose(procFile);
    }

#endif
    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

