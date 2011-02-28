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

/*
 * This is just an example of how to grab sysctl( ) 
 * stuff from BSD.
 */
void
cpu_example_func(char *host_uuid, size_t *len)
{
   int mib[2]; 

   mib[0] = CTL_KERN;
   mib[1] = KERN_HOSTUUID;
   sysctl(mib, 2, host_uuid, len, NULL, 0);
}

float
cpu_user_func( void )
{
   float val;
   val = (float) cpu_state(CP_USER)/10;
   return val;
}

float
cpu_nice_func ( void )
{
   float val;
   val = (float) cpu_state(CP_NICE)/10;
   return val;
}
float
cpu_system_func ( void )
{
   float val;
   val = (float) cpu_state(CP_SYS)/10;
   return val;
}

float
cpu_idle_func ( void )
{
   float val;
   val = (float) cpu_state(CP_IDLE)/10;
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

int getSys64(char *, uint64_t *);

uint32_t
cpu_sintr_func ( void )
{
   uint32_t val = 0;
   uint64_t val64;
   if(getSys64("vm.stats.sys.v_soft", &val64)) {
	val = (uint32_t)val64;
   }
   return val;
}

uint32_t
cpu_interrupts_func ( void )
{
   uint32_t val = 0;
   uint64_t val64;
   if(getSys64("vm.stats.sys.v_intr", &val64)) {
	val = (uint32_t)val64;
   }
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
  
int readCpuCounters(SFLHost_cpu_counters *cpu) 
{
  int gotData = NO;
  uint64_t val64;
  if(getSys64("vm.stats.sys.v_swtch", &val64)) {
    gotData = YES;
    cpu->contexts = (uint32_t)val64;
  }
  
  cpu->load_one = (float)load_one_func();
  cpu->load_five = (float)load_five_func();
  cpu->load_fifteen = (float)load_fifteen_func();
  cpu->proc_run = (uint32_t)proc_run_func();
  cpu->proc_total = (uint32_t)proc_total_func();
  cpu->cpu_num = (uint32_t)cpu_num_func();
  cpu->cpu_speed = (uint32_t) cpu_speed_func();
  cpu ->cpu_wio = (uint32_t)cpu_wio_func();
  cpu->cpu_intr = (uint32_t)cpu_intr_func();
  cpu->interrupts = (uint32_t)cpu_interrupts_func();
  cpu->cpu_sintr = (uint32_t)cpu_sintr_func();
  cpu->cpu_nice = (uint32_t)cpu_nice_func();
  cpu->cpu_user = (uint32_t)cpu_user_func();
  cpu->cpu_system = (uint32_t)cpu_system_func();
  cpu->cpu_idle = (uint32_t)cpu_idle_func();
  gotData = YES;
  
  return gotData;
}


#if defined(__cplusplus)
} /* extern "C" */
#endif

