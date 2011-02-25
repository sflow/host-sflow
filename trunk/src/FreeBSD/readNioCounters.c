/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#ifndef MIN_NET_POLL_INTERVAL
#define MIN_NET_POLL_INTERVAL 0.5
#endif

#define timertod(tvp) \
    ((double)(tvp)->tv_sec + (double)(tvp)->tv_usec/(1000*1000))


#include <sys/limits.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/time.h>

struct traffic {
        uint64_t in_bytes;
        uint64_t out_bytes;
        uint64_t in_pkts;
        uint64_t out_pkts;
};

static uint64_t
counterdiff(uint64_t oldval, uint64_t newval, uint64_t maxval, uint64_t maxdiff)
{
        uint64_t diff;

        if (maxdiff == 0)
                maxdiff = maxval;

        /* Paranoia */
        if (oldval > maxval || newval > maxval)
                return 0;

        /*
         * Tackle the easy case.  Don't worry about maxdiff here because
         * we're SOL if it happens (i.e. assuming a reset just makes
         * matters worse).
         */
        if (oldval <= newval)
                return (newval - oldval);

        /*
         * Now the tricky part.  If we assume counters never get reset,
         * this is easy.  Unfortunaly, they do get reset on some
         * systems, so we need to try and deal with that.  Our huristic
         * is that if out difference is greater then maxdiff and newval
         * is less or equal to maxdiff, then we've probably been reset
         * rather then actually wrapping.  Obviously, you need to be
         * careful to poll often enough that you won't exceed maxdiff or
         * you will get undersized numbers when you do wrap.
         */
        diff = maxval - oldval + newval;
        if (diff > maxdiff && newval <= maxdiff)
                return newval;

        return diff;
}

static void
get_netbw(double *in_bytes, double *out_bytes,
    double *in_pkts, double *out_pkts)
{
#ifdef NETBW_DEBUG
        char            name[IFNAMSIZ];
#endif
        struct          if_msghdr *ifm, *nextifm;
        struct          sockaddr_dl *sdl;
        char            *buf, *lim, *next;
        size_t          needed;
        int             mib[6];
        int             i;
        int             index;
        static double   ibytes, obytes, ipkts, opkts;
        struct timeval  this_time;
        struct timeval  time_diff;
        struct traffic  traffic;
        static struct timeval last_time = {0,0};
        static int      indexes = 0;
        static int      *seen = NULL;
        static struct traffic *lastcount = NULL;
        static double   o_ibytes, o_obytes, o_ipkts, o_opkts;

        ibytes = obytes = ipkts = opkts = 0.0;

        mib[0] = CTL_NET;
        mib[1] = PF_ROUTE;
        mib[2] = 0;
        mib[3] = 0;                     /* address family */
        mib[4] = NET_RT_IFLIST;
        mib[5] = 0;             /* interface index */

        gettimeofday(&this_time, NULL);
        timersub(&this_time, &last_time, &time_diff);
        if (timertod(&time_diff) < MIN_NET_POLL_INTERVAL) {
                goto output;
        }

        if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
               exit(1);
        if ((buf = malloc(needed)) == NULL)
               exit(1);
        if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
               exit(1);
        lim = buf + needed;

        next = buf;
        while (next < lim) {

                ifm = (struct if_msghdr *)next;

                if (ifm->ifm_type == RTM_IFINFO) {
                        sdl = (struct sockaddr_dl *)(ifm + 1);
                } else {
                        fprintf(stderr, "out of sync parsing NET_RT_IFLIST\n");
                        fprintf(stderr, "expected %d, got %d\n", RTM_IFINFO,
                                ifm->ifm_type);
                        fprintf(stderr, "msglen = %d\n", ifm->ifm_msglen);
                        fprintf(stderr, "buf:%p, next:%p, lim:%p\n", buf, next,
                                lim);
                        exit (1);
                }
                next += ifm->ifm_msglen;
                while (next < lim) {
                        nextifm = (struct if_msghdr *)next;

                        if (nextifm->ifm_type != RTM_NEWADDR)
                                break;

                        next += nextifm->ifm_msglen;
                }

                if ((ifm->ifm_flags & IFF_LOOPBACK) ||
                    !(ifm->ifm_flags & IFF_UP))
                        continue;

                index = ifm->ifm_index;

                /* If we don't have a previous value yet, make a slot. */
                if (index >= indexes) {
                        seen = realloc(seen, sizeof(*seen)*(index+1));
                        lastcount = realloc(lastcount,
                            sizeof(*lastcount)*(index+1));

                        /* Initalize the new slots */
                        for (i = indexes; i <= index; i++) {
                                seen[i] = 0;
                        }
                        indexes = index+1;
                }

                /*
                 * If this is the first time we've seen this interface,
                 * set the last values to the current ones.  That causes
                 * us to see no bandwidth on the interface the first
                 * time, but that's OK.
                 */
                if (!seen[index]) {
                        seen[index] = 1;
                        lastcount[index].in_bytes = ifm->ifm_data.ifi_ibytes;
                        lastcount[index].out_bytes = ifm->ifm_data.ifi_obytes;
                        lastcount[index].in_pkts = ifm->ifm_data.ifi_ipackets;
                        lastcount[index].out_pkts = ifm->ifm_data.ifi_opackets;
                }

                traffic.in_bytes = counterdiff(lastcount[index].in_bytes,
                    ifm->ifm_data.ifi_ibytes, ULONG_MAX, 0);
                traffic.out_bytes = counterdiff(lastcount[index].out_bytes,
                    ifm->ifm_data.ifi_obytes, ULONG_MAX, 0);
                traffic.in_pkts = counterdiff(lastcount[index].in_pkts,
                    ifm->ifm_data.ifi_ipackets, ULONG_MAX, 0);
                traffic.out_pkts = counterdiff(lastcount[index].out_pkts,
                    ifm->ifm_data.ifi_opackets, ULONG_MAX, 0);

                lastcount[index].in_bytes = ifm->ifm_data.ifi_ibytes;
                lastcount[index].out_bytes = ifm->ifm_data.ifi_obytes;
                lastcount[index].in_pkts = ifm->ifm_data.ifi_ipackets;
                lastcount[index].out_pkts = ifm->ifm_data.ifi_opackets;

#ifdef NETBW_DEBUG
                if_indextoname(index, name);
                printf("%s: \n", name);
                printf("\topackets=%llu ipackets=%llu\n",
                    traffic.out_pkts, traffic.in_pkts);
                printf("\tobytes=%llu ibytes=%llu\n",
                    traffic.out_bytes, traffic.in_bytes);
#endif

                if (timerisset(&last_time)) {
                        ibytes += (double)traffic.in_bytes / timertod(&time_diff
);
                        obytes += (double)traffic.out_bytes / timertod(&time_diff);
                        ipkts += (double)traffic.in_pkts / timertod(&time_diff);
                        opkts += (double)traffic.out_pkts / timertod(&time_diff)
;
                }
        }
        free(buf);

        /* Save the values from this time */
        last_time = this_time;
        o_ibytes = ibytes;
        o_obytes = obytes;
        o_ipkts = ipkts;
        o_opkts = opkts;

output:
        if (in_bytes != NULL)
                *in_bytes = o_ibytes;
        if (out_bytes != NULL)
                *out_bytes = o_obytes;
        if (in_pkts != NULL)
                *in_pkts = o_ipkts;
        if (out_pkts != NULL)
                *out_pkts = o_opkts;
}

float
pkts_in_func ( void )
{
   double in_pkts;
   float val;

   get_netbw(NULL, NULL, &in_pkts, NULL);

   val = (float)in_pkts;
   return val;
}

float
pkts_out_func ( void )
{
   double out_pkts;
   float val;

   get_netbw(NULL, NULL, NULL, &out_pkts);

   val = (float)out_pkts;
   return val;
}

float
bytes_out_func ( void )
{
   double out_bytes;
   float val;

   get_netbw(NULL, &out_bytes, NULL, NULL);

   val = (float)out_bytes;
   return val;
}

float
bytes_in_func ( void )
{
   double in_bytes;
   float val;

   get_netbw(&in_bytes, NULL, NULL, NULL);

   val = (float)in_bytes;
   return val;
}




  /*_________________---------------------------__________________
    _________________    getAdaptorNIO          __________________
    -----------------___________________________------------------
  */
  
  HSPAdaptorNIO *getAdaptorNIO(HSPAdaptorNIOList *nioList, char *deviceName) {
    for(int i = 0; i < nioList->num_adaptors; i++) {
      HSPAdaptorNIO *adaptor = nioList->adaptors[i];
      if(!strcmp(adaptor->deviceName, deviceName)) return adaptor;
    }
    return NULL;
  }

  /*_________________---------------------------__________________
    _________________    updateNioCounters      __________________
    -----------------___________________________------------------
  */
  
  void updateNioCounters(HSP *sp) {

    // don't do anything if we already refreshed the numbers less than a second ago
    if(sp->adaptorNIOList.last_update == sp->clk) {
      return;
    }
    sp->adaptorNIOList.last_update = sp->clk;

    FILE *procFile;
    procFile= fopen("/proc/net/dev", "r");
    if(procFile) {
      // ASCII numbers in /proc/diskstats may be 64-bit (if not now
      // then someday), so it seems safer to read into
      // 64-bit ints with scanf first,  then copy them
      // into the host_nio structure from there.
      uint64_t bytes_in = 0;
      uint64_t pkts_in = 0;
      uint64_t errs_in = 0;
      uint64_t drops_in = 0;
      uint64_t bytes_out = 0;
      uint64_t pkts_out = 0;
      uint64_t errs_out = 0;
      uint64_t drops_out = 0;
      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	char deviceName[MAX_PROC_LINE_CHARS];
	// assume the format is:
	// Inter-|   Receive                                                |  Transmit
	//  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	if(sscanf(line, "%[^:]:%"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %*u %*u %*u %*u %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64"",
		  deviceName,
		  &bytes_in,
		  &pkts_in,
		  &errs_in,
		  &drops_in,
		  &bytes_out,
		  &pkts_out,
		  &errs_out,
		  &drops_out) == 9) {
	  HSPAdaptorNIO *adaptor = getAdaptorNIO(&sp->adaptorNIOList, trimWhitespace(deviceName));
	  if(adaptor) {
	    // have to detect discontinuities here, so use a full
	    // set of latched counters and accumulators.
	    int accumulate = adaptor->last_update ? YES : NO;
	    adaptor->last_update = sp->clk;
	    uint64_t maxDeltaBytes = HSP_MAX_NIO_DELTA64;

	    SFLHost_nio_counters delta;
#define NIO_COMPUTE_DELTA(field) delta.field = field - adaptor->last_nio.field
	    NIO_COMPUTE_DELTA(pkts_in);
	    NIO_COMPUTE_DELTA(errs_in);
	    NIO_COMPUTE_DELTA(drops_in);
	    NIO_COMPUTE_DELTA(pkts_out);
	    NIO_COMPUTE_DELTA(errs_out);
	    NIO_COMPUTE_DELTA(drops_out);

	    if(sp->adaptorNIOList.polling_secs == 0) {
	      // 64-bit byte counters
	      NIO_COMPUTE_DELTA(bytes_in);
	      NIO_COMPUTE_DELTA(bytes_out);
	    }
	    else {
	      // for case where byte counters are 32-bit,  we need
	      // to use 32-bit unsigned arithmetic to avoid spikes
	      delta.bytes_in = (uint32_t)bytes_in - adaptor->last_bytes_in32;
	      delta.bytes_out = (uint32_t)bytes_out - adaptor->last_bytes_out32;
	      adaptor->last_bytes_in32 = bytes_in;
	      adaptor->last_bytes_out32 = bytes_out;
	      maxDeltaBytes = HSP_MAX_NIO_DELTA32;
	      // if we detect that the OS is using 64-bits then we can turn off the faster
	      // NIO polling. This should probably be done based on the kernel version or some
	      // other include-file definition, but it's not expensive to do it here like this:
	      if(bytes_in > 0xFFFFFFFF || bytes_out > 0xFFFFFFFF) {
		myLog(LOG_INFO, "detected 64-bit counters in /proc/net/dev");
		sp->adaptorNIOList.polling_secs = 0;
	      }
	    }

	    if(accumulate) {
	      // sanity check in case the counters were reset under out feet.
	      // normally we leave this to the upstream collector, but these
	      // numbers might be getting passed through from the hardware(?)
	      // so we treat them with particular distrust.
	      if(delta.bytes_in > maxDeltaBytes ||
		 delta.bytes_out > maxDeltaBytes ||
		 delta.pkts_in > HSP_MAX_NIO_DELTA32 ||
		 delta.pkts_out > HSP_MAX_NIO_DELTA32) {
		myLog(LOG_ERR, "detected counter discontinuity in /proc/net/dev");
		accumulate = NO;
	      }
	    }

	    if(accumulate) {
#define NIO_ACCUMULATE(field) adaptor->nio.field += delta.field
	      NIO_ACCUMULATE(bytes_in);
	      NIO_ACCUMULATE(pkts_in);
	      NIO_ACCUMULATE(errs_in);
	      NIO_ACCUMULATE(drops_in);
	      NIO_ACCUMULATE(bytes_out);
	      NIO_ACCUMULATE(pkts_out);
	      NIO_ACCUMULATE(errs_out);
	      NIO_ACCUMULATE(drops_out);
	    }

#define NIO_LATCH(field) adaptor->last_nio.field = field
	    NIO_LATCH(bytes_in);
	    NIO_LATCH(pkts_in);
	    NIO_LATCH(errs_in);
	    NIO_LATCH(drops_in);
	    NIO_LATCH(bytes_out);
	    NIO_LATCH(pkts_out);
	    NIO_LATCH(errs_out);
	    NIO_LATCH(drops_out);
	  }
	}
      }
      fclose(procFile);
    }
  }
  

  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter, SFLAdaptorList *adList) {
    int interface_count = 0;

#if defined(FreeBSD)

       // report the sum over all devices
       nio->bytes_in += (uint32_t)bytes_in_func();
       nio->bytes_out += (uint32_t)bytes_out_func();
       nio->pkts_in += (uint32_t)pkts_in_func();
       nio->pkts_out += (uint32_t)pkts_out_func ();
       interface_count++;
/*
       nio->errs_in += ifm->ifm_data.ifi_ierrors;
       nio->drops_in += ifm->ifm_data.ifi_iqdrops;
       nio->errs_out += ifm->ifm_data.ifi_oerrors;
       nio->drops_out += ifm->ifm_data.ifi_oqdrops;
*/
       
     return interface_count;
 
#else
    size_t devFilterLen = devFilter ? strlen(devFilter) : 0;

    // may need to schedule intermediate calls to updateNioCounters()
    // too (to avoid undetected wraps), but at the very least we need to do
    // it here to make sure the data is up to the second.
    updateNioCounters(sp);

    for(int i = 0; i < sp->adaptorNIOList.num_adaptors; i++) {
      HSPAdaptorNIO *adaptor = sp->adaptorNIOList.adaptors[i];
      if(devFilter == NULL || !strncmp(devFilter, adaptor->deviceName, devFilterLen)) {
	if(adList == NULL || adaptorListGet(adList, adaptor->deviceName) != NULL) {
	  interface_count++;
	  // report the sum over all devices that match the filter
	  nio->bytes_in += adaptor->nio.bytes_in;
	  nio->pkts_in += adaptor->nio.pkts_in;
	  nio->errs_in += adaptor->nio.errs_in;
	  nio->drops_in += adaptor->nio.drops_in;
	  nio->bytes_out += adaptor->nio.bytes_out;
	  nio->pkts_out += adaptor->nio.pkts_out;
	  nio->errs_out += adaptor->nio.errs_out;
	  nio->drops_out += adaptor->nio.drops_out;
	}
      }
    }
    return interface_count;
#endif
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

