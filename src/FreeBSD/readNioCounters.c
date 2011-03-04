/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <sys/limits.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if.h>

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
    
    static int mib[] = { CTL_NET,
			 PF_ROUTE,
			 0,
			 0,  /* address family */
			 NET_RT_IFLIST,
			 0 }; /* ifIndex */
    
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
      myLog(LOG_ERR, "sysctl for interface list failed");
      return;
    }
    char *buf = my_calloc(needed);
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
      myLog(LOG_ERR, "sysctl for interface list failed (2nd time)");
    }
    else {
      char *lim = buf + needed;
      char *next = buf;
      
      while (next < lim) {
	struct if_msghdr *ifm = (struct if_msghdr *)next;
	
	if (ifm->ifm_type != RTM_IFINFO) {
	  myLog(LOG_ERR, "out of sync parsing NET_RT_IFLIST\n");
	  break;
	}
	
	next += ifm->ifm_msglen;
	while (next < lim) {
	  struct if_msghdr *nextifm = (struct if_msghdr *)next;
	  if (nextifm->ifm_type != RTM_NEWADDR) break;
	  next += nextifm->ifm_msglen;
	}
	
	if (!(ifm->ifm_flags & IFF_LOOPBACK) &&
	    (ifm->ifm_flags & IFF_UP)) {
	  char  deviceName[IFNAMSIZ];
	  
	  uint32_t index = ifm->ifm_index;
	  if(if_indextoname(index, deviceName)) {
	    char *str = deviceName;
	    trimWhitespace(str);
	    HSPAdaptorNIO *adaptor = getAdaptorNIO(&sp->adaptorNIOList, str);
	    if(adaptor) {
	      uint64_t bytes_in = ifm->ifm_data.ifi_ibytes;
	      uint64_t pkts_in = ifm->ifm_data.ifi_ipackets;
	      uint64_t errs_in = ifm->ifm_data.ifi_ierrors;
	      uint64_t drops_in = ifm->ifm_data.ifi_iqdrops;
	      uint64_t bytes_out = ifm->ifm_data.ifi_obytes;
	      uint64_t pkts_out = ifm->ifm_data.ifi_opackets;
	      uint64_t errs_out = ifm->ifm_data.ifi_oerrors;
	      uint64_t drops_out = (uint64_t)-1; /* unsupported */
	      
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
      }
    }
    my_free(buf);
  }

  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter, SFLAdaptorList *adList) {
    int interface_count = 0;
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
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

