/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
    adapted from Ganglia libmetrics
  */
  
  int readNioCounters(SFLHost_nio_counters *nio, char *devFilter) {
    int interface_count = 0;

    int mib[]={ CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };
    size_t needed=0;
    if(sysctl(mib, 6, NULL, &needed, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(<NioCounters>) probe failed : %s", strerror(errno));
      return NO;
    }
    char *buf = (char*)my_calloc(needed);
    if (sysctl(mib, 6, buf, &needed, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(<NioCounters>) read failed : %s", strerror(errno));
      return NO;
    }
    char *end = buf + needed;
    for(char *p = buf; p < end; ) {
      struct if_msghdr *ifm = (struct if_msghdr *)p;
      if(ifm->ifm_type != RTM_IFINFO) {
	myLog(LOG_ERR, "sysctl(<NioCounters>) walk failed (offset=%d of %d)", p - buf, needed);
	return NO;
      }
      p += ifm->ifm_msglen;

      // consume the RTM_NEWADDR msgs that follow
      while(p < end) {
	struct if_msghdr *nextifm = (struct if_msghdr *)p;
	if(nextifm->ifm_type != RTM_NEWADDR) break;
	p += nextifm->ifm_msglen;
      }

      // ignore loopback interfaces and interfaces that are currently down
      if(ifm->ifm_flags & IFF_LOOPBACK) continue;
      if(!(ifm->ifm_flags & IFF_UP)) continue;

      // $$$ test the device filter - is the device name known here?
      // may need to get the ifindex with ifm->ifm_index and then look up
      // the name from there - or go the other way and make the filter be
      // a filter on ifindex.

      interface_count++;
      // report the sum over all devices
      nio->bytes_in += ifm->ifm_data.ifi_ibytes;
      nio->pkts_in += ifm->ifm_data.ifi_ipackets;
      nio->errs_in += ifm->ifm_data.ifi_ierrors;
      nio->drops_in += ifm->ifm_data.ifi_iqdrops;
      nio->bytes_out += ifm->ifm_data.ifi_obytes;
      nio->pkts_out += ifm->ifm_data.ifi_opackets;
      nio->errs_out += ifm->ifm_data.ifi_oerrors;
      // nio->drops_out += ifm->ifm_data.ifi_oqdrops;
      
    }
    free(buf);
    return interface_count;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

