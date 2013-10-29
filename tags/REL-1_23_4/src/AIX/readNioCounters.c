/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <libperfstat.h>


  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter, SFLAdaptorList *adList) {
    int interface_count=0;
    perfstat_netinterface_total_t nio_total;

    if(perfstat_netinterface_total(NULL, &nio_total, sizeof(nio_total), 1) != -1) {
      interface_count = nio_total.number;
      nio->bytes_in += nio_total.ibytes;
      nio->pkts_in += nio_total.ipackets;
      nio->errs_in += nio_total.ierrors;
      SFL_UNDEF_COUNTER(nio->drops_in);
      nio->bytes_out += nio_total.obytes;
      nio->pkts_out += nio_total.opackets;
      nio->errs_out += nio_total.oerrors;
      nio->drops_out += nio_total.xmitdrops;
    }
    return interface_count;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

