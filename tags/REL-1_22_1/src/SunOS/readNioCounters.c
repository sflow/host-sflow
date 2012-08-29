/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <kstat.h>

  /*_________________---------------------------__________________
    _________________    updateNioCounters      __________________
    -----------------___________________________------------------
  */

  void updateNioCounters(HSP *sp) {

    // don't do anything if we already refreshed the numbers less than a second ago
    if(sp->nio_last_update == sp->clk) {
      return;
    }
    sp->nio_last_update = sp->clk;

    kstat_ctl_t *kc;
    kstat_t *ksp;
    kstat_named_t *knp;
#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
    char devName[KSNAME_BUFFER_SIZE];

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

    kc = kstat_open();
    if (NULL == kc) {
      myLog(LOG_ERR, "readNioCounters kstat_open failed");
    } else {
      for (ksp = kc->kc_chain; NULL != ksp; ksp = ksp->ks_next) {
	snprintf(devName, KSNAME_BUFFER_SIZE, "%s%d", ksp->ks_module, ksp->ks_instance);
	if (!strncmp(ksp->ks_name, devName, KSNAME_BUFFER_SIZE)) {
	  SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, devName);
	  if (adaptor && adaptor->userData) {
	    if (-1 == kstat_read(kc, ksp, NULL)) {
	      myLog(LOG_ERR, "kstat_read error module: %s, name: %s, class: %s): %s",
		    ksp->ks_module, ksp->ks_name, ksp->ks_class, strerror(errno));
	      continue;
	    }

	    knp = kstat_data_lookup(ksp, "ipackets");
	    if (NULL != knp)
	      pkts_in += knp->value.ui32;

	    knp = kstat_data_lookup(ksp, "ierrors");
	    if (NULL != knp)
	      errs_in += knp->value.ui32;

	    knp = kstat_data_lookup(ksp, "norcvbuf");
	    if (NULL != knp)
	      drops_in += knp->value.ui32;

	    knp = kstat_data_lookup(ksp, "rbytes64");
	    if (NULL != knp)
	      bytes_in += knp->value.ui64;

	    knp = kstat_data_lookup(ksp, "opackets");
	    if (NULL != knp)
	      pkts_out += knp->value.ui32;

	    knp = kstat_data_lookup(ksp, "oerrors");
	    if (NULL != knp)
	      errs_out += knp->value.ui32;

	    knp = kstat_data_lookup(ksp, "noxmtbuf");
	    if (NULL != knp)
	      drops_out += knp->value.ui32;

	    knp = kstat_data_lookup(ksp, "obytes64");
	    if (NULL != knp)
	      bytes_out += knp->value.ui64;

	    HSPAdaptorNIO *niostate = (HSPAdaptorNIO*)adaptor->userData;
	    // have to detect discontinuities here, so use a full
	    // set of latched counters and accumulators.
	    int accumulate = niostate->last_update ? YES : NO;
	    niostate->last_update = sp->clk;
	    uint64_t maxDeltaBytes = HSP_MAX_NIO_DELTA64;

	    SFLHost_nio_counters delta;
#define NIO_COMPUTE_DELTA(field) delta.field = field - niostate->last_nio.field
	    NIO_COMPUTE_DELTA(pkts_in);
	    NIO_COMPUTE_DELTA(errs_in);
	    NIO_COMPUTE_DELTA(drops_in);
	    NIO_COMPUTE_DELTA(pkts_out);
	    NIO_COMPUTE_DELTA(errs_out);
	    NIO_COMPUTE_DELTA(drops_out);

	    if(sp->nio_polling_secs == 0) {
	      // 64-bit byte counters
	      NIO_COMPUTE_DELTA(bytes_in);
	      NIO_COMPUTE_DELTA(bytes_out);
	    }
	    else {
	      // for case where byte counters are 32-bit,  we need
	      // to use 32-bit unsigned arithmetic to avoid spikes
	      delta.bytes_in = (uint32_t)bytes_in - niostate->last_bytes_in32;
	      delta.bytes_out = (uint32_t)bytes_out - niostate->last_bytes_out32;
	      niostate->last_bytes_in32 = bytes_in;
	      niostate->last_bytes_out32 = bytes_out;
	      maxDeltaBytes = HSP_MAX_NIO_DELTA32;
	      // if we detect that the OS is using 64-bits then we can turn off the faster
	      // NIO polling. This should probably be done based on the kernel version or some
	      // other include-file definition, but it's not expensive to do it here like this:
	      if(bytes_in > 0xFFFFFFFF || bytes_out > 0xFFFFFFFF) {
		myLog(LOG_INFO, "detected 64-bit counters");
		sp->nio_polling_secs = 0;
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

		myLog(LOG_ERR, "detected counter discontinuity");
		accumulate = NO;
	      }
	    }

	    if(accumulate) {
#define NIO_ACCUMULATE(field) niostate->nio.field += delta.field
	      NIO_ACCUMULATE(bytes_in);
	      NIO_ACCUMULATE(pkts_in);
	      NIO_ACCUMULATE(errs_in);
	      NIO_ACCUMULATE(drops_in);
	      NIO_ACCUMULATE(bytes_out);
	      NIO_ACCUMULATE(pkts_out);
	      NIO_ACCUMULATE(errs_out);
	      NIO_ACCUMULATE(drops_out);
	    }

#define NIO_LATCH(field) niostate->last_nio.field = field
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

      kstat_close(kc);
    }
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

    for(int i = 0; i < sp->adaptorList->num_adaptors; i++) {
      SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
      // note that the devFilter here is a prefix-match
      if(devFilter == NULL || !strncmp(devFilter, adaptor->deviceName, devFilterLen)) {
	if(adList == NULL || adaptorListGet(adList, adaptor->deviceName) != NULL) {
	  HSPAdaptorNIO *niostate = (HSPAdaptorNIO *)adaptor->userData;
	  
	  // in the case where we are adding up across all
	  // interfaces, be careful to avoid double-counting.
	  // By leaving this test until now we make it possible
	  // to know the counters for any interface or sub-interface
	  // if required (e.g. for the readPackets() module).
	  if(devFilter == NULL && (niostate->vlan != HSP_VLAN_ALL ||
				   niostate->loopback ||
				   niostate->bond_master)) {
	    continue;
	  }

	  interface_count++;
	  // report the sum over all devices that match the filter
	  nio->bytes_in += niostate->nio.bytes_in;
	  nio->pkts_in += niostate->nio.pkts_in;
	  nio->errs_in += niostate->nio.errs_in;
	  nio->drops_in += niostate->nio.drops_in;
	  nio->bytes_out += niostate->nio.bytes_out;
	  nio->pkts_out += niostate->nio.pkts_out;
	  nio->errs_out += niostate->nio.errs_out;
	  nio->drops_out += niostate->nio.drops_out;
	}
      }
    }
    return interface_count;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

