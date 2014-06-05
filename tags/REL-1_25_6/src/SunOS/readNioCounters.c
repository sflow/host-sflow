/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <kstat.h>

extern int debug;

  /*_________________---------------------------__________________
    _________________      logNioCounters       __________________
    -----------------___________________________------------------
  */
  static void logNioCounters(SFLHost_nio_counters *nio, char *msg1, char *msg2) {
    myLog(LOG_INFO, "%s (%s):", msg1 ?: "", msg2 ?: "");
    myLog(LOG_INFO, "  byts_in=%"PRIu64" byts_out=%"PRIu64, nio->bytes_in, nio->bytes_out);
    myLog(LOG_INFO, "  pkts_in=%"PRIu32" pkts_out=%"PRIu32, nio->pkts_in, nio->pkts_out);
    myLog(LOG_INFO, "  errs_in=%"PRIu32" errs_out=%"PRIu32, nio->errs_in, nio->errs_out);
    myLog(LOG_INFO, "  drps_in=%"PRIu32" drps_out=%"PRIu32, nio->drops_in, nio->drops_out);
  }

  /*_________________---------------------------__________________
    _________________    get_kstat_uintxx       __________________
    -----------------___________________________------------------
  */

  static uint32_t get_kstat_uint32(kstat_t *ksp, char *ctrname) {
    kstat_named_t *knp = kstat_data_lookup(ksp, ctrname);
    if(knp) {
      switch(knp->data_type) {
      case KSTAT_DATA_INT32: return (uint32_t)knp->value.i32;
      case KSTAT_DATA_UINT32: return (uint32_t)knp->value.ui32;
      case KSTAT_DATA_INT64: return (uint32_t)knp->value.i64;
      case KSTAT_DATA_UINT64: return (uint32_t)knp->value.ui64;
      default: break;
      }
    }
    return 0;
  }

  static uint64_t get_kstat_uint64(kstat_t *ksp, char *ctrname) {
    kstat_named_t *knp = kstat_data_lookup(ksp, ctrname);
    if(knp) {
      switch(knp->data_type) {
      case KSTAT_DATA_INT32: return (uint64_t)knp->value.i32;
      case KSTAT_DATA_UINT32: return (uint64_t)knp->value.ui32;
      case KSTAT_DATA_INT64: return (uint64_t)knp->value.i64;
      case KSTAT_DATA_UINT64: return (uint64_t)knp->value.ui64;
      default: break;
      }
    }
    return 0;
  }

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
#ifndef KSNAME_BUFFER_SIZE
#define KSNAME_BUFFER_SIZE 32
#endif
    char devName[KSNAME_BUFFER_SIZE];


    kc = kstat_open();
    if (NULL == kc) {
      myLog(LOG_ERR, "readNioCounters kstat_open failed");
    } else {
      for (ksp = kc->kc_chain; NULL != ksp; ksp = ksp->ks_next) {
	int includeDev = NO;
	// Concatenate the module name and instance number to create device name
	snprintf(devName, KSNAME_BUFFER_SIZE, "%s%d", ksp->ks_module, ksp->ks_instance);

#if (HSP_SOLARIS >= 5011)
	// on solaris 11 we collect name=phys, module!=aggr,vnic for counter purposes.
	// and don't use any of the others for counters.
	if(my_strequal(ksp->ks_name, "phys")
	   && !my_strequal(ksp->ks_module, "aggr") 
	   && !my_strequal(ksp->ks_module, "vnic")) {
	  includeDev = YES;
	}
#else
	// If device name equals the kstat's name, then we have a kstat the describes the device. 
	if (!strncmp(ksp->ks_name, devName, KSNAME_BUFFER_SIZE)) {
	  includeDev = YES;
	}
#endif

	if(includeDev) {
	  SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, devName);
	  if (adaptor && adaptor->userData) {
	    HSPAdaptorNIO *niostate = (HSPAdaptorNIO*)adaptor->userData;

	    // we might know this is a loopback interface, so apply that filter here
	    if(niostate->vlan != HSP_VLAN_ALL
	       || niostate->loopback
	       || niostate->bond_master) {
	      continue;
	    }


	    if (-1 == kstat_read(kc, ksp, NULL)) {
	      myLog(LOG_ERR, "kstat_read error module: %s, name: %s, class: %s): %s",
		    ksp->ks_module, ksp->ks_name, ksp->ks_class, strerror(errno));
	      continue;
	    }

	    if(debug) {
	      myLog(LOG_INFO, "readNioCounters: device=%s (last_update=%u)", devName, niostate->last_update);
	    }
	    SFLHost_nio_counters latest = { 0 };

	    latest.pkts_in = get_kstat_uint32(ksp, "ipackets");
	    latest.errs_in =  get_kstat_uint32(ksp, "ierrors");
	    latest.drops_in =  get_kstat_uint32(ksp, "norcvbuf");
	    latest.bytes_in = get_kstat_uint64(ksp, "rbytes64");
	    latest.pkts_out = get_kstat_uint32(ksp, "opackets");
	    latest.errs_out = get_kstat_uint32(ksp, "oerrors");
	    latest.drops_out = get_kstat_uint32(ksp, "noxmitbuf");
	    latest.bytes_out = get_kstat_uint64(ksp, "obytes64");

	    // have to detect discontinuities here, so use a full
	    // set of latched counters and accumulators.
	    int accumulate = niostate->last_update ? YES : NO;
	    niostate->last_update = sp->clk;
	    uint64_t maxDeltaBytes = HSP_MAX_NIO_DELTA64;

	    SFLHost_nio_counters delta = { 0 };
#define NIO_COMPUTE_DELTA(field) delta.field = latest.field - niostate->last_nio.field
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
	      delta.bytes_in = (uint32_t)latest.bytes_in - niostate->last_bytes_in32;
	      delta.bytes_out = (uint32_t)latest.bytes_out - niostate->last_bytes_out32;
	      niostate->last_bytes_in32 = latest.bytes_in;
	      niostate->last_bytes_out32 = latest.bytes_out;
	      maxDeltaBytes = HSP_MAX_NIO_DELTA32;
	      // if we detect that the OS is using 64-bits then we can turn off the faster
	      // NIO polling. This should probably be done based on the kernel version or some
	      // other include-file definition, but it's not expensive to do it here like this:
	      if(latest.bytes_in > 0xFFFFFFFF || latest.bytes_out > 0xFFFFFFFF) {
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
	      if(debug > 1) {
		logNioCounters(&niostate->nio, "accumulate", devName);
	      }
	    }

#define NIO_LATCH(field) niostate->last_nio.field = latest.field
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
	  if(devFilter == NULL && (niostate->vlan != HSP_VLAN_ALL
				   || niostate->loopback
				   || niostate->bond_master
				   || !niostate->forCounters)) {
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
    if(debug > 1) {
      logNioCounters(nio, "ROLLUP", "ALL");
    }
    return interface_count;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

