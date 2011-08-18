/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

	extern int debug;

	extern void cleanNameForWMI(char *aname);

	/*
	_________________---------------------------__________________
	_________________      updateNioCounters    __________________
	-----------------___________________________------------------
	*/

	static SFLHost_nio_counters *getNewNIO(HSP *sp, char *deviceName) {
		// perform the same name-cleanup here as we did on the deviceName
		// in readInterfaces.  This is just in case we have the wrong list of
		// reserved characters.
		cleanNameForWMI(deviceName);
		//myLog(LOG_DEBUG, "looking up device <%s>...", deviceName);
		SFLAdaptor *adaptor = adaptorListGet(sp->adaptorList, deviceName);
		if(adaptor) {
			//myLog(LOG_DEBUG, "...found.  userData=%p", adaptor->userData);
			HSPAdaptorNIO *nio = (HSPAdaptorNIO *)adaptor->userData;
			if(nio) return &nio->new_nio;
		}
		return NULL;
	}

	void updateNioCounters(HSP *sp) {
		// don't do anything if we already refreshed the numbers less than a second ago
		if(sp->nio_last_update == sp->clk) {
			return;
		}
		sp->nio_last_update = sp->clk;

		// first read all the counters into new_nio
		PPDH_RAW_COUNTER_ITEM value;
		uint32_t icount = readMultiCounter("\\Network Interface(*)\\Bytes Received/sec",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				//myLog(LOG_DEBUG, "bytes_received counter <%s> = %lu",
				//	value[i].szName,
				//	value[i].RawValue.FirstValue);
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->bytes_in = value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}

		icount = readMultiCounter("\\Network Interface(*)\\Packets Received/sec",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->pkts_in = (uint32_t)value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}
		icount = readMultiCounter("\\Network Interface(*)\\Packets Received Errors",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->errs_in = (uint32_t)value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}
		icount = readMultiCounter("\\Network Interface(*)\\Packets Received Discarded",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->drops_in = (uint32_t)value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}
		icount = readMultiCounter("\\Network Interface(*)\\Bytes Sent/sec",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->bytes_out = value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}

		icount = readMultiCounter("\\Network Interface(*)\\Packets Sent/sec",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->pkts_out = (uint32_t)value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}
		icount = readMultiCounter("\\Network Interface(*)\\Packets Sent Errors",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->errs_out = (uint32_t)value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}
		icount = readMultiCounter("\\Network Interface(*)\\Packets Sent Discarded",&value);
		if(value) {
			for(uint32_t i = 0; i < icount; i++){
				SFLHost_nio_counters *newctrs = getNewNIO(sp, value[i].szName);
				if(newctrs) newctrs->drops_out = (uint32_t)value[i].RawValue.FirstValue;
			}
			my_free(value);
			value = NULL;
		}

		// now compute the deltas,  sanity check them, accumulate and latch
		for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
			SFLAdaptor *ad = sp->adaptorList->adaptors[i];
			if(ad) {
				HSPAdaptorNIO *nio = (HSPAdaptorNIO *)ad->userData;
				if(nio) {
					// have to detect discontinuities here, so use a full
					// set of latched counters and accumulators.
					int accumulate = nio->last_update ? YES : NO;
					nio->last_update = sp->clk;
					uint64_t maxDeltaBytes = HSP_MAX_NIO_DELTA64;

					SFLHost_nio_counters delta;
#define NIO_COMPUTE_DELTA(field) delta.field = nio->new_nio.field - nio->last_nio.field
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
						delta.bytes_in = (uint32_t)nio->new_nio.bytes_in - nio->last_bytes_in32;
						delta.bytes_out = (uint32_t)nio->new_nio.bytes_out - nio->last_bytes_out32;
						nio->last_bytes_in32 = (uint32_t)nio->new_nio.bytes_in;
						nio->last_bytes_out32 = (uint32_t)nio->new_nio.bytes_out;
						maxDeltaBytes = HSP_MAX_NIO_DELTA32;
						// if we detect that the OS is using 64-bits then we can turn off the faster
						// NIO polling. This should probably be done based on the kernel version or some
						// other include-file definition, but it's not expensive to do it here like this:
						if(nio->new_nio.bytes_in > 0xFFFFFFFF || nio->new_nio.bytes_out > 0xFFFFFFFF) {
							myLog(LOG_DEBUG, "detected 64-bit network counters");
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
								myLog(LOG_ERR, "detected NIO counter discontinuity");
								accumulate = NO;
						}
					}

					if(accumulate) {
#define NIO_ACCUMULATE(field) nio->nio.field += delta.field
						NIO_ACCUMULATE(bytes_in);
						NIO_ACCUMULATE(pkts_in);
						NIO_ACCUMULATE(errs_in);
						NIO_ACCUMULATE(drops_in);
						NIO_ACCUMULATE(bytes_out);
						NIO_ACCUMULATE(pkts_out);
						NIO_ACCUMULATE(errs_out);
						NIO_ACCUMULATE(drops_out);
						//myLog(LOG_DEBUG, "accumulated NIO counters (new=%lu old=%lu delta=%lu nio->nio.bytes_in now = %lu)",
						//                  nio->new_nio.bytes_in, nio->last_nio.bytes_in, delta.bytes_in, nio->nio.bytes_in);
					}

#define NIO_LATCH(field) nio->last_nio.field = nio->new_nio.field
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




	/*
	_________________---------------------------__________________
	_________________      readNioCounters      __________________
	-----------------___________________________------------------
	*/

	int readNioCounters(HSP *sp, SFLHost_nio_counters *nio) {
		// may need to schedule intermediate calls to updateNioCounters()
		// too (to avoid undetected wraps), but at the very least we need to do
		// it here to make sure the data is up to the second.
		updateNioCounters(sp);

		int gotData = NO;
		// just add up all the counters
		for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
			SFLAdaptor *ad = sp->adaptorList->adaptors[i];
			if(ad) {
				HSPAdaptorNIO *ctrs = (HSPAdaptorNIO *)ad->userData;
				if(ctrs) {
					gotData = YES;
					nio->bytes_in += ctrs->nio.bytes_in;
					nio->pkts_in += ctrs->nio.pkts_in;
					nio->errs_in += ctrs->nio.errs_in;
					nio->drops_in += ctrs->nio.drops_in;
					nio->bytes_out += ctrs->nio.bytes_out;
					nio->pkts_out += ctrs->nio.pkts_out;
					nio->errs_out += ctrs->nio.errs_out;
					nio->drops_out += ctrs->nio.drops_out;
				}
			}
		}
		myLog(LOG_INFO,"readNioCounters:\n\trbytes:\t%lu\n\trdrops:\t%lu\n\trerrs:\t%lu\n\trpkts:\t%lu\n\ttbytes:\t%lu\n\ttdrops:\t%lu\n\tterrs:\t%lu\n\ttpkts:\t%lu\n",
			nio->bytes_in,nio->drops_in,nio->errs_in,nio->pkts_in,nio->bytes_out,nio->drops_out,nio->errs_out,nio->pkts_out);
		return gotData;
	}



#if defined(__cplusplus)
} /* extern "C" */
#endif

