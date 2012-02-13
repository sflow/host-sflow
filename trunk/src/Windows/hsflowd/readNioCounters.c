/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"

extern int debug;

static PDH_HQUERY query = NULL;
static PDH_HCOUNTER bytesIn, pktsIn, errorsIn, discardsIn;
static PDH_HCOUNTER bytesOut, pktsOut,errorsOut, discardsOut;

static PDH_STATUS addCounter(wchar_t *counterName, PDH_HCOUNTER *counter)
{
	return addCounterToQuery(NIO_COUNTER_OBJECT, COUNTER_INSTANCE_ALL, counterName, &query, counter);
}

/**
 * If we are going to collect counters every second while we work out whether
 * we've got 64bit or not, lets just make the counter query once and reuse it.
 */
static PDH_STATUS createCounterQuery()
{
	PDH_STATUS status= PdhOpenQuery(NULL, 0, &query);
	if (status == ERROR_SUCCESS) {
		addCounter(NIO_COUNTER_BYTES_IN, &bytesIn);
		addCounter(NIO_COUNTER_PACKETS_IN, &pktsIn);
		addCounter(NIO_COUNTER_ERRORS_IN, &errorsIn);
		addCounter(NIO_COUNTER_DISCARDS_IN, &discardsIn);
		addCounter(NIO_COUNTER_BYTES_OUT, &bytesOut);
		addCounter(NIO_COUNTER_PACKETS_OUT, &pktsOut);
		addCounter(NIO_COUNTER_ERRORS_OUT, &errorsOut);
		addCounter(NIO_COUNTER_DISCARDS_OUT, &discardsOut);
		return ERROR_SUCCESS;
	} else {
		return status;
	}
}

/**
 * Returns the latest cached NIO counters for the adaptor which is referenced by
 * instanceName. Note this is not the deviceName (GUID) for the adaptor
 * but the friendly name used by perfmon and stored in the adaptor's
 * userData HSPAdaptorNIO->countersInstance.
 * Returns NULL if an adaptor with the counters instance name is not found.
 */
static SFLHost_nio_counters *getNewNIO(HSP *sp, wchar_t *instanceName) {
	SFLAdaptorList *adList = sp->adaptorList;
	if (adList == NULL) {
		return NULL;
	}
	//if(LOG_INFO <= debug) myLog(LOG_INFO, "getNewNIO: looking up device %S...", instanceName);
	for (uint32_t i = 0; i < adList->num_adaptors; i++) {
		SFLAdaptor *adaptor = adList->adaptors[i];
		if (adaptor != NULL && adaptor->userData != NULL) {
			HSPAdaptorNIO *nio = (HSPAdaptorNIO *)sp->adaptorList->adaptors[i]->userData;
			if (nio != NULL && nio->countersInstance != NULL) {
				//if(LOG_INFO <= debug) myLog(LOG_INFO, "getNewNIO: comparing <%S> with <%S>", instanceName, nio->countersInstance);
				if (wcscmp(instanceName, nio->countersInstance) == 0) {
					//if(LOG_INFO <= debug) myLog(LOG_INFO, "getNewNIO: found device %S userData=%p", nio->countersInstance, adaptor->userData);
					return &nio->new_nio;
				}
			}
		}
	}
	return NULL;
}

/**
 * Updates the cached NIO counters using PDH if the counters were updated 
 * more than a second ago.
 * Computes the delta between current and last counters, checks for
 * discontinuities (including determining whether 32 bit counters are being
 * use - eg for bytes - and have wrapped), accumulates totals, and stores
 * the latest counter values for delta computation on next invokation. 
 * If 64 bit counters are detected, indicates this by setting 
 * sp->nio->polling_seconds = 0 so that more
 * frequent polling of counters can be turned off.
 */
void updateNioCounters(HSP *sp) {
	// don't do anything if we refreshed the numbers less than a second ago
	if (sp->nio_last_update == sp->clk) {
		return;
	}
	

	sp->nio_last_update = sp->clk;
	// first read all the counters into new_nio
	if (query == NULL) {
		PDH_STATUS status = createCounterQuery();
		if (status != ERROR_SUCCESS) {
			query = NULL;
			myLog(LOG_ERR, "updateNioCounters: creating query failed: 0x%x", status);
			return;
		}
	}
	PdhCollectQueryData(query);

	PPDH_RAW_COUNTER_ITEM_W values;
	uint32_t icount = 0;
	icount = getRawCounterValues(&bytesIn, &values);

	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if (newctrs != NULL) {
				newctrs->bytes_in = values[i].RawValue.FirstValue;
				if(debug) myLog(LOG_INFO, "updateNioCounters: adaptor %lu has name <%S> bytesIn=%lu",
					i, values[i].szName, newctrs->bytes_in);
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&pktsIn, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if(newctrs != NULL) {
				newctrs->pkts_in = (uint32_t)values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&errorsIn, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if(newctrs != NULL) {
				newctrs->errs_in = (uint32_t)values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&discardsIn, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if (newctrs != NULL) {
				newctrs->drops_in = (uint32_t)values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&bytesOut, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if (newctrs != NULL) {
				newctrs->bytes_out = values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&pktsOut, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if (newctrs != NULL) {
				newctrs->pkts_out = (uint32_t)values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&errorsOut, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if (newctrs != NULL) {
				newctrs->errs_out = (uint32_t)values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	icount = getRawCounterValues(&discardsOut, &values);
	if (icount > 0) {
		for (uint32_t i = 0; i < icount; i++) {
			SFLHost_nio_counters *newctrs = getNewNIO(sp, values[i].szName);
			if (newctrs != NULL) {
				newctrs->drops_out = (uint32_t)values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
		icount = 0;
	}
	// now compute the deltas,  sanity check them, accumulate and latch
	for (uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
		SFLAdaptor *ad = sp->adaptorList->adaptors[i];
		if (ad != NULL) {
			HSPAdaptorNIO *nio = (HSPAdaptorNIO *)ad->userData;
			if (nio != NULL) {
				// have to detect discontinuities here, so use a full
				// set of latched counters and accumulators.
				BOOL accumulate = nio->last_update ? TRUE : FALSE;
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

				if (sp->nio_polling_secs == 0) {
					// 64-bit byte counters
					NIO_COMPUTE_DELTA(bytes_in);
					NIO_COMPUTE_DELTA(bytes_out);
				} else {
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
					if (nio->new_nio.bytes_in > 0xFFFFFFFF || nio->new_nio.bytes_out > 0xFFFFFFFF) {
						myLog(LOG_INFO, "detected 64-bit network counters");
						sp->nio_polling_secs = 0;
					}
				}

				if (accumulate) {
					// sanity check in case the counters were reset under out feet.
					// normally we leave this to the upstream collector, but these
					// numbers might be getting passed through from the hardware(?)
					// so we treat them with particular distrust.
					if (delta.bytes_in > maxDeltaBytes ||
						delta.bytes_out > maxDeltaBytes ||
						delta.pkts_in > HSP_MAX_NIO_DELTA32 ||
						delta.pkts_out > HSP_MAX_NIO_DELTA32) {
						myLog(LOG_INFO, "detected NIO counter discontinuity");
						accumulate = FALSE;
					}
				}

				if (accumulate) {
#define NIO_ACCUMULATE(field) nio->nio.field += delta.field
					NIO_ACCUMULATE(bytes_in);
					NIO_ACCUMULATE(pkts_in);
					NIO_ACCUMULATE(errs_in);
					NIO_ACCUMULATE(drops_in);
					NIO_ACCUMULATE(bytes_out);
					NIO_ACCUMULATE(pkts_out);
					NIO_ACCUMULATE(errs_out);
					NIO_ACCUMULATE(drops_out);
					//myLog(LOG_INFO, "accumulated NIO counters (new=%lu old=%lu delta=%lu nio->nio.bytes_in now = %lu)",
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

/**
 * Populates nio with the counters accumulated for all of the non-virtual
 * adaptors, first ensuring that the accumulated counters are current.
 * Returns TRUE if there are adaptors for which their are counters 0,
 * FALSE otherwise.
 */
BOOL readNioCounters(HSP *sp, SFLHost_nio_counters *nio) {
	// may need to schedule intermediate calls to updateNioCounters()
	// too (to avoid undetected wraps), but at the very least we need to do
	// it here to make sure the data is up to the second.
	updateNioCounters(sp);
	BOOL gotData = FALSE;
	// just add up all the counters for the non-virtual adaptors
	for (uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
		SFLAdaptor *ad = sp->adaptorList->adaptors[i];
		if (ad != NULL) {
			HSPAdaptorNIO *ctrs = (HSPAdaptorNIO *)ad->userData;
			if(ctrs) {
				if(debug) myLog(LOG_INFO, "readNioCounters: accumulating1: pkts_in=%lu (device=%s virtual=%d)",
					ctrs->nio.pkts_in,ad->deviceName,ctrs->isVirtual);
			}

			if (ctrs != NULL && !ctrs->isVirtual) {
				gotData = TRUE;
				if(debug) myLog(LOG_INFO, "readNioCounters: accumulating2: pkts_in=%lu (device=%s virtual=%d)",
					ctrs->nio.pkts_in,ad->deviceName,ctrs->isVirtual);
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
	myLog(LOG_INFO,"readNioCounters: %lu adaptors\n\trbytes:\t%llu\n\trpkts:\t%lu\n\trdrops:\t%lu\n\trerrs:\t%lu\n\ttbytes:\t%llu\n\ttpkts:\t%lu\n\ttdrops:\t%lu\n\tterrs:\t%lu\n",
		  sp->adaptorList->num_adaptors,nio->bytes_in,nio->pkts_in,nio->drops_in,nio->errs_in,nio->bytes_out,nio->pkts_out,nio->drops_out,nio->errs_out);
	return gotData;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif

