/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;
  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(SFLHost_nio_counters *nio) {
    int gotData = NO;
	PPDH_RAW_COUNTER_ITEM value;
	uint32_t i, icount;
	
	icount = readMultiCounter("\\Network Interface(*)\\Bytes Received/sec",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->bytes_in += value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Received/sec",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->pkts_in += (uint32_t)value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Received Errors",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->errs_in += (uint32_t)value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Received Discarded",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->drops_in += (uint32_t)value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Bytes Sent/sec",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->bytes_out += value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Sent/sec",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->pkts_out += (uint32_t)value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Outbound Errors",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->errs_out += (uint32_t)value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Outbound Discarded",&value);
	if(value) {
		for(i = 0; i < icount; i++){
			nio->drops_out += (uint32_t)value[i].RawValue.FirstValue;
		}
		my_free(value);
		value = NULL;
	}

	myLog(LOG_INFO,"readNioCounters:\n\trbytes:\t%lu\n\trdrops:\t%lu\n\trerrs:\t%lu\n\trpkts:\t%lu\n\ttbytes:\t%lu\n\ttdrops:\t%lu\n\tterrs:\t%lu\n\ttpkts:\t%lu\n",
			nio->bytes_in,nio->drops_in,nio->errs_in,nio->pkts_in,nio->bytes_out,nio->drops_out,nio->errs_out,nio->pkts_out);

	gotData = YES;
    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

