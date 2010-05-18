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
	if(debug){
		printf("entering readNioCounters\n");
	}
	icount = readMultiCounter("\\Network Interface(*)\\Bytes Received/sec",&value);
	for(i = 0; i < icount; i++){
		nio->bytes_in += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Received/sec",&value);
	for(i = 0; i < icount; i++){
		nio->pkts_in += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Received Errors",&value);
	for(i = 0; i < icount; i++){
		nio->errs_in += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Received Discarded",&value);
	for(i = 0; i < icount; i++){
		nio->drops_in += (uint32_t)value[i].RawValue.FirstValue;
	}

	icount = readMultiCounter("\\Network Interface(*)\\Bytes Sent/sec",&value);
	for(i = 0; i < icount; i++){
		nio->bytes_out += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Sent/sec",&value);
	for(i = 0; i < icount; i++){
		nio->pkts_out += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Outbound Errors",&value);
	for(i = 0; i < icount; i++){
		nio->errs_out += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	icount = readMultiCounter("\\Network Interface(*)\\Packets Outbound Discarded",&value);
	for(i = 0; i < icount; i++){
		nio->drops_out += (uint32_t)value[i].RawValue.FirstValue;
	}
	if(value){
		free(value);
	}

	//if(debug){
	//	printf("readNioCounters:\n\trbytes:\t%lu\n\trdrops:\t%lu\n\trerrs:\t%lu\n\trpkts:\t%lu\n\ttbytes:\t%lu\n\ttdrops:\t%lu\n\tterrs:\t%lu\n\ttpkts:\t%lu\n",
	//		nio->rbytes,nio->rdrops,nio->rerrs,nio->rpkts,nio->tbytes,nio->tdrops,nio->terrs,nio->tpkts);
	//}
	gotData = YES;
    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

