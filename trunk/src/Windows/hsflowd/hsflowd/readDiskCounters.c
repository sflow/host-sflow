/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsCounters.h"

extern int debug;

  /*_________________---------------------------__________________
    _________________     readDiskCounters      __________________
    -----------------___________________________------------------
  */
  
  int readDiskCounters(SFLHost_dsk_counters *dsk) {
    int gotData = NO;
    
	dsk->reads = readSingleCounter("\\PhysicalDisk(_Total)\\Disk Reads/sec");
	dsk->read_time = readSingleCounter("\\PhysicalDisk(_Total)\\% Disk Read Time");
	//dsk->reads_merged += 0;
	//dsk->sectors_read += 0;

	dsk->writes = readSingleCounter("\\PhysicalDisk(_Total)\\Disk Writes/sec");
	dsk->write_time = readSingleCounter("\\PhysicalDisk(_Total)\\% Disk Write Time");
	//dsk->writes_merged += 0;
	//dsk->sectors_written += 0;
	
	//TODO:
	//part_max_used
	//disk_free
	//disk_total

	if(debug){
		printf("readDiskCounters:\n\treads:\t%lu\n\tread_time:\t%lu\n\twrites:\t%lu\n\twrite_time:\t%lu\n",
			dsk->reads,dsk->read_time,dsk->writes,dsk->write_time);
	}

	gotData = YES;

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
