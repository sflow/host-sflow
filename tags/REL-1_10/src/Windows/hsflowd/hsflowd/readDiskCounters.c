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
    
	dsk->reads = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\Disk Reads/sec");
	dsk->read_time = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\% Disk Read Time");
	dsk->bytes_read = readSingleCounter("\\PhysicalDisk(_Total)\\Disk Read Bytes/sec");

	dsk->writes = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\Disk Writes/sec");
	dsk->write_time = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\% Disk Write Time");
	dsk->bytes_written = readSingleCounter("\\PhysicalDisk(_Total)\\Disk Write Bytes/sec");

	//TODO:
	//part_max_used
	//disk_free
	//disk_total

	MyLog(LOG_INFO,"readDiskCounters:\n\treads:\t%lu\n\tread_time:\t%lu\n\tbytes_read:\t%lu\n\twrites:\t%lu\n\twrite_time:\t%lu\n\tbytes_written:\t%ul\n",
			dsk->reads,dsk->read_time,dsk->bytes_read,dsk->writes,dsk->write_time,dsk->bytes_written);

	gotData = YES;

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
