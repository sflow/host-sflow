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
#define HSF_MAX_DRIVESTRINGS_LEN 1024
	char szBuffer[HSF_MAX_DRIVESTRINGS_LEN];
	uint32_t i=0,len;
	uint64_t i64FreeBytesToCaller, i64TotalBytes=0, i64FreeBytes=0;
	uint32_t tmp_part_used = 0;
    
	dsk->reads = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\Disk Reads/sec");
	dsk->read_time = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\% Disk Read Time");
	dsk->bytes_read = readSingleCounter("\\PhysicalDisk(_Total)\\Disk Read Bytes/sec");

	dsk->writes = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\Disk Writes/sec");
	dsk->write_time = (uint32_t)readSingleCounter("\\PhysicalDisk(_Total)\\% Disk Write Time");
	dsk->bytes_written = readSingleCounter("\\PhysicalDisk(_Total)\\Disk Write Bytes/sec");

	dsk->disk_total = UNKNOWN_GAUGE_64;
	dsk->disk_free = UNKNOWN_GAUGE_64;
	dsk->part_max_used = UNKNOWN_PERCENT;

	len = GetLogicalDriveStrings(1024, szBuffer);
	if(len == 0) {
		if(debug) myLog(LOG_ERR, "GetLogicalDriveStrings() failed: %d", GetLastError());
	}
	else if(len > HSF_MAX_DRIVESTRINGS_LEN) {
		if(debug) myLog(LOG_ERR, "GetLogicalDriveStrings() needs more buffer space (%u bytes)", len);
	}
	else {
		dsk->disk_total = 0;
		dsk->disk_free = 0;
		dsk->part_max_used = 0;

		while (i < len) {
			if (GetDriveType(szBuffer + i) == DRIVE_FIXED) {
							      
				GetDiskFreeSpaceEx (szBuffer + i,
					(PULARGE_INTEGER)&i64FreeBytesToCaller,
					(PULARGE_INTEGER)&i64TotalBytes,
					(PULARGE_INTEGER)&i64FreeBytes);

				dsk->disk_total += i64TotalBytes;
				dsk->disk_free += i64FreeBytes;

				tmp_part_used = (uint32_t)(((i64TotalBytes - i64FreeBytes) * 10000) / i64TotalBytes);
				if (tmp_part_used > dsk->part_max_used) 
					dsk->part_max_used = tmp_part_used;
			}
			i += lstrlen(szBuffer + i) + 1;
		}
	}
	myLog(LOG_INFO,"readDiskCounters:\n\tdisk_total: %I64u\n\tdisk_free: %I64u\n\tpart_max_used: %.2f%%\n\treads:\t%lu\n\tread_time:\t%lu\n\tbytes_read:\t%lu\n\twrites:\t%lu\n\twrite_time:\t%lu\n\tbytes_written:\t%ul\n",
	 dsk->disk_total,dsk->disk_free,(dsk->part_max_used / 100.0),dsk->reads,dsk->read_time,dsk->bytes_read,dsk->writes,dsk->write_time,dsk->bytes_written);

	gotData = YES;

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
