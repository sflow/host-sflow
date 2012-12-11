/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"

extern int debug;

#define HSF_MAX_DRIVESTRINGS_LEN 1024

/**
 * Reads host_disk_io counters and populates SFLHost_dsk_counters struct.
 * Uses PhysicalDisk performance counter object for the disk io counters and
 * GetDiskFreeSpaceEx function ofr total and free disk space.
 */
void readDiskCounters(SFLHost_dsk_counters *dsk)
{
	PDH_HQUERY query;
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS) {
		PDH_HCOUNTER reads, readTime, readBytes, writes, writeTime, writeBytes;
		if (addCounterToQuery(DISK_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, DISK_COUNTER_READS, &query, &reads) == ERROR_SUCCESS &&
			addCounterToQuery(DISK_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, DISK_COUNTER_READ_TIME, &query, &readTime) == ERROR_SUCCESS &&
			addCounterToQuery(DISK_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, DISK_COUNTER_READ_BYTES, &query, &readBytes) == ERROR_SUCCESS &&
			addCounterToQuery(DISK_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, DISK_COUNTER_WRITES, &query, &writes) == ERROR_SUCCESS &&
			addCounterToQuery(DISK_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, DISK_COUNTER_WRITE_TIME, &query, &writeTime) == ERROR_SUCCESS &&
			addCounterToQuery(DISK_COUNTER_OBJECT, COUNTER_INSTANCE_TOTAL, DISK_COUNTER_WRITES, &query, &writeBytes) == ERROR_SUCCESS &&
			PdhCollectQueryData(query) == ERROR_SUCCESS) {
			dsk->reads = (uint32_t)getRawCounterValue(&reads);
			dsk->read_time = (uint32_t)(getRawCounterValue(&readTime)/tick_to_ms);
			dsk->bytes_read = getRawCounterValue(&readBytes);
			dsk->writes = (uint32_t)getRawCounterValue(&writes);
			dsk->write_time = (uint32_t)(getRawCounterValue(&writeTime)/tick_to_ms);
			dsk->bytes_written = getRawCounterValue(&writeBytes);
		}
		PdhCloseQuery(query);
	}
	dsk->disk_total = UNKNOWN_GAUGE_64;
	dsk->disk_free = UNKNOWN_GAUGE_64;
	dsk->part_max_used = UNKNOWN_PERCENT;

	char szBuffer[HSF_MAX_DRIVESTRINGS_LEN];
	uint32_t i=0, len;
	uint64_t i64FreeBytesToCaller, i64TotalBytes=0, i64FreeBytes=0;
	uint32_t tmp_part_used = 0;
	len = GetLogicalDriveStrings(1024, szBuffer);
	if (len == 0) {
		myLog(LOG_ERR, "readDiskCounters: GetLogicalDriveStrings() failed: %d", GetLastError());
	} else if (len > HSF_MAX_DRIVESTRINGS_LEN) {
		myLog(LOG_ERR, "readDiskCounters: GetLogicalDriveStrings() needs more buffer space (%u bytes)", len);
	} else {
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
	myLog(LOG_INFO,
		"readDiskCounters:\n\tdisk_total: \t%I64u\n\tdisk_free: \t%I64u\n\tpart_max_used: \t%.2f%%\n"
		"\treads:\t\t%lu\n\tread_time:\t%lu\n\tbytes_read:\t%lu\n"
		"\twrites:\t\t%lu\n\twrite_time:\t%lu\n\tbytes_written:\t%lu\n",
		  dsk->disk_total,dsk->disk_free,(dsk->part_max_used / 100.0),
		  dsk->reads,dsk->read_time,dsk->bytes_read,
		  dsk->writes,dsk->write_time,dsk->bytes_written);
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
