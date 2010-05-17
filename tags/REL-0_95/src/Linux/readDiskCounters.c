/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

/* It looks like we could read this from "fdisk -l",  so the source
   code to fdisk should probably be consulted to find where it can
   be read off */
#define ASSUMED_DISK_SECTOR_BYTES 512

  /*_________________---------------------------__________________
    _________________     readDiskCounters      __________________
    -----------------___________________________------------------
  */
  
  int readDiskCounters(SFLHost_dsk_counters *dsk) {
    int gotData = NO;
    FILE *procFile;
    procFile= fopen("/proc/diskstats", "r");
    if(procFile) {
      // ASCII numbers in /proc/diskstats may be 64-bit (if not now
      // then someday), so it seems safer to read into
      // 64-bit ints with scanf first,  then copy them
      // into the host_dsk structure from there.
      uint32_t majorNo;
      uint32_t minorNo;
      
      uint64_t reads = 0;
      /* uint64_t reads_merged = 0;*/
      uint64_t sectors_read = 0;
      uint64_t read_time_ms = 0;
      uint64_t writes = 0;
      /* uint64_t writes_merged = 0;*/
      uint64_t sectors_written = 0;
      uint64_t write_time_ms = 0;
      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      char devName[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	if(sscanf(line, "%"SCNu32" %"SCNu32" %s %"SCNu64" %*u %"SCNu64" %"SCNu64" %"SCNu64" %*u %"SCNu64" %"SCNu64"",
		  &majorNo,
		  &minorNo,
		  devName,
		  &reads,
		  /*&reads_merged,*/
		  &sectors_read,
		  &read_time_ms,
		  &writes,
		  /*&writes_merged,*/
		  &sectors_written,
		  &write_time_ms) == 9) {
	  gotData = YES;
	  // report the sum over all disks
	  dsk->reads += reads;
	  dsk->bytes_read += (sectors_read * ASSUMED_DISK_SECTOR_BYTES);
	  dsk->read_time += read_time_ms;
	  dsk->writes += writes;
	  dsk->bytes_written += (sectors_written * ASSUMED_DISK_SECTOR_BYTES);
	  dsk->write_time += write_time_ms;
	}
      }
      fclose(procFile);
    }

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

