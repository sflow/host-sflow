/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#include <search.h> // for tfind,tsearch,tsdestroy
#include <sys/statvfs.h> // for statvfs

/* It looks like we could read this from "fdisk -l",  so the source
   code to fdisk should probably be consulted to find where it can
   be read off */
#define ASSUMED_DISK_SECTOR_BYTES 512

  extern int debug;

  /*_________________---------------------------__________________
    _________________     remote_mount          __________________
    -----------------___________________________------------------
    from Ganglia/linux/metrics.c
  */

int remote_mount(const char *device, const char *type)
{
  return ((strchr(device,':') != 0)
	  || (!strcmp(type, "smbfs") && device[0]=='/' && device[1]=='/')
	  || (!strncmp(type, "nfs", 3)) || (!strcmp(type, "autofs"))
	  || (!strcmp(type,"gfs")) || (!strcmp(type,"none")) );
}


  /*_________________---------------------------__________________
    _________________     readDiskCounters      __________________
    -----------------___________________________------------------
  */
  
  int readDiskCounters(HSP *sp, SFLHost_dsk_counters *dsk) {
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

      // handle 64-bit counters specially
      uint64_t total_sectors_read = 0;
      uint64_t total_sectors_written = 0;

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
	  // report the sum over all disks - except software RAID devices and logical volumes
	  // because that would cause double-counting.   We identify those by their
	  // major numbers:
	  // Software RAID = 9
	  // Logical Vol = 253
	  if(majorNo != 9 && majorNo != 253) {
	    dsk->reads += reads;
	    total_sectors_read += sectors_read;
	    dsk->read_time += read_time_ms;
	    dsk->writes += writes;
	    total_sectors_written += sectors_written;
	    dsk->write_time += write_time_ms;
	  }
	}
      }
      fclose(procFile);
      
      // accumulate the 64-bit counters (they may only be 32-bit counters in this OS)
      sp->diskIO.bytes_read += (total_sectors_read - sp->diskIO.last_sectors_read) * ASSUMED_DISK_SECTOR_BYTES;
      sp->diskIO.last_sectors_read = total_sectors_read;
      sp->diskIO.bytes_written += (total_sectors_written - sp->diskIO.last_sectors_written) * ASSUMED_DISK_SECTOR_BYTES;
      sp->diskIO.last_sectors_written = total_sectors_written;
      // and copy the accumulated total into the output
      dsk->bytes_read = sp->diskIO.bytes_read;
      dsk->bytes_written = sp->diskIO.bytes_written;
    }

    // borrowed heavily from ganglia/linux/metrics.c for this part where
    // we read the mount points and then interrogate them to add up the
    // disk space on local disks.
    procFile = fopen("/proc/mounts", "r");
    if(procFile) {
#undef MAX_PROC_LINE_CHARS
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      char device[MAX_PROC_LINE_CHARS];
      char mount[MAX_PROC_LINE_CHARS];
      char type[MAX_PROC_LINE_CHARS];
      char mode[MAX_PROC_LINE_CHARS];
      void *treeRoot = NULL;
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	if(sscanf(line, "%s %s %s %s", device, mount, type, mode) == 4) {
	  // must start with /dev/ or /dev2/
	  if(strncmp(device, "/dev/", 5) == 0 ||
	     strncmp(device, "/dev2/", 6) == 0) {
	    // must be read-write
	    if(strncmp(mode, "ro", 2) != 0) {
	      // must be local
	      if(!remote_mount(device, type)) {
		// don't count it again if it was seen before
		if(tfind(device, &treeRoot, (comparison_fn_t)strcmp) == NULL) {
		  // not found, so remember it
		  tsearch(my_strdup(device), &treeRoot, (comparison_fn_t)strcmp);
		  // and get the numbers
		  struct statvfs svfs;
		  if(statvfs(mount, &svfs) == 0) {
		    if(svfs.f_blocks) {
		      uint64_t dtot64 = (uint64_t)svfs.f_blocks * (uint64_t)svfs.f_bsize;
		      uint64_t dfree64 = (uint64_t)svfs.f_bavail * (uint64_t)svfs.f_bsize;
		      dsk->disk_total += dtot64;
		      dsk->disk_free += dfree64;
		      // percent used (as % * 100)
		      uint32_t pc = (uint32_t)(((dtot64 - dfree64) * 10000) / dtot64);
		      if(pc > dsk->part_max_used) dsk->part_max_used = pc;
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
      tdestroy(treeRoot, my_free);
      fclose(procFile);
    }
    
    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

