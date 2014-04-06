/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <kstat.h>
#include <search.h> // for tfind,tsearch,tdestroy
#include <sys/statvfs.h> // for statvfs
#include <sys/mnttab.h>

#define ASSUMED_DISK_SECTOR_BYTES 512

  extern int debug;

  /*_________________---------------------------__________________
    _________________     readDiskCounters      __________________
    -----------------___________________________------------------
  */

  /* 
     #ifndef __MY_COMPAR_FN_T
     #define __MY_COMPAR_FN_T
     typedef int (*__my_compar_fn_t) (__const void*, __const void*);
     typedef __my_compar_fn_t my_comparison_fn_t;
     #endif
  */ 

  int readDiskCounters(HSP *sp, SFLHost_dsk_counters *dsk) {
    int gotData = NO;

    kstat_ctl_t *kc;
    kstat_t *ksp;
    kstat_io_t kio;

    FILE *mounts;
    struct mnttab mp;
    char *mount, *device, *type;
    struct statvfs buf;

    u_long blocksize;
    fsblkcnt_t free, size;

    uint64_t total_size, total_free;
    uint64_t bytes_size, bytes_free;
    uint32_t pc, tmppc;

    uint32_t reads, writes;
    uint64_t bytes_read, bytes_written;

    kc = kstat_open();
    if (NULL == kc) {
      myLog(LOG_ERR, "readDiskCounters kstat_open() failed");
    }

    mounts = fopen("/etc/mnttab", "r");
    if (mounts) {

      total_size = 0;
      total_free = 0;
      pc = 0;
      //void *treeRoot = NULL;
      while (0 == getmntent(mounts, &mp)) {
	mount = mp.mnt_mountp;
	device = mp.mnt_special;
	type = mp.mnt_fstype;
			
	// See Ganglia libmetrics/metrics.c::valid_mount_type()
	if (!strncmp(type, "ufs", 3) && !strncmp(type, "vxfs", 4))
	  continue;
	// don't count it again if it was seen before
	//if (NULL != tfind(device, &treeRoot, (my_comparison_fn_t)strcmp))
	//	continue;
	//else
	//	// not found, so remember it
	//	tsearch(my_strdup(device), &treeRoot, (my_comparison_fn_t)strcmp);
	
	gotData = YES;

	statvfs(mount, &buf);
	size = buf.f_blocks;
	free = buf.f_bavail;
	blocksize = buf.f_frsize;

	bytes_size = (uint64_t)size * (uint64_t)blocksize;
	bytes_free = (uint64_t)free * (uint64_t)blocksize;
	total_size += bytes_size;
	total_free += bytes_free;

	if (size > 0) {
	  tmppc = (uint32_t)((((uint64_t)size - (uint64_t)free) * 10000) / ((double)size));
	  if (tmppc > pc)
	    pc = tmppc;
	}
      }
      //tdestroy(treeRoot, my_free);

      // disk_total
      dsk->disk_total += total_size;

      // disk_free
      dsk->disk_free += total_free;
		
      // part_max_used
      dsk->part_max_used = pc;

      reads = 0;
      writes = 0;
      bytes_read = 0;
      bytes_written = 0;

      if (NULL != kc) {
	for (ksp = kc->kc_chain; NULL != ksp; ksp = ksp->ks_next) {
	  if (KSTAT_TYPE_IO == ksp->ks_type && !(strncmp(ksp->ks_class, "disk", 4))) {
	    gotData = YES;
	    kstat_read(kc, ksp, &kio);
	    reads += kio.reads;
	    writes += kio.writes;
	    bytes_read += kio.nread;
	    bytes_written += kio.nwritten;
	  }
	}

	// reads
	dsk->reads = reads;

	// read_time
	// TODO: rtime of kstat disk class is "run time", not "read time".  Determine where
	// to get read time from.

	SFL_UNDEF_COUNTER(dsk->read_time);

	// writes
	dsk->writes = writes;
			
	// write_time
	// TODO: wtime of kstat disk class is "wait time", not "write time".  Determine where
	// to get write time from.
	SFL_UNDEF_COUNTER(dsk->write_time);
      }

      // accumulate the 64-bit counters
      uint64_t total_sectors_read = (uint64_t) bytes_read / ((float)ASSUMED_DISK_SECTOR_BYTES);
      uint64_t total_sectors_written = (uint64_t)(bytes_written / ((float)ASSUMED_DISK_SECTOR_BYTES));

      sp->diskIO.bytes_read += bytes_read;
      sp->diskIO.last_sectors_read = (total_sectors_read - sp->diskIO.last_sectors_read);
      sp->diskIO.bytes_written += bytes_written;
      sp->diskIO.last_sectors_written = (total_sectors_written - sp->diskIO.last_sectors_written);
	
      // bytes_read
      dsk->bytes_read = sp->diskIO.bytes_read;
      // bytes_written
      dsk->bytes_written = sp->diskIO.bytes_written;

      fclose(mounts);
    }	

    kstat_close(kc);
    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
