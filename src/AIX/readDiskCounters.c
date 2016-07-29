/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <libperfstat.h>

  extern int debug;

  /*_________________---------------------------__________________
    _________________     readDiskCounters      __________________
    -----------------___________________________------------------
  */


  
  int readDiskCounters(HSP *sp, SFLHost_dsk_counters *dsk) {
    int gotData = NO;
    perfstat_disk_total_t disk_total;

    if(perfstat_disk_total(NULL, &disk_total, sizeof(disk_total), 1) != -1) {
      gotData = YES;
      dsk->reads = disk_total.xrate; // read-transfers
      dsk->writes = disk_total.xfers - disk_total.xrate;
      dsk->read_time = disk_total.rserv; // in mS ?
      dsk->write_time = disk_total.wserv; // in mS ?
      dsk->bytes_read = disk_total.rblks * 512;
      dsk->bytes_written = disk_total.wblks * 512;

      dsk->disk_total = disk_total.size;
      dsk->disk_total *= (1024 * 1024); // convert MB to bytes

      dsk->disk_free = disk_total.free;
      dsk->disk_free *= (1024 * 1024); // convert MB to bytes
      
      dsk->part_max_used = 0; // would have to iterate over all disks to get this
    }
    
    return gotData;
  }



#if defined(__cplusplus)
} /* extern "C" */
#endif

