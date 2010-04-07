/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(SFLHost_nio_counters *nio) {
    int gotData = NO;
    FILE *procFile;
    procFile= fopen("/proc/net/dev", "r");
    if(procFile) {
      // ASCII numbers in /proc/diskstats may be 64-bit (if not now
      // then someday), so it seems safer to read into
      // 64-bit ints with scanf first,  then copy them
      // into the host_nio structure from there.
      uint64_t bytes_in = 0;
      uint64_t pkts_in = 0;
      uint64_t errs_in = 0;
      uint64_t drops_in = 0;
      uint64_t bytes_out = 0;
      uint64_t pkts_out = 0;
      uint64_t errs_out = 0;
      uint64_t drops_out = 0;
      // limit the number of chars we will read from each line
      // (there can be more than this - fgets will chop for us)
#define MAX_PROC_LINE_CHARS 240
      char line[MAX_PROC_LINE_CHARS];
      while(fgets(line, MAX_PROC_LINE_CHARS, procFile)) {
	// assume the format is:
	// Inter-|   Receive                                                |  Transmit
	//  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	if(sscanf(line, "%*s %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %*u %*u %*u %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64"",
		  &bytes_in,
		  &pkts_in,
		  &errs_in,
		  &drops_in,
		  &bytes_out,
		  &pkts_out,
		  &errs_out,
		  &drops_out) == 8) {
	  gotData = YES;
	  // report the sum over all devices
	  nio->bytes_in += bytes_in;
	  nio->pkts_in += (uint32_t)pkts_in;
	  nio->errs_in += (uint32_t)errs_in;
	  nio->drops_in += (uint32_t)drops_in;
	  nio->bytes_out += bytes_out;
	  nio->pkts_out += (uint32_t)pkts_out;
	  nio->errs_out += (uint32_t)errs_out;
	  nio->drops_out += (uint32_t)drops_out;
	}
      }
      fclose(procFile);
    }

    return gotData;
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif

