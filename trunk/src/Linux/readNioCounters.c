/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  /*_________________---------------------------__________________
    _________________    updateNioCounters      __________________
    -----------------___________________________------------------
  */
  
  static HSPAdaptorNIO *getAdaptorNIO(HSPAdaptorNIOList *nioList, char *deviceName) {
    for(int i = 0; i < nioList->num_adaptors; i++) {
      HSPAdaptorNIO *adaptor = nioList->adaptors[i];
      if(!strcmp(adaptor->deviceName, deviceName)) return adaptor;
    }
    return NULL;
  }
  
  void updateNioCounters(HSP *sp) {

    // don't do anything if we already refreshed the numbers less than a second ago
    if(sp->adaptorNIOList.last_update == sp->clk) {
      return;
    }
    sp->adaptorNIOList.last_update = sp->clk;

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
	char deviceName[MAX_PROC_LINE_CHARS];
	  // assume the format is:
	  // Inter-|   Receive                                                |  Transmit
	  //  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	  if(sscanf(line, "%[^:]:%"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %*u %*u %*u %*u %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64"",
		    deviceName,
		    &bytes_in,
		    &pkts_in,
		    &errs_in,
		    &drops_in,
		    &bytes_out,
		    &pkts_out,
		    &errs_out,
		    &drops_out) == 9) {
	    HSPAdaptorNIO *adaptor = getAdaptorNIO(&sp->adaptorNIOList, trimWhitespace(deviceName));
	    if(adaptor) {
	      // accumulate 64-bit counters specially, in case the OS is using only 32-bits
	      adaptor->nio.bytes_in += (bytes_in - adaptor->last_bytes_in);
	      adaptor->last_bytes_in = bytes_in;
	      adaptor->nio.bytes_out += (bytes_out - adaptor->last_bytes_out);
	      adaptor->last_bytes_out = bytes_out;

	      // but if we detect that the OS is using 64-bits then we can turn off the faster
	      // NIO polling. This should probaly be done based on the kernel version or some
	      // other include-file definition, but it's not expensive to do it here like this:
	      if(bytes_in > 0xFFFFFFFF ||
		 bytes_out > 0xFFFFFFFF) {
		sp->adaptorNIOList.polling_secs = HSP_NIO_POLLING_SECS_64BIT;
	      }
		
	      // the rest are 32-bit in the output
	      adaptor->nio.pkts_in = (uint32_t)pkts_in;
	      adaptor->nio.errs_in = (uint32_t)errs_in;
	      adaptor->nio.drops_in = (uint32_t)drops_in;
	      adaptor->nio.pkts_out = (uint32_t)pkts_out;
	      adaptor->nio.errs_out = (uint32_t)errs_out;
	      adaptor->nio.drops_out = (uint32_t)drops_out;
	  }
	}
      }
      fclose(procFile);
    }
  }


  /*_________________---------------------------__________________
    _________________      readNioCounters      __________________
    -----------------___________________________------------------
  */
  
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter) {
    int interface_count = 0;
    size_t devFilterLen = devFilter ? strlen(devFilter) : 0;

    // may need to schedule intermediate calls to updateNioCounters()
    // too (to avoid undetected wraps), but at the very least we need to do
    // it here to make sure the data is up to the second.
    updateNioCounters(sp);

    for(int i = 0; i < sp->adaptorNIOList.num_adaptors; i++) {
      HSPAdaptorNIO *adaptor = sp->adaptorNIOList.adaptors[i];
      if(devFilter == NULL || !strncmp(devFilter, adaptor->deviceName, devFilterLen)) {
	interface_count++;
	// report the sum over all devices that match the filter
	nio->bytes_in += adaptor->nio.bytes_in;
	nio->pkts_in += adaptor->nio.pkts_in;
	nio->errs_in += adaptor->nio.errs_in;
	nio->drops_in += adaptor->nio.drops_in;
	nio->bytes_out += adaptor->nio.bytes_out;
	nio->pkts_out += adaptor->nio.pkts_out;
	nio->errs_out += adaptor->nio.errs_out;
	nio->drops_out += adaptor->nio.drops_out;
      }
    }
    return interface_count;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

