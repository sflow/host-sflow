/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  /*_________________---------------------------__________________
    _________________     readHidCounters       __________________
    -----------------___________________________------------------
  */
  
  int readHidCounters(SFLHost_hid_counters *hid, char *buf, int bufLen) {
    int gotData = NO;
    FILE *procFile;
    procFile= fopen("/proc/sys/kernel/hostname", "r");
    if(procFile) {
      if(fgets(buf, bufLen, procFile)) {
	gotData = YES;
	int len = strlen(buf);
	// fgets may include a newline
	if(buf[len-1] == '\n') --len;
	hid->hostname.str = buf;
	hid->hostname.len = len;
      }
      fclose(procFile);
    }

    // UUID $$$

    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

