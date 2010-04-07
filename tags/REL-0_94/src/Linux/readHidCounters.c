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
  
  int readHidCounters(SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen) {
    int gotData = NO;
    FILE *procFile;
    procFile= fopen("/proc/sys/kernel/hostname", "r");
    if(procFile) {
      if(fgets(hbuf, hbufLen, procFile)) {
	gotData = YES;
	int len = strlen(hbuf);
	// fgets may include a newline
	if(hbuf[len-1] == '\n') --len;
	hid->hostname.str = hbuf;
	hid->hostname.len = len;
      }
      fclose(procFile);
    }

    // UUID $$$
    // machine_type $$$

    hid->os_name = SFLOS_linux;

    procFile= fopen("/proc/sys/kernel/osrelease", "r");
    if(procFile) {
      if(fgets(rbuf, rbufLen, procFile)) {
	gotData = YES;
	int len = strlen(rbuf);
	// fgets may include a newline
	if(rbuf[len-1] == '\n') --len;
	hid->os_release.str = rbuf;
	hid->os_release.len = len;
      }
      fclose(procFile);
    }
    
    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

