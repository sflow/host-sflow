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
  
  int readHidCounters(HSP *sp, SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen) {
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

    // UUID
    memcpy(hid->uuid, sp->uuid, 16);

    // machine_type
    hid->machine_type = SFLMT_unknown;
#ifdef __i386__
    hid->machine_type = SFLMT_x86;
#endif
#ifdef __x86_64__
    hid->machine_type = SFLMT_x86_64;
#endif
#ifdef __ia64__
    hid->machine_type = SFLMT_ia64;
#endif
#ifdef __sparc__
    hid->machine_type = SFLMT_sparc;
#endif
#ifdef __alpha__
    hid->machine_type = SFLMT_alpha;
#endif
#ifdef __powerpc__
    hid->machine_type = SFLMT_powerpc;
#endif
#ifdef __m68k__
    hid->machine_type = SFLMT_68k;
#endif
#ifdef __mips__
    hid->machine_type = SFLMT_mips;
#endif
#ifdef __arm__
    hid->machine_type = SFLMT_arm;
#endif
#ifdef __hppa__
    hid->machine_type = SFLMT_hppa;
#endif
#ifdef __s390__
    hid->machine_type = SFLMT_s390;
#endif

    // os name
    hid->os_name = SFLOS_linux;

    // os release
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

