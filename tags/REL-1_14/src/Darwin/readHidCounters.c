/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <sys/sysctl.h>
#include <mach/mach.h>

  /*_________________---------------------------__________________
    _________________     readHidCounters       __________________
    -----------------___________________________------------------
  */
  
  int readHidCounters(HSP *sp, SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen) {
    int gotData = NO;
    size_t len = hbufLen;
    if(sysctlbyname("kern.hostname", hbuf, &len, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(<kern.hostname>) failed : %s", strerror(errno));
    }
    else {
      gotData = YES;
      hid->hostname.str = hbuf;
      hid->hostname.len = strlen(hbuf);
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
    hid->os_name = SFLOS_darwin;

    // os release
    len = rbufLen;
    if(sysctlbyname("kern.osrelease", rbuf, &len, NULL, 0) != 0) {
      myLog(LOG_ERR, "sysctl(<kern.osrelease>) failed : %s", strerror(errno));
    }
    else {
      gotData = YES;
      hid->os_release.str = rbuf;
      hid->os_release.len = strlen(rbuf);
    }
    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

