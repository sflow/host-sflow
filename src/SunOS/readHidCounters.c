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

    // hostname
    if (!gethostname(hbuf, hbufLen)) {
      gotData = YES;
      int len = strlen(hbuf);
      hid->hostname.str = hbuf;
      hid->hostname.len = len;
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
    hid->os_name = SFLOS_solaris;

    // os release
    FILE *releaseFile;
    releaseFile = fopen("/etc/release", "r");
    if (releaseFile) {
      int tmpbufLen = rbufLen * 4;
      char tmpbuf[tmpbufLen];
      char *tmpptr = tmpbuf;
      if (fgets(tmpbuf, tmpbufLen, releaseFile)) {
	gotData = YES;
	while(isspace(*tmpptr))
	  tmpptr++;

	int len;
	char *str;

	// remove the (redundant) "Solaris " prefix -- helps
	// to squeeze the field into the 32 char limit specified
	// in the sFlow standard.
	str = strstr(tmpptr, "Solaris");
	if (NULL != str && strlen(str) >= 8) {
	  str = str + 8;		
	  len = strlen(str);
	  if (str[len - 1] == '\n')
	    --len;
	  strncpy(rbuf, str, rbufLen);
	} else {
	  len = strlen(tmpptr);
	  if (tmpptr[len - 1] == '\n')
	    --len;
	  strncpy(rbuf, tmpptr, rbufLen);
	}

	hid->os_release.str = rbuf;
	hid->os_release.len = len;
      }
    }
    fclose(releaseFile);
    
    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

