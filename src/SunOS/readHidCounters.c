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
		if (fgets(tmpbuf, tmpbufLen, releaseFile)) {
			gotData = YES;
			int len = strlen(tmpbuf);
			if (tmpbuf[len - 1] == '\n')
				--len;

			if (len > rbufLen) 
				// We take the last rbufLen characters of the 1st line
				// in /etc/release because it is more likely to give
				// us a meaningful part of the release number.
				strncpy(rbuf, tmpbuf + (len - rbufLen), rbufLen);
			else
				strncpy(rbuf, tmpbuf, rbufLen);

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

