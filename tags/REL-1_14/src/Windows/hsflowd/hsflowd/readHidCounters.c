/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

extern int debug;
  /*_________________---------------------------__________________
    _________________     readHidCounters       __________________
    -----------------___________________________------------------
  */
 

int readHidCounters(HSP *sp, SFLHost_hid_counters *hid){
	DWORD dwRes;
	OSVERSIONINFO osvi;
	SYSTEM_INFO si;
#define MAX_FDQN_CHARS 255
	char dnsBuf[MAX_FDQN_CHARS+1];
	DWORD dnsLen = MAX_FDQN_CHARS;

	if(GetComputerNameEx(ComputerNameDnsHostname,dnsBuf,&dnsLen)) {
		uint32_t copyLen = dnsLen < SFL_MAX_HOSTNAME_CHARS ? dnsLen :  SFL_MAX_HOSTNAME_CHARS;
		memcpy(hid->hostname.str, dnsBuf, copyLen);
		hid->hostname.str[copyLen] = '\0';
		hid->hostname.len = copyLen;
	}

	hid->os_name = SFLOS_windows;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	dwRes = GetVersionEx(&osvi);
	if(dwRes){
      sprintf_s(hid->os_release.str,SFL_MAX_OSRELEASE_CHARS,"%d.%d.%d %s",
			osvi.dwMajorVersion,
			osvi.dwMinorVersion,
			osvi.dwBuildNumber,
			osvi.szCSDVersion);
		hid->os_release.len = my_strlen(hid->os_release.str);
	}

	GetNativeSystemInfo(&si);
	hid->machine_type = SFLMT_unknown;
	switch(si.wProcessorArchitecture){
		case PROCESSOR_ARCHITECTURE_AMD64:
			hid->machine_type = SFLMT_x86_64;
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			hid->machine_type = SFLMT_ia64;
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			hid->machine_type = SFLMT_x86;
			break;
	}

	dwRes = readSystemUUID(hid->uuid);

	myLog(LOG_INFO,"readHidCounters:\n\thostname:\t%s\n\trelease:\t%s\n\tmachine_type:\t%d\n",hid->hostname.str,hid->os_release.str,hid->machine_type);

    return YES;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

