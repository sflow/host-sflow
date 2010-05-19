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
  
int readHidCounters(SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen){
    int gotData = NO;
	DWORD dwRes;
	OSVERSIONINFO osvi;
	SYSTEM_INFO si;

	ZeroMemory(hbuf,hbufLen);
	dwRes = GetComputerNameEx(ComputerNameDnsHostname,hbuf,&hbufLen);
	if(dwRes){ 
		hid->hostname.str = hbuf;
		hid->hostname.len = hbufLen;
	}
	
	hid->os_name = SFLOS_windows;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	dwRes = GetVersionEx(&osvi);
	if(dwRes){
		ZeroMemory(rbuf,rbufLen);
		sprintf(rbuf,"%d.%d.%d %s",osvi.dwMajorVersion,osvi.dwMinorVersion,osvi.dwBuildNumber,osvi.szCSDVersion);
		hid->os_release.str = rbuf;
		hid->os_release.len = strlen(rbuf);
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
	
	MyLog(LOG_INFO,"readHidCounters:\n\thostname:\t%s\n\trelease:\t%s\n\tmachine_type:\t%d\n",hid->hostname.str,hid->os_release.str,hid->machine_type);

    return YES;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

