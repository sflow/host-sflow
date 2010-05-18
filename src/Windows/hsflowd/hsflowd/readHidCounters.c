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
	DWORD dwRes,len;
	OSVERSIONINFO osvi;
	SYSTEM_INFO si;

	if(debug){
		printf("entering readHidCounters\n");
	}
	dwRes = GetComputerNameEx(ComputerNameDnsHostname,hbuf,&len);
	if(!dwRes) return NO;
	gotData = YES;
	hid->hostname.str = hbuf;
	hid->hostname.len = len;
	
	hid->os_name = SFLOS_windows;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	dwRes = GetVersionEx(&osvi);
	if(!dwRes) return gotData;
	sprintf(rbuf,"%d.%d.%d %s",osvi.dwMajorVersion,osvi.dwMinorVersion,osvi.dwBuildNumber,osvi.szCSDVersion);
	hid->os_release.str = rbuf;
	hid->os_release.len = strlen(rbuf);

	GetSystemInfo(&si);
	hid->machine_type = SFLMT_unknown;
	switch(si.dwProcessorType){
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

	strcpy(hid->uuid,"");
	
	if(debug){
		printf("readHidCounters:\n\thostname:\t%s\n\trelease:\t%s",hid->hostname.str,hid->os_release.str);
	}
    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

