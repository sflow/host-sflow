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
  
  int readHidCounters(SFLHost_hid_counters *hid, char *buf, int bufLen) {
    int gotData = NO;
	DWORD dwRes,len;

	if(debug){
		printf("entering readHidCounters\n");
	}
	dwRes = GetComputerNameEx(ComputerNameDnsHostname,buf,&len);
	if(!dwRes) return NO;
	gotData = YES;
	hid->hostname.str = buf;
	hid->hostname.len = len;

	hid->os_name = SFLOS_windows;
	hid->os_release.str = "";
	hid->os_release.len = 0;
	hid->machine_type = SFLMT_unknown;
	if(debug){
		printf("readHidCounters:\n\thostname:\t%s\n",hid->hostname.str);
	}
    return gotData;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

