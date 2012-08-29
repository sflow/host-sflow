/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

	/*________________---------------------------__________________
	  ________________      cleanNameForWMI      __________________
	  ----------------___________________________------------------
	*/

	void cleanNameForWMI(char *aname) {
		// fix the adaptor name for WMI counter-name compatibility
		// TODO: Find list of reserved chars for WMI.
		for(int i = my_strlen(aname); --i >= 0; ) {
			switch(aname[i]) {
			case '/': aname[i] = '_'; break;
			case '\\': aname[i] = '_'; break;
			case '(': aname[i] = '['; break;
			case ')': aname[i] = ']'; break;
			case '#': aname[i] = '_'; break;
			// case '*': aname[i] = '_'; break;  // this one does *not* get changed for interface names!
			default: break;
			}
		}
	}

	/*________________---------------------------__________________
 	  ________________      readInterfaces       __________________
	  ----------------___________________________------------------
	*/

	int readInterfaces(HSP *sp)
	{
		PIP_ADAPTER_INFO pAdapterInfo;
		PIP_ADAPTER_INFO pAdapter = NULL;
		DWORD dwRetVal = 0;
		ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

		if(sp->adaptorList == NULL) sp->adaptorList = adaptorListNew();
		else adaptorListMarkAll(sp->adaptorList);

		pAdapterInfo = (IP_ADAPTER_INFO *) my_calloc(sizeof (IP_ADAPTER_INFO));
		if (pAdapterInfo == NULL) {
			myLog(LOG_ERR,"Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
		if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
			my_free(pAdapterInfo);
			pAdapterInfo = (IP_ADAPTER_INFO *) my_calloc(ulOutBufLen);
			if (pAdapterInfo == NULL) {
				myLog(LOG_ERR,"Error allocating memory needed to call GetAdaptersinfo\n");
				return 1;
			}
		}
		if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
			pAdapter = pAdapterInfo;
			while (pAdapter) {
				char *aname = my_strdup(pAdapter->Description);
				cleanNameForWMI(aname);
				SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, aname, pAdapter->Address, sizeof(HSPAdaptorNIO));
				// clear the mark so we don't free it below
				adaptor->marked = NO;
				adaptor->ifIndex = pAdapter->Index;
				// TODO: do we get IPv6 addresses here?
				uint32_t ip4Addr = inet_addr(pAdapter->IpAddressList.IpAddress.String);
				if(ip4Addr) {
					SFLAddress ipAddr;
					ipAddr.type = SFLADDRESSTYPE_IP_V4;
					ipAddr.address.ip_v4.addr = ip4Addr;
					EnumIPSelectionPriority pri = IPSP_IP4;
					if(SFLAddress_isLoopback(&ipAddr)) pri = IPSP_LOOPBACK4;
					else if(SFLAddress_isSelfAssigned(&ipAddr)) pri = IPSP_SELFASSIGNED;
					if(pri > sp->ipPriority) {
						sp->agentIP = ipAddr;
						setStr(&sp->agentDevice, aname);
						sp->ipPriority = pri;
						myLog(LOG_INFO,"adaptor %s has agent-address priority=%d\n", aname, pri);
					}
				}
				myLog(LOG_INFO,"AdapterInfo:\n\tAdapterName:\t%s\n\tDescription:\t%s\n\tWMI_deviceId:\t<%s>\n",pAdapter->AdapterName, pAdapter->Description, aname);
				my_free(aname); 
				pAdapter = pAdapter->Next;
			}
		}

		adaptorListFreeMarked(sp->adaptorList);
		return sp->adaptorList->num_adaptors;
	}

#if defined(__cplusplus)
} /* extern "C" */
#endif
