/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <Mstcpip.h>

#define VMSMP L"VMSMP"
#define PROP_GUID L"GUID"
#define PROP_NAME L"Name"
#define PROP_MAC L"MACAddress"
#define PROP_IFINDEX L"InterfaceIndex"
#define PROP_SVC_NAME L"ServiceName"


 /**
 * Frees the allocated memory for a HSPAdaptorNIO.
 */
void freeAdaptorInfo(void *info)
{
	HSPAdaptorNIO *adaptorInfo = (HSPAdaptorNIO *)info;
	if (info != NULL && adaptorInfo->countersInstance != NULL) {
		my_free(adaptorInfo->countersInstance);
	}
	my_free(adaptorInfo);
}
    

/**
 * Finds the associated Win32_NetworkAdapterConfiguration for Win32_NetworkAdapter adapterObj.
 * Iterates through the IP addresses associated with the adapter and chooses the highest
 * priority IP address (according to EnumIPSelectionPriority) as the adapter address
 * which is used to populate adapter->userData->ipAddr.
 * If two addresses have the same highest priority, then the first one seen is chosen.
 */
void readIpAddresses(IWbemServices *pNamespace, IWbemClassObject *adapterObj, SFLAdaptor *adaptor)
{
	IEnumWbemClassObject *configEnum;
	HRESULT hr = associatorsOf(pNamespace, adapterObj,
							   L"Win32_NetworkAdapterSetting",
							   L"Win32_NetworkAdapterConfiguration",
							   L"Setting", &configEnum);
	if (SUCCEEDED(hr)) {
		IWbemClassObject *configObj;
		ULONG configCount;
		hr = configEnum->Next(WBEM_INFINITE, 1, &configObj, &configCount);
		if (SUCCEEDED(hr) && configCount == 1) {
			VARIANT addresses;
			hr = configObj->Get(L"IPAddress", 0, &addresses, 0, 0);
			if (WBEM_S_NO_ERROR == hr && addresses.vt == (VT_ARRAY |VT_BSTR))  {
				SAFEARRAY *sa = V_ARRAY(&addresses);
				LONG lstart, lend;
				hr = SafeArrayGetLBound(sa, 1, &lstart);
				hr = SafeArrayGetUBound(sa, 1, &lend);
				BSTR *pbstr;
				hr = SafeArrayAccessData(sa, (void HUGEP **)&pbstr);
				if (SUCCEEDED(hr)) {
					HSPAdaptorNIO *nioState = (HSPAdaptorNIO *)adaptor->userData;
					for (LONG idx=lstart; idx <= lend; idx++) {		
						PCWSTR addrStr = pbstr[idx];
						IN_ADDR in_addr = {0};
						LPCWSTR terminator;
						LONG result = RtlIpv4StringToAddressW(addrStr, TRUE, &terminator, &in_addr);
						if (NO_ERROR == result) {
							SFLAddress addrv4;
							addrv4.type = SFLADDRESSTYPE_IP_V4;
							addrv4.address.ip_v4.addr =  in_addr.S_un.S_addr;
							EnumIPSelectionPriority ipPriority = agentAddressPriority(&addrv4);
							if (ipPriority > nioState->ipPriority) {
								nioState->ipPriority = ipPriority;
								nioState->ipAddr = addrv4;
							}
						} else {
							IN6_ADDR in6_addr = {0};
							result = RtlIpv6StringToAddressW(addrStr, &terminator, &in6_addr);
							if (NO_ERROR == result) {
								SFLAddress addrv6;
								addrv6.type = SFLADDRESSTYPE_IP_V6;
								memcpy(addrv6.address.ip_v6.addr, in_addr6.u.Byte, sizeof(in6_addr.u.Byte));
								EnumIPSelectionPriority ipPriority = agentAddressPriority(&addrv6);
								if (ipPriority > nioState->ipPriority) {
									nioState->ipPriority = ipPriority;
									nioState->ipAddr = addrv6;
								}
							}
						}
					}
					SafeArrayUnaccessData(sa);
				}
			}
			VariantClear(&addresses);
			configObj->Release();
		}
		configEnum->Release();
	}
}

/**
 * Enumerates the adapters for this host from WMI Win32_NetworkAdapter
 * where NetConnectionStatus=2 (to exclude tunnels, ras, wan miniports etc).
 * Uses the information to populate the sp->adaptorList structure.
 * adapter->deviceName = Win32_NetworkAdapter.GUID (converted to 
 * lowercase char with enclosing {} removed)
 * adapter->ifIndex = Win32_NetworkAdapter.InterfaceIndex
 * this is the interface index used in the route table (rather than Index
 * which is the index for the interface in the registry).
 * adapter->userData->countersInstance = Win32_NetworkAdapter.Name 
 * (with reserved chars replaced) 
 * adapter->userData->isVirtual = (Win32_NetworkAdapter.ServiceName == "VMSMP")
 * Optionally gets the IP address (v4 and/or v6) from the associated
 * Win32_NetworkAdapterConfiguration. This is only required when trying
 * to identify the IP addresses that could be used as the agent address.
 */
void readInterfaces(HSP *sp, BOOL getIpAddr)
{
	if (sp->adaptorList == NULL) {
		sp->adaptorList = adaptorListNew();
	}
	adaptorListMarkAll(sp->adaptorList);

	BSTR path = SysAllocString(WMI_CIMV2_NS);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;
	
	hr = connectToWMI(path, &pNamespace);
	SysFreeString(path);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_ERR,"readInterfaces: connectToWMI failed for namespace %S", path);
		return;
	}
	BSTR queryLang = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionStatus=2");
	IEnumWbemClassObject *adapterEnum = NULL;
	hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &adapterEnum);
	SysFreeString(queryLang);
	if (!SUCCEEDED(hr)) {
		myLog(LOG_ERR,"readInterfaces: ExecQuery() failed for query %S error=0x%x", query, hr);
		SysFreeString(query);
		pNamespace->Release();
		CoUninitialize();
		return;
	}
	SysFreeString(query);
	IWbemClassObject *adapterObj = NULL;
	VARIANT ifIndexVal;
	hr = WBEM_S_NO_ERROR;
	while (WBEM_S_NO_ERROR == hr) {
		ULONG adapterCount = 1;
		hr = adapterEnum->Next(WBEM_INFINITE, 1, &adapterObj, &adapterCount);
		if (0 == adapterCount) {
			break;
		}
		wchar_t *guidString = stringFromWMIProperty(adapterObj, PROP_GUID);
		wchar_t *macString = stringFromWMIProperty(adapterObj, PROP_MAC);
		if (guidString != NULL && macString != NULL) {
			u_char deviceName[FORMATTED_GUID_LEN+1];
			guidToString(guidString, deviceName, FORMATTED_GUID_LEN);
			u_char mac[13];
			wchexToBinary(macString, mac, 13);
			SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, 
												(char *)deviceName, mac, 
												sizeof(HSPAdaptorNIO));
			// clear the mark so we don't free it below
			adaptor->marked = FALSE;
			if (WBEM_S_NO_ERROR == adapterObj->Get(PROP_IFINDEX, 0, &ifIndexVal, 0, 0) &&
				(V_VT(&ifIndexVal) == VT_I4 || V_VT(&ifIndexVal) == VT_UI4)) {
				adaptor->ifIndex = ifIndexVal.ulVal;
			}
			HSPAdaptorNIO *userData = (HSPAdaptorNIO *)adaptor->userData;
			if (userData->countersInstance != NULL) {
				my_free(userData->countersInstance);
			}
			wchar_t *counterName = stringFromWMIProperty(adapterObj, PROP_NAME);
			if (counterName != NULL) {
				cleanCounterName(counterName, UTNETWORK_INTERFACE);
				userData->countersInstance = counterName;
			}
			wchar_t *svcName = stringFromWMIProperty(adapterObj, PROP_SVC_NAME);
			if (svcName != NULL) {
				userData->isVirtual = (_wcsicmp(VMSMP, svcName) == 0);
				my_free(svcName);
			}
			if (getIpAddr) {
				userData->ipPriority = IPSP_NONE;
				readIpAddresses(pNamespace, adapterObj, adaptor);
			}
			myLog(LOG_INFO,"ReadInterfaces:\n\tAdapterName:\t%s\n\tifIndex:\t%lu\n\tCounterName:\t%S\n\tisVirtual\t%u",
				adaptor->deviceName, adaptor->ifIndex, userData->countersInstance, userData->isVirtual);
		}
		if (guidString != NULL) {
			my_free(guidString);
		}
		if (macString != NULL) {
			my_free(macString);
		}
		adapterObj->Release();
		VariantClear(&ifIndexVal);
	}
	adapterEnum->Release();
	pNamespace->Release();
	CoUninitialize();
	adaptorListFreeMarked(sp->adaptorList, freeAdaptorInfo);
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
