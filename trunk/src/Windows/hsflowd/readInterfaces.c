/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <Mstcpip.h>

#define VMSMP L"VMSMP"

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
	SysFreeString(query);
	if (!SUCCEEDED(hr)) {
		myLog(LOG_ERR,"readInterfaces: ExecQuery() failed for query %S error=0x%x", query, hr);
		SysFreeString(queryLang);
		pNamespace->Release();
		CoUninitialize();
		return;
	}
	BSTR propGuid = SysAllocString(L"GUID");
	BSTR propName = SysAllocString(L"Name");
	BSTR propMac = SysAllocString(L"MACAddress");
	BSTR propifIndex = SysAllocString(L"InterfaceIndex");
	BSTR propSvcName = SysAllocString(L"ServiceName");
	IWbemClassObject *adapterObj = NULL;
	VARIANT guidVal;
	VARIANT nameVal;
	VARIANT macVal;
	VARIANT ifIndexVal;
	VARIANT svcNameVal;
	hr = WBEM_S_NO_ERROR;
	while (WBEM_S_NO_ERROR == hr) {
		ULONG adapterCount = 1;
		hr = adapterEnum->Next(WBEM_INFINITE, 1, &adapterObj, &adapterCount);
		if (0 == adapterCount) {
			break;
		}
		adapterObj->Get(propGuid, 0, &guidVal, 0, 0);
		adapterObj->Get(propName, 0, &nameVal, 0, 0);
		adapterObj->Get(propMac, 0, &macVal, 0, 0);
		adapterObj->Get(propifIndex, 0, &ifIndexVal, 0, 0);
		adapterObj->Get(propSvcName, 0, &svcNameVal, 0, 0);
		u_char deviceName[FORMATTED_GUID_LEN+1];
		guidToString(guidVal.bstrVal, deviceName, FORMATTED_GUID_LEN);
		u_char mac[13];
		wchexToBinary(macVal.bstrVal, mac, 13);
		SFLAdaptor *adaptor = adaptorListAdd(sp->adaptorList, 
											 (char *)deviceName, mac, 
											 sizeof(HSPAdaptorNIO));
		// clear the mark so we don't free it below
		adaptor->marked = FALSE;
		adaptor->ifIndex = ifIndexVal.ulVal;
		HSPAdaptorNIO *userData = (HSPAdaptorNIO *)adaptor->userData;
		if (userData->countersInstance != NULL) {
			my_free(userData->countersInstance);
		}
		size_t length = SysStringLen(nameVal.bstrVal)+1;
		wchar_t *counterName = (wchar_t *)my_calloc(length*sizeof(wchar_t));
		wcscpy_s(counterName, length, nameVal.bstrVal);
		cleanCounterName(counterName, UTNETWORK_INTERFACE);
		userData->countersInstance = counterName;
		userData->isVirtual = (_wcsicmp(VMSMP, svcNameVal.bstrVal) == 0);
		if (getIpAddr) {
			userData->ipPriority = IPSP_NONE;
			readIpAddresses(pNamespace, adapterObj, adaptor);
		}
		myLog(LOG_INFO,"ReadInterfaces:\n\tAdapterName:\t%s\n\tifIndex:\t%lu\n\tCounterName:\t%S\n\tisVirtual\t%u",
			  adaptor->deviceName, adaptor->ifIndex, userData->countersInstance, userData->isVirtual);
		adapterObj->Release();
		VariantClear(&guidVal);
		VariantClear(&nameVal);
		VariantClear(&macVal);
		VariantClear(&ifIndexVal);
		VariantClear(&svcNameVal);
	}
	adapterEnum->Release();
	SysFreeString(propGuid);
	SysFreeString(propName);
	SysFreeString(propMac);
	SysFreeString(propifIndex);
	SysFreeString(propSvcName);
	pNamespace->Release();
	CoUninitialize();
	adaptorListFreeMarked(sp->adaptorList, freeAdaptorInfo);
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
