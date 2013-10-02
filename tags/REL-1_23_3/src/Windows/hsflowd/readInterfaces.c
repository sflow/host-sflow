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
#define PROP_IFGUID L"InterfaceGuid"
#define PROP_NAME L"Name"
#define PROP_IFDESC L"InterfaceDescription"
#define PROP_MAC L"MACAddress"
#define PROP_PERMADDR L"PermanentAddress"
#define PROP_IFINDEX L"InterfaceIndex"
#define PROP_SVC_NAME L"ServiceName"
#define PROP_VIRTUAL L"Virtual"


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
 * Parses addrString into an IPv4 or IPv6 address, then determines
 * whether the priority of the address is higher than the existing
 * adaptor IP address (according to EnumIPSelectionPriority).
 * If it is, then the new address is assigned as the adaptor IP address
 * and used to populate adapter->userData->ipAddr.
 * If two addresses have the same highest priority, then the first one seen 
 * is chosen.
 */
static void stringToAdaptorIp(PCWSTR addrString, SFLAdaptor *adaptor)
{
	HSPAdaptorNIO *nioState = (HSPAdaptorNIO *)adaptor->userData;
	IN_ADDR in_addr = {0};
	LPCWSTR terminator;
	LONG result = RtlIpv4StringToAddressW(addrString, TRUE, &terminator, &in_addr);
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
		result = RtlIpv6StringToAddressW(addrString, &terminator, &in6_addr);
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

/**
 * Enumerates MSFT_NetIpAddress whose interface index is the same as the
 * adaptor's. Calls stringToAdaptorIP() for each object so that the
 * highest priority IP address is associated with the adaptor.
 */
static void readIpAddressesMsft(IWbemServices *pNamespace, SFLAdaptor *adaptor)
{
	BSTR queryLang = SysAllocString(L"WQL");
	wchar_t *query = L"SELECT * FROM MSFT_NetIpAddress WHERE InterfaceIndex=%u";
	wchar_t ipQuery[70];
	swprintf_s(ipQuery, 70, query, adaptor->ifIndex);
	IEnumWbemClassObject *ipEnum = NULL;
	HRESULT hr = pNamespace->ExecQuery(queryLang, ipQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &ipEnum);
	SysFreeString(queryLang);
	if (!SUCCEEDED(hr)) {
		myLog(LOG_ERR,"readIpAddressesMsft: ExecQuery() failed for query %S error=0x%x", ipQuery, hr);
		return;
	}
	IWbemClassObject *ipObj;
	hr = WBEM_S_NO_ERROR;
	while (WBEM_S_NO_ERROR == hr) {
		ULONG ipCount = 0;
		hr = ipEnum->Next(WBEM_INFINITE, 1, &ipObj, &ipCount);
		if (ipCount == 0) {
			break;
		}
		VARIANT address;
		hr = ipObj->Get(L"IPAddress", 0, &address, 0, 0);
		if (WBEM_S_NO_ERROR == hr && V_VT(&address) == VT_BSTR)  {
			stringToAdaptorIp(address.bstrVal, adaptor);
		}
		VariantClear(&address);
		ipObj->Release();
	}
	ipEnum->Release();
}

/**
 * Enumerates the adapters from root\standardcimv2 MSFT_NetAdapter,
 * which is supported from Win8/2012. This method is preferred since
 * the interface description, which is used to name the counters, 
 * is not changed when a team is created.
 * Returns true on success, false on failure.
 * Uses the information to populate the sp->adaptorList structure:
 * adapter->deviceName = MSFT_NetAdapter.InterfaceGuid (converted to 
 * lowercase char with enclosing {} removed)
 * adapter->ifIndex = MSFT_NetAdapter.InterfaceIndex
 * adapter->mac[0] = MSFT_NetAdapter.PermanentAddress (this might not
 * be correct but it is just as correct as chosing the first or random
 * address from the NetworkAddresses property since the SFLAdapter 
 * struct only allows one MAC).
 * this is the interface index used in the route table (rather than Index
 * which is the index for the interface in the registry).
 * adapter->userData->countersInstance = MSFT_NetAdapter.InterfaceDescription 
 * (with reserved chars replaced) 
 * adapter->userData->isVirtual = MSFT_NetAdapter.Virtual
 * Optionally gets the IP address (v4 and/or v6) from the associated
 * MSFT_NetIPAddress filtering on the interfaceIndex. 
 * This is only required when trying
 * to identify the IP addresses that could be used as the agent address.
 */
BOOL readInterfacesMsft(SFLAdaptorList *adaptorList, BOOL getIpAddr)
{
	BSTR path = SysAllocString(WMI_STD_CIMV2_NS);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;
	
	hr = connectToWMI(path, &pNamespace);
	SysFreeString(path);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_INFO,"readInterfacesMsft: connectToWMI failed for namespace %S", path);
		return FALSE;
	}
	BSTR queryLang = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM MSFT_NetAdapter");
	IEnumWbemClassObject *adapterEnum = NULL;
	hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &adapterEnum);
	SysFreeString(queryLang);
		if (!SUCCEEDED(hr)) {
		myLog(LOG_ERR,"readInterfacesMsft: ExecQuery() failed for query %S error=0x%x", query, hr);
		SysFreeString(query);
		pNamespace->Release();
		CoUninitialize();
		return FALSE;
	}
	SysFreeString(query);
	IWbemClassObject *adapterObj = NULL;
	VARIANT ifIndexVal;
	VARIANT virtualVal;
	hr = WBEM_S_NO_ERROR;
	while (WBEM_S_NO_ERROR == hr) {
		ULONG adapterCount = 1;
		hr = adapterEnum->Next(WBEM_INFINITE, 1, &adapterObj, &adapterCount);
		if (0 == adapterCount) {
			break;
		}
		wchar_t *guidString = stringFromWMIProperty(adapterObj, PROP_IFGUID);
		wchar_t *macString = stringFromWMIProperty(adapterObj, PROP_PERMADDR);
		if (guidString != NULL && macString != NULL) {
			u_char deviceName[FORMATTED_GUID_LEN+1];
			guidToString(guidString, deviceName, FORMATTED_GUID_LEN);
			u_char mac[13];
			wchexToBinary(macString, mac, 13);
			SFLAdaptor *adaptor = adaptorListAdd(adaptorList, 
												(char *)deviceName, mac, 
												sizeof(HSPAdaptorNIO));
			// clear the mark so we don't free it later
			adaptor->marked = FALSE;
			if (WBEM_S_NO_ERROR == adapterObj->Get(PROP_IFINDEX, 0, &ifIndexVal, 0, 0) &&
				(V_VT(&ifIndexVal) == VT_I4 || V_VT(&ifIndexVal) == VT_UI4)) {
				adaptor->ifIndex = ifIndexVal.ulVal;
			}
			HSPAdaptorNIO *userData = (HSPAdaptorNIO *)adaptor->userData;
			if (userData->countersInstance != NULL) {
				my_free(userData->countersInstance);
			}
			wchar_t *counterName = stringFromWMIProperty(adapterObj, PROP_IFDESC);
			if (counterName != NULL) {
				cleanCounterName(counterName, UTNETWORK_INTERFACE);
				userData->countersInstance = counterName;
			}
			if (WBEM_S_NO_ERROR == adapterObj->Get(PROP_VIRTUAL, 0, &virtualVal, 0, 0) &&
				(V_VT(&virtualVal) == VT_BOOL)) {
				userData->isVirtual = virtualVal.boolVal != 0; // VARIANT_BOOL is a short
			}
			if (getIpAddr) {
				userData->ipPriority = IPSP_NONE;
				readIpAddressesMsft(pNamespace, adaptor);
			}
			myLog(LOG_INFO,"ReadInterfacesMsft:\n\tAdapterName:\t%s\n\tifIndex:\t%lu\n\tCounterName:\t%S\n\tisVirtual\t%u",
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
		VariantClear(&virtualVal);
	}
	adapterEnum->Release();
	pNamespace->Release();
	CoUninitialize();
	return TRUE;
}

 /**
 * Finds the associated Win32_NetworkAdapterConfiguration for Win32_NetworkAdapter adapterObj.
 * Iterates through the IP addresses associated with the adapter calling
 * stringToAdaptorIp() to choose the highest priority address (according to EnumIPSelectionPriority)
 * as the adapter address which is used to populate adapter->userData->ipAddr.
 * If two addresses have the same highest priority, then the first one seen is chosen.
 */
static void readIpAddressesWin32(IWbemServices *pNamespace, IWbemClassObject *adapterObj, SFLAdaptor *adaptor)
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
			if (WBEM_S_NO_ERROR == hr && addresses.vt == (VT_ARRAY | VT_BSTR))  {
				SAFEARRAY *sa = V_ARRAY(&addresses);
				LONG lstart, lend;
				hr = SafeArrayGetLBound(sa, 1, &lstart);
				hr = SafeArrayGetUBound(sa, 1, &lend);
				BSTR *pbstr;
				hr = SafeArrayAccessData(sa, (void HUGEP **)&pbstr);
				if (SUCCEEDED(hr)) {
					for (LONG idx=lstart; idx <= lend; idx++) {		
						PCWSTR addrStr = pbstr[idx];
						stringToAdaptorIp(addrStr, adaptor);
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
 * Returns true on success, false on failure.
 */
static BOOL readInterfacesWin32(SFLAdaptorList *adaptorList, BOOL getIpAddr)
{
	BSTR path = SysAllocString(WMI_CIMV2_NS);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;
	
	hr = connectToWMI(path, &pNamespace);
	SysFreeString(path);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_ERR,"readInterfacesWin32: connectToWMI failed for namespace %S", path);
		return FALSE;
	}
	BSTR queryLang = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionStatus=2");
	IEnumWbemClassObject *adapterEnum = NULL;
	hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &adapterEnum);
	SysFreeString(queryLang);
	if (!SUCCEEDED(hr)) {
		myLog(LOG_ERR,"readInterfacesWin32: ExecQuery() failed for query %S error=0x%x", query, hr);
		SysFreeString(query);
		pNamespace->Release();
		CoUninitialize();
		return FALSE;
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
			SFLAdaptor *adaptor = adaptorListAdd(adaptorList, 
												(char *)deviceName, mac, 
												sizeof(HSPAdaptorNIO));
			// clear the mark so we don't free it later
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
				readIpAddressesWin32(pNamespace, adapterObj, adaptor);
			}
			myLog(LOG_INFO,"ReadInterfacesWin32:\n\tAdapterName:\t%s\n\tifIndex:\t%lu\n\tCounterName:\t%S\n\tisVirtual\t%u",
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
	return TRUE;
}

 /**
 * Enumerates the adapters for this host by first trying to enumerate
 * MSFT_NetAdapter and if this fails (root\standardcimv2 namespace does
 * not exist prior to Win8/2012) then tries to enumerate Win32_NetworkAdapter
 * where NetConnectionStatus=2 (to exclude tunnels, ras, wan miniports etc).
 * Uses the information to populate the sp->adaptorList structure.
 * Optionally gets the IP address (v4 and/or v6) from the approriate associated
 * objects (MSFT_NetIpAddress or Win32_NetworkAdapterConfiguration). 
 * This is only required when trying to identify the IP addresses that could be 
 * used as the agent address.
 * MSFT_NetAdapter is preferred, since the interface description is used for
 * the interface counter instance name, and this description does not
 * change when teaming is enabled, whereas Win32_NetworkAdapter.Name does
 * change when teaming is enabled.
 */
 void readInterfaces(HSP *sp, BOOL getIPAddr)
 {
	if (sp->adaptorList == NULL) {
		sp->adaptorList = adaptorListNew();
	}
	adaptorListMarkAll(sp->adaptorList);
	if (!readInterfacesMsft(sp->adaptorList, getIPAddr)) {
		readInterfacesWin32(sp->adaptorList, getIPAddr);
	}
	adaptorListFreeMarked(sp->adaptorList, freeAdaptorInfo);
 }

#if defined(__cplusplus)
} /* extern "C" */
#endif
