/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readSystemUUID.h"
#include <Objbase.h>
#include <Wbemidl.h>


PVOID getUUIDPtr(uint32_t length,smbiosHeader *smbios){
	//We're not going to parse the whole SMBIOS table here.  Just a quick and dirty to get the UUID
	smbiosHeader *pTable;
	smbiosSystemInformation *si;
	uchar *scanPtr;
	pTable = smbios;
	while (pTable < smbios + length){
		if (pTable->type == SMBIOS_TABLE_SYSTEM_INFORMATION) {
			si = (smbiosSystemInformation*)pTable;
			return si->uuid;
		} else {
			//tables are terminated with double NULL
			scanPtr = (uchar*)pTable + pTable->length;
			while(!(*scanPtr == '\0' && *(scanPtr+1) =='\0')){
				scanPtr++;
			}
			scanPtr+=2;
			pTable = (smbiosHeader*)scanPtr;
		}
	}
	return NULL;
}

BOOL readSystemUUID(u_char *uuidbuf){
	BOOL gotData = FALSE;
	BSTR path = SysAllocString(WMI_WMI_NS);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;
	hr = connectToWMI(path, &pNamespace);
	SysFreeString(path);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_ERR,"readSystemUUD: connectToWMI failed for namespace %S", path);
		return FALSE;
	} 
	BSTR className = SysAllocString(L"MSSmBios_RawSMBiosTables");
	IEnumWbemClassObject *smbiosEnum = NULL;
	hr = pNamespace->CreateInstanceEnum(className, 0, NULL, &smbiosEnum);
	pNamespace->Release();
	SysFreeString(className);

	if (!SUCCEEDED(hr)) {
		myLog(LOG_ERR,"getSystemUUID: CreateInstanceEnum() failed for MSSmBios_RawSMBiosTables");
		gotData = FALSE;
	} else {
		ULONG uReturned = 1;
		IWbemClassObject *smbiosObj = NULL;

		hr = smbiosEnum->Next(4000, 1, &smbiosObj, &uReturned );
		smbiosEnum->Release();
		if (1 != uReturned){
			myLog(LOG_ERR,"getSystemUUID: Next() failed for pEnumSMBIOS");
			gotData = FALSE;
		} else {
			BSTR propName = SysAllocString(L"SMBiosData");
			CIMTYPE type;
			VARIANT val;
			smbiosObj->Get(propName, 0L, &val, &type, NULL);
			SysFreeString(propName);
			if ((VT_UI1 | VT_ARRAY) != val.vt) {
				myLog(LOG_ERR,"getSystemUUID: Get() failed for pSmbios");
				gotData = FALSE;
			} else {
				SAFEARRAY *pArray = NULL;
				smbiosHeader *smbiosData;
				u_char *uuid;
				DWORD smbufSize;
				pArray = V_ARRAY(&val);
				smbufSize = pArray->rgsabound[0].cElements;
				smbiosData = (smbiosHeader*)my_calloc(smbufSize);
				if (!smbiosData) {
					myLog(LOG_ERR,"getSystemUUID: failed to allocate buffer for smbiosData");
					gotData = FALSE;
				} else {
					memcpy((void*)smbiosData, pArray->pvData, smbufSize);
					uuid = (u_char*)getUUIDPtr(smbufSize, smbiosData);
					if (!uuid) {
						myLog(LOG_ERR,"getSystemUUID: failed to find UUID in SMBIOS");
						gotData = FALSE;
					} else {
						memcpy((void*)uuidbuf, uuid, 16);
						gotData = TRUE;
					}
				}
				VariantClear(&val);
				if (smbiosData) {
					my_free(smbiosData);
				}
			}
			smbiosObj->Release();
		}
	}
	return gotData;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif