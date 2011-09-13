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
	while(pTable < smbios + length){
		if(pTable->type == SMBIOS_TABLE_SYSTEM_INFORMATION){
			si = (smbiosSystemInformation*)pTable;
			return si->uuid;
		}
		else{
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

int readSystemUUID(u_char *uuidbuf){
	int	                    gotData = NO;
	BSTR                    path = SysAllocString(L"root\\wmi");
	BSTR                    className = SysAllocString(L"MSSmBios_RawSMBiosTables");
	BSTR                    propName = SysAllocString(L"SMBiosData");
	ULONG                   uReturned = 1;
	HRESULT                 hr = S_FALSE;
	IWbemLocator            *pLocator = NULL;
	IWbemServices           *pNamespace = NULL;
	IEnumWbemClassObject    *pEnumSMBIOS = NULL;
	IWbemClassObject        *pSmbios = NULL;
	CIMTYPE                 type;
	VARIANT                 pVal;
	SAFEARRAY               *pArray = NULL;
	smbiosHeader            *smbiosData;
	u_char                  *uuidPtr;
	DWORD                   smbufSize;

	hr =  CoInitializeEx(0, COINIT_MULTITHREADED);
	if (! SUCCEEDED( hr ) ){
		myLog(LOG_ERR,"readSystemUUID: failed to initialize COM");
		gotData = NO;
		goto Cleanup;
	}
	
	hr =  CoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE,NULL);
	hr = CoCreateInstance( CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLocator );
	if(! SUCCEEDED( hr ) ){
		myLog(LOG_ERR,"readSystemUUID: failed to create WMI instance");
		gotData = NO;
		goto Cleanup;
	}

	hr = pLocator->ConnectServer(path, NULL, NULL, NULL, 0, NULL, NULL, &pNamespace );
	pLocator->Release();
	if( WBEM_S_NO_ERROR != hr ){
		myLog(LOG_ERR,"getSystemUUID: ConnectServer() failed for namespace");
		gotData = NO;
		goto Cleanup;
	}

	hr = pNamespace->CreateInstanceEnum(className, 0, NULL, &pEnumSMBIOS );
	pNamespace->Release();
	if (! SUCCEEDED( hr ) ){
		myLog(LOG_ERR,"getSystemUUID: CreateInstanceEnum() failed for MSSmBios_RawSMBiosTables");
		gotData = NO;
		goto Cleanup;
	}

	hr = pEnumSMBIOS->Next(4000, 1, &pSmbios, &uReturned );
	pEnumSMBIOS->Release();
	if ( 1 != uReturned ){
		myLog(LOG_ERR,"getSystemUUID: Next() failed for pEnumSMBIOS");
		gotData = NO;
		goto Cleanup;
	}
	
	pSmbios->Get(propName,0L,&pVal,&type,NULL);
	if ( ( VT_UI1 | VT_ARRAY) != pVal.vt){
		myLog(LOG_ERR,"getSystemUUID: Get() failed for pSmbios");
	    gotData = NO;
		goto Cleanup;
	}

	pArray = V_ARRAY(&pVal);
	smbufSize = pArray->rgsabound[0].cElements;
	smbiosData = (smbiosHeader*)my_calloc(smbufSize);
	if(!smbiosData){
		myLog(LOG_ERR,"getSystemUUID: failed to allocate buffer for smbiosData");
		gotData = NO;
		goto Cleanup;
	}
	memcpy((void*)smbiosData,pArray->pvData,smbufSize);
	uuidPtr = (u_char*)getUUIDPtr(smbufSize,smbiosData);
	if(!uuidPtr){
		myLog(LOG_ERR,"getSystemUUID: failed to find UUID in SMBIOS");
		gotData = NO;
		goto Cleanup;
	}
	memcpy((void*)uuidbuf,uuidPtr,16);
	gotData = YES;

Cleanup:
	SysFreeString(propName);
	SysFreeString(className);
	SysFreeString(path);
	if(smbiosData) my_free(smbiosData);

	return gotData;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif