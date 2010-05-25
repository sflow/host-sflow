#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readSystemUUID.h"

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
	RawSMBIOSData *smbuf;
	DWORD smbufSize;
	u_char* uuidPtr;
	int gotData = NO;

	smbufSize = GetSystemFirmwareTable('RSMB',0,NULL,0);
	if(smbufSize == 0){
		MyLog(LOG_ERR,"GetSystemFirmwareTable failed 1st call: %d",GetLastError());
		return gotData;
	}
	smbuf = malloc(smbufSize);
	if( GetSystemFirmwareTable('RSMB',0,(PVOID)smbuf,smbufSize) < smbufSize){
		MyLog(LOG_ERR,"GetSystemFirmwareTable failed 2nd call: %d",GetLastError());
		return gotData;
	}
	uuidPtr = NULL;
	uuidPtr = getUUIDPtr(smbuf->Length,(smbiosHeader*)smbuf->SMBIOSTableData);
	if(!uuidPtr){
		MyLog(LOG_ERR,"readSystemUUID: failed");
		return gotData;
	}
	memcpy((void*)uuidbuf,uuidPtr,16);
	gotData = YES;
	return gotData;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif