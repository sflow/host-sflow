/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

/*________________---------------------------__________________
  ________________    freeAdaptors           __________________
  ----------------___________________________------------------
*/


void freeAdaptors(HSP *sp)
{
  uint32_t i;

  if(sp->adaptorList) {
    for( i = 0; i < sp->adaptorList->num_adaptors; i++) {
      free(sp->adaptorList->adaptors[i]);
    }
    free(sp->adaptorList);
    sp->adaptorList = NULL;
  }
}

  
/*________________---------------------------__________________
  ________________    newAdaptorList         __________________
  ----------------___________________________------------------
*/

void newAdaptorList(HSP *sp)
{
  freeAdaptors(sp);
  sp->adaptorList = (SFLAdaptorList *)malloc(sizeof(SFLAdaptorList));
  sp->adaptorList->capacity = 4; // will grow if necessary
  sp->adaptorList->adaptors = (SFLAdaptor **)malloc(sp->adaptorList->capacity * sizeof(SFLAdaptor *));
  sp->adaptorList->num_adaptors = 0;
}

/*________________---------------------------__________________
  ________________    trimWhitespace         __________________
  ----------------___________________________------------------
*/

static char *trimWhitespace(char *str)
{
  char *end;
  
  // Trim leading space
  while(isspace(*str)) str++;
  
  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;
  
  // Write new null terminator
  *(end+1) = 0;
  
  return str;
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
  SFLAdaptor *adaptor;
  ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

  newAdaptorList(sp);

  pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
  if (pAdapterInfo == NULL) {
      MyLog(LOG_ERR,"Error allocating memory needed to call GetAdaptersinfo\n");
      return 1;
  }
  if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            MyLog(LOG_ERR,"Error allocating memory needed to call GetAdaptersinfo\n");
            return 1;
        }
   }
  if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
		while (pAdapter) {
			adaptor = (SFLAdaptor *)calloc(1, sizeof(SFLAdaptor) + (1 * sizeof(SFLMacAddress)));
			memcpy(adaptor->macs[0].mac,pAdapter->Address,6);
			adaptor->num_macs = 1;
			adaptor->deviceName = _strdup(pAdapter->AdapterName);
			adaptor->ifIndex = pAdapter->Index;
			adaptor->ipAddr.addr = inet_addr(pAdapter->IpAddressList.IpAddress.String);
			sp->adaptorList->adaptors[sp->adaptorList->num_adaptors] = adaptor;
			if(++sp->adaptorList->num_adaptors == sp->adaptorList->capacity)  {
		  	// grow
		  		sp->adaptorList->capacity *= 2;
		  		sp->adaptorList->adaptors = (SFLAdaptor **)realloc(sp->adaptorList->adaptors,
								     sp->adaptorList->capacity * sizeof(SFLAdaptor *));
			}
			MyLog(LOG_INFO,"AdapterInfo:\n\tAdapterName:\t%s\n\tDescription:\t%s\n",pAdapter->AdapterName,pAdapter->Description);
			pAdapter = pAdapter->Next;
		}
  }
  

  if (pAdapterInfo) free(pAdapterInfo);
  return sp->adaptorList->num_adaptors;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
