/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "hypervSwitch.h"
#include "util.h"

extern int debug;

/**
 * Test to see whether we are running on a system with Hyper-V enabled.
 * We consider Hyper-V to be running (and can export per vm stats) if
 * the Hyper-V related services (nvspwmi, vmm, vhdsvc) are running and
 * we can access the WMI namespace root\virtualization (ie v1 for Win 2008).
 * We do not check for the v2 namespace, since this is not required for 
 * per vm stats.
 * The ability connect to the sFlow filter for export of packet samples 
 * and counter samples for the virtual switch is made separately.
 */
BOOL testForHyperv()
{
	BSTR path = SysAllocString(WMI_CIMV2_NS);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;

	hr = connectToWMI(path, &pNamespace);
	SysFreeString(path);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_ERR,"testForHyperv: connectToWMI failed for namespace %S", path);
		return false;
	}
	//Test for Hyper-V services
	BOOL gotHyperV = false;
	BSTR queryLang = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM Win32_Service WHERE Name=\"nvspwmi\" OR Name=\"vmms\" OR Name=\"vhdsvc\"");
	IEnumWbemClassObject *serviceEnum = NULL;
	hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &serviceEnum);
	SysFreeString(query);
	SysFreeString(queryLang);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_ERR, "testForHyperv: ExecQuery() failed for %S error=0x%x", query, hr);
	} else {
		IWbemClassObject *serviceObj = NULL;
		ULONG uReturned = 0;
		BOOL gotHyperVSvc = false;
		hr = serviceEnum->Next(WBEM_INFINITE, 1, &serviceObj, &uReturned);
		if (SUCCEEDED(hr)) {
			if (uReturned == 1) {
				gotHyperVSvc = true;
				serviceObj->Release();
			}
		}
		serviceEnum->Release();
		pNamespace->Release();
		if (gotHyperVSvc) { //now check that we have the v1 virtualization namespace
			CoUninitialize();
			path = SysAllocString(WMI_VIRTUALIZATION_NS_V1);
			hr = connectToWMI(path, &pNamespace);
			SysFreeString(path);
			if (WBEM_NO_ERROR == hr) {
				gotHyperV = true;
				pNamespace->Release();
			}
		}
	}
	CoUninitialize();
	myLog(LOG_INFO, "testForHyperv: HyperV=%u", gotHyperV);
	return gotHyperV;
}

/**
 * Frees the allocated memory for a HVSVPortInfo.
 */
void freePortInfo(void *info)
{
	HVSVPortInfo *portInfo = (HVSVPortInfo *)info;
	if (portInfo->portFriendlyName != NULL) {
		my_free(portInfo->portFriendlyName);
	}
	if (portInfo->portCountersInstance != NULL) {
		my_free(portInfo->portCountersInstance);
	}
	if (portInfo->switchName != NULL) {
		my_free(portInfo->switchName);
	}
	if (portInfo->vmSystemName != NULL) {
		my_free(portInfo->vmSystemName);
	}
	my_free(portInfo);
}

/**
 * Creates a new GuidStore structure, populates it with the uuid and dsIndex,
 * then adds it to the head of linked list of GuidStores (store).
 * Returns the new GuidStore at the head of the list.
 */
static GuidStore *newGuidStore(GuidStore *guidStore, char *uuid, uint32_t dsIndex)
{
	GuidStore *newStore = (GuidStore *)my_calloc(sizeof(GuidStore));
    memcpy(newStore->uuid, uuid, 16);
	newStore->dsIndex = dsIndex;
	ADD_TO_LIST(guidStore, newStore);
	return newStore;
}

/**
 * Returns the unique dsIndex for the uuid, either by finding an existing mapping for the uuid
 * in the guidStore linked list or if none exists, creating a new mapping and adding it to the
 * head of the guidStore linked list and updating **guidStore to point to the new head and
 * marking the store as invalid so that it can ve resaved to persistent storage.
 * Algorithm for allocating a new dsIndex is simply to use maxIndex. However this should be
 * revisited when guid entries are aged out.
 */
uint32_t assign_dsIndex(GuidStore **guidStore, char *uuid, uint32_t *maxIndex, BOOL *invalidFlag) 
{
	// Have we seen the UUID before?
	GuidStore *store = *guidStore;
	for ( ; store != NULL; store = store->nxt) {
		if (memcmp(uuid, store->uuid, 16) == 0) {
			return store->dsIndex;
		}
	}
	// new UUID so allocate a new entry and add it to the head of the store
	*guidStore = newGuidStore(*guidStore, uuid, ++*maxIndex);
	// indicate that the store has changed and should be resaved to persistent storage
	*invalidFlag = TRUE;
	return *maxIndex;
}

/**
 * Reads the file to extract saved GUID (UUID) to dsIndex mappings
 * and populates the GuidStore structure. **guidStore is updated to point
 * to the head of the list.
 * Any lines in the file that cannot be parsed or contain invalid entries
 * are discarded.
 */
void readGuidStore(FILE *file, WCHAR *fileName, GuidStore **guidStore, uint32_t *maxIndex)
{
	if (file == NULL) {
		return;
	}
	CHAR line[GUID_STORE_MAX_LINELEN+1];
	rewind(file);
	uint32_t lineNo = 0;
	while (fgets(line, GUID_STORE_MAX_LINELEN, file)) {
		lineNo++;
		CHAR *p = line;
		// comments start with '#'
		p[strcspn(p, "#")] = '\0';
		// should just have two tokens, so check for 3
		uint32_t tokc = 0;
		CHAR *tokv[3];
		for (uint32_t i = 0; i < 3; i++) {
			size_t len;
			p += strspn(p, GUID_STORE_SEPARATORS);
			if ((len = strcspn(p, GUID_STORE_SEPARATORS)) == 0){
				break;
			}
			tokv[tokc++] = p;
			p += len;
			if (*p != '\0') {
				*p++ = '\0';
			}
		}
		// expect UUID=int
		CHAR uuid[16];
		long dsIndex;
		if (tokc != 2 || !parseUUID(tokv[0], uuid) || (dsIndex = strtol(tokv[1], NULL, 0)) < 1) {
			myLog(LOG_ERR, "readGuidStore: bad line %u %s in %S", lineNo, line, fileName);
		} else {
			*guidStore = newGuidStore(*guidStore, uuid, dsIndex);
			if ((*guidStore)->dsIndex > *maxIndex) {
				*maxIndex = (*guidStore)->dsIndex;
			}
		}
	}
}

/**
 * Writes out the guidStore to persistent storage represented by file,
 * replacing the contents of the original contents of the file.
 */
void writeGuidStore(GuidStore *guidStore, FILE *file)
{
	rewind(file);
	for (GuidStore *store = guidStore; store != NULL; store = store->nxt) {
		char uuidStr[FORMATTED_GUID_LEN+1];
		printUUID((u_char *)store->uuid, (u_char *)uuidStr, FORMATTED_GUID_LEN);
		fprintf(file, "%s=%u\n", uuidStr, store->dsIndex);
    }
	fflush(file);
    // chop off anything that may be lingering from before
	truncateOpenFile(file);
}

/**
 * Returns the adaptor representing the switch port with the switchId and portId equal to 
 * the specified switchId and portId.
 * Returns null of there is no switch port with the same ids.
 */
SFLAdaptor *getVAdaptorByIds(SFLAdaptorList *vAdaptors, uint64_t switchId, uint32_t portId)
{
	if (vAdaptors) {
		for (uint32_t i = 0; i < vAdaptors->num_adaptors; i++) {
			HVSVPortInfo *portInfo = (HVSVPortInfo *)vAdaptors->adaptors[i]->userData;
			if (portInfo != NULL  && portInfo->switchId == switchId && portInfo->portId == portId) {
				return vAdaptors->adaptors[i];
			}
		}
	}
    return NULL;
}

/**
 * Allocates space for a SFLAdaptor and its HVSPortInfo userData. 
 * Copies the guid to SFLAdaptor->deviceName (so guid can be freed), sets the
 * ifIndex and default values for ifSpeed etc. Adds the new adaptor to 
 * vAdaptors and returns the new adaptor.
 * Does not check whether there is already an adaptor with the device name first.
 */
SFLAdaptor *addVAdaptor(SFLAdaptorList *vAdaptors, char *guid, uint32_t ifIndex)
{
	SFLAdaptor *vAdaptor = (SFLAdaptor *)my_calloc(sizeof(SFLAdaptor));
	vAdaptor->deviceName = my_strdup(guid);
	vAdaptor->ifIndex = ifIndex;
	vAdaptor->ifDirection = 3;
	vAdaptor->ifSpeed = 1000000000UL;
	vAdaptor->promiscuous = 2;
	HVSVPortInfo *portInfo = (HVSVPortInfo *)my_calloc(sizeof(HVSVPortInfo));
	portInfo->filterEnabled = FALSE;
	portInfo->portId = 0;
	portInfo->revision = 0;
	portInfo->portFriendlyName = NULL;
	portInfo->portCountersInstance = NULL;
	portInfo->switchName = NULL;
	portInfo->vmSystemName = NULL;
	vAdaptor->userData = portInfo;
	if(vAdaptors->num_adaptors == vAdaptors->capacity) {
		// grow
		vAdaptors->capacity *= 2;
		vAdaptors->adaptors = (SFLAdaptor **)my_realloc(vAdaptors->adaptors, 
			  vAdaptors->capacity * sizeof(SFLAdaptor *));
	}
	vAdaptors->adaptors[vAdaptors->num_adaptors++] = vAdaptor;
	return vAdaptor;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif