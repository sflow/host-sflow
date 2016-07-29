/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef HYPERVUTIL_H
#define HYPERVUTIL_H

#if defined(__cplusplus)
extern "C" {
#endif

//persistent state for mapping VM UUIDs and switch port GUIDs to datasource indices
#define GUID_STORE_MAX_LINELEN 100
#define GUID_STORE_SEPARATORS " \t\r\n="
typedef struct _GuidStore {
	_GuidStore *nxt;
	uchar uuid[16];
	uint32_t dsIndex;
} GuidStore;

uint32_t assign_dsIndex(GuidStore **guidStore, char *uuid, uint32_t *maxIndex, BOOL *invalidFlag);
void readGuidStore(FILE *file, WCHAR *fileName, GuidStore **guidStore, uint32_t *maxIndex);
void writeGuidStore(GuidStore *guidStore, FILE *file);

//User data structure to store state for virtual switch ports
typedef struct {
	BOOL filterEnabled; //is packet sampling enabled on this port
	uint32_t revision; //last revision of info received from filter
	uint32_t portId; //NDIS_SWITCH_PORT_ID
	wchar_t *switchName; //switch GUID
	uint64_t switchId; //NDIS_SWITCH_ID
	wchar_t *portFriendlyName;
	wchar_t *portCountersInstance; //<switchGUID>_<portGUID>
	wchar_t *vmSystemName; // Msvm_ComputerSystem.Name (GUID)
} HVSVPortInfo;

//Virtual Adaptor/Switch Port list functions
SFLAdaptor *getVAdaptorByIds(SFLAdaptorList *vAdaptors, uint64_t switchId, uint32_t portId);
SFLAdaptor *addVAdaptor(SFLAdaptorList *vAdaptors, char *guid, uint32_t ifIndex);
void freePortInfo(void *info);

// userData structure to store state for virtual machines
typedef struct {
	BOOL marked;
	uint32_t processId;
	wchar_t *vmName; //GUID
	wchar_t *vmFriendlyName;
	uchar uuid[16];
	time_t timestamp;
	WcsArray *disks; 
} HVSVmState;

BOOL testForHyperv();

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif HYPERVUTIL_H