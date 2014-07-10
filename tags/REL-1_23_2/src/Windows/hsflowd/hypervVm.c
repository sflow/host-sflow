/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include <initguid.h> //needs to be before ole2.h which is included in windows.h included in hsflowd.h
#include "hsflowd.h"
#include "hypervUtil.h"
#include "xmlUtil.h"
#include "readWindowsEnglishCounters.h"
#include <xmllite.h>
#include <Shlwapi.h>
#include <virtdisk.h>

extern int debug;

#define XML_INSTANCE L"INSTANCE"
#define XML_PROPERTY L"PROPERTY"
#define XML_NAME L"NAME"
#define XML_NAME_VAL L"Name"
#define XML_VALUE L"VALUE"
#define XML_DATA_VAL L"Data"
#define XML_FQDN L"FullyQualifiedDomainName"
#define XML_OSNAME L"OSName"
#define XML_OSVERSION L"OSVersion"

#define PROP_ELEMENT_NAME L"ElementName"
#define PROP_SYSTEM_NAME L"SystemName"
#define PROP_SPEED L"Speed"
#define PROP_NAME L"Name"
#define PROP_MAC_ADDR L"PermanentAddress"
#define PROP_PROCESS L"ProcessID"
#define PROP_BIOS_GUID L"BIOSGUID"

/**
 * Functions to parse the XML in the GuestIntrinsicExchangeItems 
 * each of which has format:
 <INSTANCE CLASSNAME="Msvm_KvpExchangeDataItem">
	<PROPERTY NAME="Caption" PROPAGATED="true" TYPE="string"></PROPERTY>
	<PROPERTY NAME="Data" TYPE="string">
		<VALUE>6.2.8064</VALUE>
	</PROPERTY>
	<PROPERTY NAME="Description" PROPAGATED="true" TYPE="string"></PROPERTY>
	<PROPERTY NAME="ElementName" PROPAGATED="true" TYPE="string"></PROPERTY>
	<PROPERTY NAME="Name" TYPE="string">
		<VALUE>OSVersion</VALUE>
	</PROPERTY>
	<PROPERTY NAME="Source" TYPE="uint16"><VALUE>2</VALUE></PROPERTY>
</INSTANCE>
 */

BOOL readXmlValue(IXmlReader *xmlReader, wchar_t **value)
{
	XmlNodeType nodeType;
	if (S_OK == xmlReader->GetNodeType(&nodeType) &&
		XmlNodeType_Element == nodeType &&
		!xmlReader->IsEmptyElement()) {
		LPCWSTR localName = NULL;
		LPCWSTR tempVal;
		uint32_t valLen;
		if (S_OK == xmlReader->GetLocalName(&localName, NULL) && 
			wcscmp(XML_VALUE, localName) == 0 &&
			S_OK == xmlReader->Read(&nodeType) &&
			XmlNodeType_Text == nodeType &&
			S_OK == xmlReader->GetValue(&tempVal, &valLen)) {
			//need to copy the value before it is invalidated by moving to the next node
			*value = (wchar_t *)my_calloc((valLen+1) * sizeof(wchar_t));
			memcpy(*value, tempVal, valLen*sizeof(wchar_t));
			//read </VALUE>
			if (S_OK == xmlReader->Read(&nodeType) &&
				XmlNodeType_EndElement == nodeType) {
				//read </PROPERTY>
				return S_OK == xmlReader->Read(NULL);
			}
		}
	}
	return false;
}

BOOL readXmlProperty(IXmlReader *xmlReader, wchar_t **nameVal, wchar_t **dataVal)
{
	XmlNodeType nodeType;
	LPCWSTR localName;
	if (S_OK == xmlReader->GetNodeType(&nodeType) && 
		XmlNodeType_Element == nodeType &&
		!xmlReader->IsEmptyElement() &&
		S_OK == xmlReader->GetLocalName(&localName, NULL) &&
		wcscmp(XML_PROPERTY, localName) == 0 &&
		S_OK == xmlReader->MoveToAttributeByName(XML_NAME, NULL)) {
		LPCWSTR value;
		if (S_OK == xmlReader->GetValue(&value, NULL)) {
			BOOL xmlOK = false;
			if (wcscmp(XML_NAME_VAL, value) == 0 && 
				S_OK == xmlReader->Read(NULL)) {
				xmlOK = readXmlValue(xmlReader, nameVal);
			} else if (wcscmp(XML_DATA_VAL, value) == 0 && 
				S_OK == xmlReader->Read(NULL)) {
				xmlOK = readXmlValue(xmlReader, dataVal);
			} else {
				//advance to closing </PROPERTY>
				bool gotCloseProp = false;
				while (!gotCloseProp && S_OK == xmlReader->Read(&nodeType)) {
					if (XmlNodeType_EndElement == nodeType &&
						S_OK == xmlReader->GetLocalName(&localName, NULL) &&
						wcscmp(XML_PROPERTY, localName) == 0) {
						gotCloseProp = true;
					}
				}
				xmlOK = gotCloseProp;
			}
			if (xmlOK && S_OK == xmlReader->GetNodeType(&nodeType) 
				&& XmlNodeType_EndElement == nodeType) {
					return 
						S_OK == xmlReader->GetLocalName(&localName, NULL) &&
						wcscmp(XML_PROPERTY, localName) == 0 &&
						S_OK == xmlReader->Read(NULL);
			}
		}
	}
	return false;
}

BOOL readXmlInstance(IXmlReader *xmlReader, SFLHost_hid_counters *hid,
					 char *hnamebuf, uint32_t hnamebufLen, 
					 char *osrelbuf, uint32_t osrelbufLen)
{
	XmlNodeType nodeType;
	if (S_OK == xmlReader->GetNodeType(&nodeType) && 
		XmlNodeType_Element == nodeType) {
		LPCWSTR localName;
		if (S_OK == xmlReader->GetLocalName(&localName, NULL) && 
			wcscmp(XML_INSTANCE, localName) == 0) {
			if (S_OK == xmlReader->Read(NULL)) {
				wchar_t *nameVal = NULL;
				wchar_t *dataVal = NULL;
				size_t hnLen = 0;
				size_t osrLen = 0;
				uint32_t osName = SFLOS_unknown;
				while (readXmlProperty(xmlReader, &nameVal, &dataVal)) {
					if (nameVal != NULL) {
						if (wcscmp(nameVal, XML_FQDN) == 0) {
							wcstombs_s(&hnLen, hnamebuf, hnamebufLen, dataVal, wcslen(dataVal));
							//don't count the NULL
							if (hnLen > 0) {
								hnLen--;
							}
						} else if (wcscmp(nameVal, XML_OSNAME) == 0) {					
							if (StrStrIW(dataVal, L"Windows") != NULL) {
								osName = SFLOS_windows;
							} else if (StrStrIW(dataVal, L"Linux") != NULL) {
								osName = SFLOS_linux;
							}
						} else if (wcscmp(nameVal, XML_OSVERSION) == 0) {
							wcstombs_s(&osrLen, osrelbuf, osrelbufLen, dataVal, wcslen(dataVal));
							//don't count the NULL
							if (osrLen > 0) {
								osrLen--;
							}
						}
						my_free(nameVal);
						nameVal = NULL;
						if (dataVal != NULL) {
							my_free(dataVal);
							dataVal = NULL;
						}
					}
				}
				if (S_OK == xmlReader->GetNodeType(&nodeType) && 
					XmlNodeType_EndElement == nodeType) {
					bool xmlOK = (S_OK == xmlReader->GetLocalName(&localName, NULL) && 
						   wcscmp(XML_INSTANCE, localName) == 0);
					if (xmlOK) {
						if (hnLen > 0) {
							hid->hostname.str = hnamebuf;
							hid->hostname.len = (uint32_t)hnLen;
						} else if (osName != SFLOS_unknown) {
							hid->os_name = osName;
						} else if (osrLen > 0) {
							hid->os_release.str = osrelbuf;
							hid->os_release.len = (uint32_t)osrLen;
						}
						return true;
					} else {
						if (dataVal != NULL) {
							my_free(dataVal);
						}
						return false;
					}
				}
			}
		}
	}
	return false;
}

void parseKvpXml(VARIANT *vtVar, SFLHost_hid_counters *hid,
	             char *hnamebuf, uint32_t hnamebufLen,
				 char *osrelbuf, uint32_t osrelbufLen)
{
	if (V_VT(vtVar) != (VT_ARRAY | VT_BSTR)) {
		return;
	}
	LONG lstart, lend;
	LONG idx = -1;
	HRESULT hr;
	BSTR* pbstr;
	SAFEARRAY *sa = V_ARRAY(vtVar);

	// Get the lower and upper bound
	hr = SafeArrayGetLBound(sa, 1, &lstart);
	if (FAILED(hr)) {
		return;
	}
	hr = SafeArrayGetUBound(sa, 1, &lend);
	if (FAILED(hr)) {
		return;
	}
	// loop
	hr = SafeArrayAccessData(sa, (void HUGEP**)&pbstr);
	if (SUCCEEDED(hr))
	{
		for (idx=lstart; idx <= lend; idx++) {		
			BSTR s;
			s = pbstr[idx];
			// s now contains the item at position idx in the array
			//printf("***parseKvpXml: Item=%S\n", s);
			IXmlReader *xmlReader = NULL;
			ISequentialStream *xmlStream = NULL;
			xmlStream = new CStringStream(s);
			if (FAILED(hr = CreateXmlReader(__uuidof(IXmlReader), (void **)&xmlReader, NULL))) {
				myLog(LOG_ERR, "parseKvpXml: error creating xml reader 0x%x", hr);
				return;
			}
			if (FAILED(hr = xmlReader->SetInput(xmlStream))) {
				myLog(LOG_ERR, "parseKvpXml: Error setting input for reader 0x%x", hr);
				return;
			}
			if (S_OK == xmlReader->Read(NULL)) {
				readXmlInstance(xmlReader, hid, hnamebuf, hnamebufLen, osrelbuf, osrelbufLen);
			}
			if (xmlReader) {
				xmlReader->Release();
			}
		}
	}
	hr = SafeArrayUnaccessData(sa);	
}

/**
 * Functions to manipulate HVSVmState
 */

/**
 * Frees any strings or other memory allocations associated with
 * HVSVmState then frees the structure.
 */
void freeVmState(HVSVmState * state)
{
	if (state->vmName != NULL) {
		my_free(state->vmName);
	}
	if (state->vmFriendlyName != NULL) {
		my_free(state->vmFriendlyName);
	}
	if (state->disks != NULL) {
		wcsArrayFree(state->disks);
	}
	my_free(state);
}

static void readVmHidCounters(HVSVmState *state, SFLHost_hid_counters *hid,
							  char *hnamebuf, uint32_t hnamebufLen,
							  char *osrelbuf, uint32_t osrelbufLen)
{
	BSTR path = SysAllocString(WMI_VIRTUALIZATION_NS_V1);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;

	hr = connectToWMI(path, &pNamespace);
	SysFreeString(path);
	if (WBEM_S_NO_ERROR != hr) {
		myLog(LOG_ERR,"readVmHidCounters connectToWMI failed for namespace %S", path);
	} else {
		BSTR queryLang = SysAllocString(L"WQL");
		wchar_t *queryFormat = L"SELECT * FROM Msvm_KvpExchangeComponent WHERE SystemName=\"%s\"";
		size_t length = wcslen(queryFormat) + wcslen(state->vmName)+1;
		wchar_t *query = (wchar_t *)my_calloc(length * sizeof(wchar_t));
		swprintf_s(query, length, queryFormat, state->vmName); 
		IEnumWbemClassObject *kvpEnum = NULL;
		hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &kvpEnum);
		my_free(query);
		if (SUCCEEDED(hr)) {
			IWbemClassObject *kvpObj;
			ULONG kvpCount;
			hr = kvpEnum->Next(WBEM_INFINITE, 1, &kvpObj, &kvpCount);
			if (0 != kvpCount) {
				VARIANT items;
				if (WBEM_S_NO_ERROR == kvpObj->Get(L"GuestIntrinsicExchangeItems", 0, &items, 0, 0)) {
					parseKvpXml(&items, hid, hnamebuf, hnamebufLen, osrelbuf, osrelbufLen);
				}
				VariantClear(&items);
			}
			kvpEnum->Release();
		}
		pNamespace->Release();
		CoUninitialize();
		SysFreeString(queryLang);
	}
	//now fill in the rest...
	memcpy(hid->uuid, state->uuid, 16);
	hid->machine_type = SFLMT_unknown;
	if (hid->hostname.str == NULL || hid->hostname.len == 0) {
		wchar_t punycode[SFL_MAX_HOSTNAME_CHARS+1];
		if (IdnToAscii(0, state->vmFriendlyName, -1, punycode, SFL_MAX_HOSTNAME_CHARS) == 0) {
			hid->hostname.str = "";
			hid->hostname.len = 0;
		} else {
			size_t hnLen;
			wcstombs_s(&hnLen, hnamebuf, hnamebufLen, punycode, wcslen(punycode));
			if (hnLen > 0) {
				hnLen--;
			}
			hid->hostname.str = hnamebuf;
			hid->hostname.len = (uint32_t)hnLen;
		}
	}
	if (hid->os_release.str == NULL) {
		hid->os_release.str = "";
		hid->os_release.len = 0;
	}
	if (LOG_INFO <= debug) {
		u_char uuid[17];
		printHex(hid->uuid, 8, uuid, 17, FALSE);
		myLog(LOG_INFO, "readVmHidCounters(%S):\n\thostname:\t%s\n\tUUID:\t%s\n\tosName:\t%u\n\tosRelease:\t%s",
			  state->vmFriendlyName, hid->hostname.str, uuid, hid->os_name, hid->os_release.str); 
	}
}

static void readVmCpuCounters(HVSVmState *state, SFLHost_vrt_cpu_counters *cpu)
{
	PDH_HQUERY query;
	PDH_HCOUNTER counter;
	if (makeSingleCounterQuery(VCPU_COUNTER_OBJECT, 
							   COUNTER_INSTANCE_ALL, 
							   VCPU_COUNTER_CPU_TIME, 
							   &query, &counter) == ERROR_SUCCESS &&
		PdhCollectQueryData(query) == ERROR_SUCCESS) {
		PPDH_RAW_COUNTER_ITEM_W values;
		uint32_t count = 0;
		count = getRawCounterValues(&counter, &values);
		uint32_t cpuCount = 0;
		if (count > 0) {
			wchar_t *formatString = L"%s:";
			size_t length = wcslen(state->vmFriendlyName)+2;
			wchar_t *counterPrefix = (wchar_t *)my_calloc(length*sizeof(wchar_t));
			swprintf(counterPrefix, length, formatString, state->vmFriendlyName);
			cleanCounterName(counterPrefix, UTHYPERV_VIRT_PROC);
			for (uint32_t i = 0; i < count; i++) {
				if (StrStrIW(values[i].szName, counterPrefix) != NULL) {
					//Time in 100ns units, divide by 10000 for ms
					cpu->cpuTime += (uint32_t)(values[i].RawValue.FirstValue/tick_to_ms);
					cpuCount++;
				}
			}
			my_free(counterPrefix);
			my_free(values);
		}
		if (query != NULL) {
			PdhCloseQuery(query);
		}
		cpu->nrVirtCpu = cpuCount;
	}
	cpu->state = SFL_VIR_DOMAIN_NOSTATE;
	if (LOG_INFO <= debug) {
		myLog(LOG_INFO, "readVmCpuCounters(%S):\n\tcpuTime:\t%lu\n\tnrCpu:\t\t%lu\n", 
			  state->vmFriendlyName, cpu->cpuTime, cpu->nrVirtCpu);
	}
}

/**
 * Populates SFLHost_vrt_mem_counters structure from the Hyper-V Dynamic Memory VM
 * performance counters:
 * memory=(Physical Memory *1024*1024) * (Current Pressure / 100)
 * maxMemory = Guest Visible Physical Memory *1024*1024
 * For VMs with dynamic memory enabled, Guest Visible Physical Memory is OK, but
 * memory demand is not available (ie current pressure is 0).
 * We could use WMI (Msvm_MemorySettingData.DynamicMemoryEnabled=false and
 * Msvm_MemorySettingData.VirtualQuantity=Startup RAM for maxMemory) to detect
 * if the vm is not using dynamic memory and save maxMemory for later use here,
 * but it seems simpler (and more efficient) just to get the counters here with
 * PDH.
 */ 
static void readVmMemCounters(HVSVmState *state, SFLHost_vrt_mem_counters *mem)
{
	wchar_t *counterName = my_wcsdup(state->vmFriendlyName);
	cleanCounterName(counterName, UTHYPERV_DYN_MEM_VM);
	PDH_HQUERY query;
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS) {
		PDH_HCOUNTER physical, pressure, max;
		if (addCounterToQuery(VMEM_COUNTER_OBJECT, counterName, VMEM_COUNTER_PHYS, &query, &physical) == ERROR_SUCCESS &&
			addCounterToQuery(VMEM_COUNTER_OBJECT, counterName, VMEM_COUNTER_PRESSURE, &query, &pressure) == ERROR_SUCCESS &&
			addCounterToQuery(VMEM_COUNTER_OBJECT, counterName, VMEM_COUNTER_MAX, &query, &max) == ERROR_SUCCESS &&
			PdhCollectQueryData(query) == ERROR_SUCCESS) {
			uint64_t physMem = getRawCounterValue(&physical)*1024*1024;
			mem->memory = physMem*getRawCounterValue(&pressure)/100;
			if (mem->memory == 0) {
				//assume current pressure == 0 indicates the dynamic memory is disabled or not supported
				//in which case we can't measure memory used.
				mem->memory = UNKNOWN_GAUGE_64;
			}
			mem->maxMemory = getRawCounterValue(&max)*1024*1024;
		}
		PdhCloseQuery(query);
	}
	my_free(counterName);
	if (LOG_INFO <= debug) {
		myLog(LOG_INFO, "readVmMemCounters(%S): maxMemory=%llu memory=%llu", 
			  state->vmFriendlyName, mem->maxMemory, mem->memory);
	}
}

static uint64_t getVmDioCounterVal(HVSVmState *state, PDH_HCOUNTER *counter)
{
	uint64_t counterVal = 0;
	PPDH_RAW_COUNTER_ITEM_W values;
	uint32_t count = 0;
	count = getRawCounterValues(counter, &values);
	if (count > 0) {
		for (uint32_t i = 0; i < state->disks->n; i++) {
			wchar_t *disk = my_wcsdup(state->disks->strings[i]);
			cleanCounterName(disk, UTHYPERV_VIRT_STORAGE_DEV);
			for (uint32_t j = 0; j < count; j++) {	
				if (wcscmp(values[j].szName, disk) == 0) {
					counterVal += values[j].RawValue.FirstValue;
				}
			}
			my_free(disk);
		}
		my_free(values);
	}
	return counterVal;
}

/**
 * Populates SFLHost_vrt_dsk_counters structure from the Hyper-V Virtual Storage Device
 * performance counters for disk IO and used the OpenVirtualDisk function for capacity
 * and allocation.
 * OpenVirtualDisk is called with OPEN_VIRTUAL_DISK_VERSION_2 which gives better file 
 * sharing support and avoids access violation errors, however, this is not available
 * before Windows 8, in which case capacity and allocation will be 0.
 * VMs configured with physical disks are not supported.
 */
static void readVmDioCounters(HVSVmState *state, SFLHost_vrt_dsk_counters *dio)
{
	if (state->disks == NULL || state->disks->n == 0) {
		return;
	}
	PDH_HQUERY query;
	PDH_HCOUNTER readBytes, writeBytes, reads, writes, errors;
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS &&
		addCounterToQuery(VDISK_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VDISK_COUNTER_READ_BYTES,
						  &query, &readBytes) == ERROR_SUCCESS && 
		addCounterToQuery(VDISK_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VDISK_COUNTER_WRITE_BYTES,
						  &query, &writeBytes) == ERROR_SUCCESS &&
		addCounterToQuery(VDISK_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VDISK_COUNTER_READS,
						  &query, &reads) == ERROR_SUCCESS &&
		addCounterToQuery(VDISK_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VDISK_COUNTER_WRITES,
						  &query, &writes) == ERROR_SUCCESS &&
		addCounterToQuery(VDISK_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VDISK_COUNTER_ERRORS,
						  &query, &errors) == ERROR_SUCCESS &&
		PdhCollectQueryData(query) == ERROR_SUCCESS) {
		dio->rd_bytes = getVmDioCounterVal(state, &readBytes);
		dio->wr_bytes = getVmDioCounterVal(state, &writeBytes);
		dio->rd_req = (uint32_t)getVmDioCounterVal(state, &reads);
		dio->wr_req = (uint32_t)getVmDioCounterVal(state, &writes);
		dio->errs = (uint32_t)getVmDioCounterVal(state, &errors);
		if (query != NULL) {
			PdhCloseQuery(query);
		}
	}
	uint64_t capacity = 0;
	uint64_t allocation = 0;
	for (uint32_t i = 0; i < state->disks->n; i++) {
		HANDLE hVhd;
		VIRTUAL_STORAGE_TYPE storageType = {
			VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
			VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
		};
		OPEN_VIRTUAL_DISK_PARAMETERS parameters = {};
		parameters.Version = OPEN_VIRTUAL_DISK_VERSION_2;
		parameters.Version2.GetInfoOnly = TRUE;
		wchar_t *vhd = state->disks->strings[i];
		DWORD retVal = OpenVirtualDisk(&storageType, vhd,
									   VIRTUAL_DISK_ACCESS_NONE, 
									   OPEN_VIRTUAL_DISK_FLAG_NONE, &parameters, &hVhd);
		if (ERROR_SUCCESS == retVal) {
			GET_VIRTUAL_DISK_INFO info;
			ULONG infoSize = (ULONG)sizeof(GET_VIRTUAL_DISK_INFO);
			ULONG sizeUsed;
			info.Version = GET_VIRTUAL_DISK_INFO_SIZE;
			retVal = GetVirtualDiskInformation(hVhd, &infoSize, &info, &sizeUsed);
			if (ERROR_SUCCESS == retVal) {
				capacity += info.Size.VirtualSize;
				allocation += info.Size.PhysicalSize;
			}
			CloseHandle(hVhd);
		}
	}
	dio->capacity = capacity;
	dio->allocation = allocation;
	//dio->available = UNKNOWN_GAUGE_64; really dio->physical - size of physical disk containing image
	if (LOG_INFO <= debug) {
		myLog(LOG_INFO, "readVmDioCounters(%S):\n\trd_bytes:\t%llu\n\twr_bytes:\t%llu\n"
			"\trd_req:\t\t%lu\n\twr_req:\t\t%lu\n\terrors:\t\t%lu\n"
			"\tcapacity:\t%llu\n\tallocation:\t%llu",
			state->vmFriendlyName, dio->rd_bytes, dio->wr_bytes, 
			dio->rd_req, dio->wr_req, dio->errs, dio->capacity, dio->allocation);
	}
}

static uint64_t getVmNioCounterVal(HVSVmState *state, PDH_HCOUNTER *counter)
{
	uint64_t counterVal = 0;
	PPDH_RAW_COUNTER_ITEM_W values;
	uint32_t count = 0;
	count = getRawCounterValues(counter, &values);
	if (count > 0) {
		for (uint32_t i = 0; i < count; i++) {
			if (StrStrIW(values[i].szName, state->vmName) != NULL) {
				counterVal += values[i].RawValue.FirstValue;
			}
		}
		my_free(values);
	}
	return counterVal;
}

static void readVmNioCounters(HVSVmState *state, SFLHost_nio_counters *nio)
{
	PDH_HQUERY query;
	PDH_HCOUNTER bytesIn, bytesOut, pktsIn, pktsOut, dropsIn, dropsOut;
	if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS &&
		addCounterToQuery(VNIO_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VNIO_COUNTER_BYTES_IN, 
						  &query, &bytesIn) == ERROR_SUCCESS &&
		addCounterToQuery(VNIO_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VNIO_COUNTER_BYTES_OUT, 
						  &query, &bytesOut) == ERROR_SUCCESS &&
		addCounterToQuery(VNIO_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VNIO_COUNTER_PACKETS_IN, 
						  &query, &pktsIn) == ERROR_SUCCESS &&
		addCounterToQuery(VNIO_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VNIO_COUNTER_PACKETS_OUT, 
						  &query, &pktsOut) == ERROR_SUCCESS &&
		addCounterToQuery(VNIO_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VNIO_COUNTER_DISCARDS_IN, 
						  &query, &dropsIn) == ERROR_SUCCESS &&
		addCounterToQuery(VNIO_COUNTER_OBJECT, 
						  COUNTER_INSTANCE_ALL, 
						  VNIO_COUNTER_DISCARDS_OUT, 
						  &query, &dropsOut) == ERROR_SUCCESS &&
		PdhCollectQueryData(query) == ERROR_SUCCESS) {
		nio->bytes_in = getVmNioCounterVal(state, &bytesIn);
		nio->bytes_out = getVmNioCounterVal(state, &bytesOut);
		nio->pkts_in = (uint32_t)getVmNioCounterVal(state, &pktsIn);
		nio->pkts_out = (uint32_t)getVmNioCounterVal(state, &pktsOut);
		nio->drops_in = (uint32_t)getVmNioCounterVal(state, &dropsIn);
		nio->drops_out = (uint32_t)getVmNioCounterVal(state, &dropsOut);
		if (query) {
			PdhCloseQuery(query);
		}
	}
	nio->errs_in = UNKNOWN_COUNTER;
	nio->errs_out = UNKNOWN_COUNTER;
	if (LOG_INFO <= debug) {
		myLog(LOG_INFO, "readVmNioCounters(%S):\n\tbytes_in:\t%llu\n\tbytes_out:\t%llu\n"
			"\tpkts_in:\t%lu\n\tpkts_out:\t%lu\n\tdrops_in:\t%lu\n\tdrops_out:\t%lu\n",
			state->vmFriendlyName, nio->bytes_in, nio->bytes_out, 
			nio->pkts_in, nio->pkts_out, nio->drops_in, nio->drops_out);
	}
}

static SFLAdaptorList *getVmAdaptors(HSP *sp, HVSVmState *state, SFLAdaptorList *vmAdaptors)
{
	wchar_t *vmName = state->vmName;
	if (sp->vAdaptorList != NULL) {
		for (uint32_t i = 0; i < sp->vAdaptorList->num_adaptors; i++) {
			SFLAdaptor *adaptor = sp->vAdaptorList->adaptors[i];
			wchar_t *adVmName = ((HVSVPortInfo *)adaptor->userData)->vmSystemName;
			if (adVmName != NULL && StrCmpIW(vmName, adVmName) == 0 &&
				vmAdaptors->num_adaptors < vmAdaptors->capacity) {
				vmAdaptors->adaptors[vmAdaptors->num_adaptors++] = adaptor;
			}
		}
	}
	return vmAdaptors;
}

void getCounters_vm(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
	assert(poller->magic);
	HVSVmState *state = (HVSVmState *)poller->userData;
	if (state == NULL) {
		return;
	}
	HSP *sp = (HSP *)poller->magic;
	
	// host ID
	SFLCounters_sample_element hidElem = { 0 };
	hidElem.tag = SFLCOUNTERS_HOST_HID;
	char hnamebuf[SFL_MAX_HOSTNAME_CHARS+1];
	memset(hnamebuf, 0, SFL_MAX_HOSTNAME_CHARS+1);
	char osrelbuf[SFL_MAX_OSRELEASE_CHARS+1];
	memset(osrelbuf, 0, SFL_MAX_OSRELEASE_CHARS+1);
	readVmHidCounters(state, &hidElem.counterBlock.host_hid, 
					  hnamebuf, SFL_MAX_HOSTNAME_CHARS, 
					  osrelbuf, SFL_MAX_OSRELEASE_CHARS);
	SFLADD_ELEMENT(cs, &hidElem);

	//host parent
	SFLCounters_sample_element parElem = { 0 };
	parElem.tag = SFLCOUNTERS_HOST_PAR;
	parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
	parElem.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
	SFLADD_ELEMENT(cs, &parElem);

	//VM Network IO
	SFLCounters_sample_element nioElem = { 0 };
	nioElem.tag = SFLCOUNTERS_HOST_VRT_NIO;
	readVmNioCounters(state, &nioElem.counterBlock.host_nio);
	SFLADD_ELEMENT(cs, &nioElem);

	//VM DiskIO
	SFLCounters_sample_element dioElem = { 0 };
	dioElem.tag = SFLCOUNTERS_HOST_VRT_DSK;
	readVmDioCounters(state, &dioElem.counterBlock.host_vrt_dsk);
	SFLADD_ELEMENT(cs, &dioElem);

	//VM memory
	SFLCounters_sample_element memElem = { 0 };
	memElem.tag = SFLCOUNTERS_HOST_VRT_MEM;
	readVmMemCounters(state, &memElem.counterBlock.host_vrt_mem);
	SFLADD_ELEMENT(cs, &memElem);

	//VM CPU
	SFLCounters_sample_element cpuElem = {0 };
	cpuElem.tag = SFLCOUNTERS_HOST_VRT_CPU;
	readVmCpuCounters(state, &cpuElem.counterBlock.host_vrt_cpu);
	SFLADD_ELEMENT(cs, &cpuElem);

	//VM adaptors
	SFLCounters_sample_element adaptorsElem = { 0 };
	adaptorsElem.tag = SFLCOUNTERS_ADAPTORS;
	SFLAdaptorList vmAdaptors;
	SFLAdaptor *adaptors[HSP_MAX_VIFS];
	vmAdaptors.adaptors = adaptors;
	vmAdaptors.capacity = HSP_MAX_VIFS;
	vmAdaptors.num_adaptors = 0;
	adaptorsElem.counterBlock.adaptors = getVmAdaptors(sp, state, &vmAdaptors);
	SFLADD_ELEMENT(cs, &adaptorsElem);

	sfl_poller_writeCountersSample(poller, cs);
}

/**
 * Used to discover the virtual adaptors used by a vm and map to associated switch
 * ports. As new adaptors the HSP->vAdaptors if they don't already exist
 * (from discovery via the sFlow filter or previous vm enumeration).
 */
void readVmAdaptors(HSP *sp, IWbemServices *pNamespace, wchar_t *vmName)
{
	HRESULT hr = S_FALSE;

	BSTR queryLang = SysAllocString(L"WQL");
	wchar_t *queryFormat(L"SELECT * FROM %s WHERE SystemName=\"%s\"");
	uint32_t portTypeCount = 2;
	wchar_t *portTypes[2];
	portTypes[0] = L"Msvm_SyntheticEthernetPort";
	portTypes[1] = L"Msvm_EmulatedEthernetPort";
	IEnumWbemClassObject *portEnum = NULL;
	for (uint32_t i = 0; i < portTypeCount; i++) {
		size_t length = wcslen(queryFormat)+wcslen(portTypes[i])+wcslen(vmName);
		wchar_t *query = (wchar_t *)my_calloc(length*sizeof(wchar_t));
		swprintf_s(query, length, queryFormat, portTypes[i], vmName);
		hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &portEnum);
		if (FAILED(hr)) {	
			myLog(LOG_ERR,"readVmAdaptors: ExecQuery() failed for query %S error=0x%x", query, hr);
			my_free(query);
			break;
		}
		my_free(query);
		hr = WBEM_S_NO_ERROR;
		while (WBEM_S_NO_ERROR == hr) {
			IWbemClassObject *portObj = NULL;
			ULONG portCount = 0;
			hr = portEnum->Next(WBEM_INFINITE, 1, &portObj, &portCount);
			if (0 == portCount) {
				break;
			}
			if (sp->vAdaptorList == NULL) {
				sp->vAdaptorList = adaptorListNew();
			}
			HRESULT assocHr;
			IEnumWbemClassObject *lanEpEnum = NULL;
			assocHr = associatorsOf(pNamespace, portObj,
									L"Msvm_DeviceSAPImplementation",
									L"Msvm_VmLANEndPoint",
									L"Dependent", &lanEpEnum);
			if (SUCCEEDED(assocHr)) {
				IWbemClassObject *lanEpObj;
				ULONG epCount = 0;
				assocHr = lanEpEnum->Next(WBEM_INFINITE, 1, &lanEpObj, &epCount);
				if (epCount == 1) {
					IEnumWbemClassObject *swPortEnum = NULL;
					assocHr = associatorsOf(pNamespace, lanEpObj,
											L"Msvm_ActiveConnection",
											L"Msvm_SwitchPort",
											L"Antecedent", &swPortEnum);
					if (SUCCEEDED(assocHr)) {
						IWbemClassObject *swPortObj = NULL;
						ULONG swPortCount = 0;
						assocHr = swPortEnum->Next(WBEM_INFINITE, 1, &swPortObj, &swPortCount);
						if (swPortCount == 1) {
							wchar_t *guidString = stringFromWMIProperty(swPortObj, PROP_NAME);
							if (guidString != NULL) {
								char portGuid[FORMATTED_GUID_LEN+1];
								guidToString(guidString, (UCHAR *)portGuid, FORMATTED_GUID_LEN);
								my_free(guidString);
								SFLAdaptor *vAdaptor = adaptorListGet(sp->vAdaptorList, portGuid);
								if (vAdaptor == NULL) {
									char uuid[16];
									hexToBinary((UCHAR *)portGuid, (UCHAR *)uuid, 33);
									uint32_t ifIndex = assign_dsIndex(&sp->portStore, 
																	  uuid, &sp->maxIfIndex, 
																	  &sp->portStoreInvalid);
									vAdaptor = addVAdaptor(sp->vAdaptorList, portGuid, ifIndex);
								}
								vAdaptor->marked = FALSE;
								wchar_t *speedString = stringFromWMIProperty(portObj, PROP_SPEED);
								if (speedString != NULL) {
									ULONGLONG ifSpeed = _wcstoui64(speedString, NULL, 10);
									vAdaptor->ifSpeed = ifSpeed;
									my_free(speedString);
								}
								wchar_t *macString = stringFromWMIProperty(portObj, PROP_MAC_ADDR);
								if (macString != NULL) {
									vAdaptor->num_macs = 1;
									wchexToBinary(macString, vAdaptor->macs[0].mac, 13);
									my_free(macString);
								}
								HVSVPortInfo *portInfo = (HVSVPortInfo *)vAdaptor->userData;
								wchar_t *sysName = stringFromWMIProperty(portObj, PROP_SYSTEM_NAME);
								if (sysName != NULL) {
									if (portInfo->vmSystemName != NULL) {
										my_free(portInfo->vmSystemName);
									}
									portInfo->vmSystemName = sysName;
								}
								wchar_t *switchName = stringFromWMIProperty(swPortObj, PROP_SYSTEM_NAME);
								if (switchName != NULL) {
									if (portInfo->switchName) {
										my_free(portInfo->switchName);
									}
									portInfo->switchName = switchName;
								}
								if (LOG_INFO <= debug) {
									u_char macAddr[13];
									if (vAdaptor->num_macs > 0 && vAdaptor->macs) {
										printHex(vAdaptor->macs[0].mac, 6, macAddr, 13, FALSE);
									}
									myLog(LOG_INFO, 
										"readVmAdaptors: updated vAdaptor ifIndex=%u switchPortName=%s ifSpeed=%llu MAC=%s vmName=%S\n", 
										vAdaptor->ifIndex, vAdaptor->deviceName, vAdaptor->ifSpeed, macAddr, portInfo->vmSystemName);
								}
							}
							swPortObj->Release();
						}
					}
					swPortEnum->Release();
				}
				lanEpObj->Release();
			}
			portObj->Release();
			lanEpEnum->Release();
		}
		portEnum->Release();
	}
	SysFreeString(queryLang);
}

void readVmDisks(IWbemServices *pNamespace, IWbemClassObject *vmObj, HVSVmState *state)
{
	IEnumWbemClassObject *diskEnum;
	HRESULT diskHr = associatorsOf(pNamespace, vmObj,
								   L"Msvm_SystemDevice",
								   L"Msvm_LogicalDisk",
								   L"PartComponent", &diskEnum);
	if (SUCCEEDED(diskHr)) {
		IWbemClassObject *diskObj;
		ULONG diskCount;
		while (WBEM_S_NO_ERROR == diskHr) {
			diskHr = diskEnum->Next(WBEM_INFINITE, 1, &diskObj, &diskCount);
			if (diskCount == 0) {
				break;
			}
			IEnumWbemClassObject *diskSettingEnum;
			HRESULT settingHr = associatorsOf(pNamespace, diskObj,
											  L"Msvm_ElementSettingData",
											  L"Msvm_ResourceAllocationSettingData",
											  L"SettingData", &diskSettingEnum);
			if (SUCCEEDED(settingHr)) {
				IWbemClassObject *settingObj;
				ULONG settingCount;
				settingHr = diskSettingEnum->Next(WBEM_INFINITE, 1, &settingObj, &settingCount);
				if (SUCCEEDED(settingHr) && settingCount == 1) {
					VARIANT connection;
					if (WBEM_S_NO_ERROR == settingObj->Get(L"Connection", 0, &connection, 0, 0) &&
						V_VT(&connection) == (VT_ARRAY | VT_BSTR)) {
						SAFEARRAY *sa = V_ARRAY(&connection);
						LONG lstart, lend;
						SafeArrayGetLBound(sa, 1, &lstart);
						SafeArrayGetUBound(sa, 1, &lend);
						if (lstart <= lend) {
							BSTR *pbstr;
							settingHr = SafeArrayAccessData(sa, (void HUGEP **)&pbstr);
							if (SUCCEEDED(settingHr)) {
								wchar_t *disk = my_wcsdup(pbstr[lstart]);
								if (wcsArrayIndexOf(state->disks, disk) == -1) {
									wcsArrayAdd(state->disks, disk);
								}
								my_free(disk);
							}
							SafeArrayUnaccessData(sa);
						}
					}
					VariantClear(&connection);
					settingObj->Release();					
				}
				diskSettingEnum->Release();
			}
			diskObj->Release();
		}
		diskEnum->Release();
	}
}

void readVms(HSP *sp)
{
	HSPSFlow *sf = sp->sFlow;
	if (sf != NULL && sf->agent != NULL) {
		// mark and sweep
		// 1a. mark all the current virtual machine pollers
		for (SFLPoller *poller = sf->agent->pollers; poller != NULL; poller = poller->nxt) {
			if (SFL_DS_CLASS(poller->dsi) == SFL_DSCLASS_LOGICAL_ENTITY) {
				HVSVmState *state = (HVSVmState *)poller->userData;
				state->marked = TRUE;
			}
		}
		// 1b. mark all the adaptors
		if (sp->vAdaptorList == NULL) {
			sp->vAdaptorList = adaptorListNew();
		}
		adaptorListMarkAll(sp->vAdaptorList);
		
		// 2. create new VM pollers, or clear the mark on existing ones
		BSTR path = SysAllocString(WMI_VIRTUALIZATION_NS_V1);
		HRESULT hr = S_FALSE;
		IWbemServices *pNamespace = NULL;

		hr = connectToWMI(path, &pNamespace);
		SysFreeString(path);
		if (WBEM_S_NO_ERROR != hr) {
			myLog(LOG_ERR,"readVms: connectToWMI failed for namespace %S", path);
		} else {
			BSTR queryLang = SysAllocString(L"WQL");
			//libvirt uses EnabledState!=0 AND EnabledState!=3 and EnabledState!=32768 (!unknown !disabled !suspended)
			//use Description since this is locale independent
			wchar_t *query1 = L"SELECT * FROM Msvm_ComputerSystem WHERE Description=\"Microsoft Virtual Machine\" AND EnabledState=2";
			IEnumWbemClassObject *vmEnum = NULL;
			hr = pNamespace->ExecQuery(queryLang, query1, WBEM_FLAG_FORWARD_ONLY, NULL, &vmEnum);
			if (!SUCCEEDED(hr)) {
				myLog(LOG_ERR,"readVms: ExecQuery() failed for query %S error=0x%x", query1, hr);
				sp->num_partitions = 0;
			} else {
				wchar_t *query2 = L"SELECT * FROM Msvm_VirtualSystemSettingData WHERE SettingType=3 AND InstanceID=\"Microsoft:%s\"";
				IWbemClassObject *vmObj = NULL;
				IEnumWbemClassObject *vssdEnum = NULL;
				IWbemClassObject *vssdObj = NULL;
				time_t now = time(NULL);
				uint32_t numPartitions = 0;

				hr = WBEM_S_NO_ERROR;
				while (WBEM_S_NO_ERROR == hr) {
					ULONG vmCount = 1;
					hr = vmEnum->Next(WBEM_INFINITE, 1, &vmObj, &vmCount);
					if (0 == vmCount) {
						break;
					}
					numPartitions++;
					wchar_t *vmName = stringFromWMIProperty(vmObj, PROP_NAME);
					if (vmName != NULL) {
						//get the adaptor and switch port info for the vm
						readVmAdaptors(sp, pNamespace, vmName);
						size_t length = wcslen(vmName)+1+wcslen(query2)+1;
						wchar_t *vmQuery = (wchar_t *)my_calloc(length*sizeof(wchar_t));
						swprintf_s(vmQuery, length, query2, vmName);
						hr = pNamespace->ExecQuery(queryLang, vmQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &vssdEnum);
						if (!SUCCEEDED(hr)) {
							myLog(LOG_ERR,"readVms: ExecQuery() failed for query: %S error=0x%x", vmQuery, hr);
							my_free(vmQuery);
						} else {
							my_free(vmQuery);
							ULONG settingCount;
							hr = vssdEnum->Next(WBEM_INFINITE, 1, &vssdObj, &settingCount);
							if (0 != settingCount) {
								BOOL noUUID = true;
								wchar_t *biosGuidString = NULL;
								while (vssdObj && noUUID) {
									biosGuidString = stringFromWMIProperty(vssdObj, PROP_BIOS_GUID);
									noUUID = false;
								}
								if (biosGuidString != NULL) { 
									char uuid[16];
									wchexToBinary(biosGuidString, (UCHAR *)uuid, 33);
									my_free(biosGuidString);
									wchar_t *friendlyName = stringFromWMIProperty(vmObj, PROP_ELEMENT_NAME);
									VARIANT processVal;
									uint32_t processId = 0;
									hr = vmObj->Get(PROP_PROCESS, 0, &processVal, 0, 0);
									if (WBEM_S_NO_ERROR == hr && 
										(V_VT(&processVal) == VT_I4 || V_VT(&processVal) == VT_UI4)) {
										processId = processVal.ulVal;
									}
									VariantClear(&processVal);

									uint32_t dsIndex = assign_dsIndex(&sp->vmStore, uuid, &sp->maxDsIndex, &sp->vmStoreInvalid);
									SFLDataSource_instance dsi;
									// ds_class = <virtualEntity>, ds_index = offset + <assigned>, ds_instance = 0
									SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, HSP_DEFAULT_LOGICAL_DSINDEX_START + dsIndex, 0);
									SFLPoller *vpoller = sfl_agent_addPoller(sf->agent, &dsi, sp, agentCB_getCounters);
									HVSVmState *state = (HVSVmState *)vpoller->userData;
									if (state != NULL) {
										// We already know about this VM, so just clear the mark
										state->marked = FALSE;
										//Reset info we are about to refresh
										state->processId = processId;
										if (state->vmName != NULL) {
											my_free(state->vmName);
										}
										state->vmName = vmName;
										if (state->vmFriendlyName != NULL) {
											my_free(state->vmFriendlyName);
										}
										state->vmFriendlyName = friendlyName;
										state->timestamp = now;
									} else {
										//found a new vm
										uint32_t pollingInterval = sf->sFlowSettings ? 
										sf->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
										if (pollingInterval > 0) {
											sfl_poller_set_sFlowCpInterval(vpoller, pollingInterval);
											sfl_poller_set_sFlowCpReceiver(vpoller, HSP_SFLOW_RECEIVER_INDEX);
											// hang a new HVSVmState object on the userData hook
											state = (HVSVmState *)my_calloc(sizeof(HVSVmState));
											state->marked = FALSE;
											state->processId = processId;
											state->vmName = vmName;
											state->vmFriendlyName = friendlyName;
											memcpy(state->uuid, uuid, 16);
											state->timestamp = now;
											vpoller->userData = state;
											state->disks = wcsArrayNew();
											//get the disk info
											readVmDisks(pNamespace, vmObj, state);
											if (LOG_INFO <= debug) {
												u_char uuidbuf[FORMATTED_GUID_LEN+1];
												printUUID(state->uuid, uuidbuf, FORMATTED_GUID_LEN);
												myLog(LOG_INFO, "readVms: adding vm at dsIndex=%u %S, %S, %s, %ul",
												SFL_DS_INDEX(vpoller->dsi),   
												state->vmFriendlyName, state->vmName, uuidbuf, state->processId);
											}
										} //pollingInterval > 0
									} //found new vm
								} //got biosGuid
							} //settingCount != 0
							vssdEnum->Release();
						} //finished with vssdEnum
					} //nmName != NULL
					vmObj->Release();
				} //while vmEnum->Next, assign vmObj
				vmEnum->Release();
				sp->num_partitions = numPartitions;				
			} //done with vmEnum
			pNamespace->Release();
			CoUninitialize();
			SysFreeString(queryLang);
		} //done with connection to WMI

		// 3a. remove any pollers that don't exist any more
		for (SFLPoller *poller = sf->agent->pollers; poller != NULL; poller = poller->nxt) {
			if (SFL_DS_CLASS(poller->dsi) == SFL_DSCLASS_LOGICAL_ENTITY) {
				HVSVmState *state = (HVSVmState *)poller->userData;
				if (state->marked) {
					myLog(LOG_INFO, "readVMs: removing poller with dsIndex=%u (vmName=%S, %S)",
						  SFL_DS_INDEX(poller->dsi),
						  state->vmName, state->vmFriendlyName);
					freeVmState(state);
					poller->userData = NULL;
					removeQueuedPoller(sp, poller);
					sfl_agent_removePoller(sf->agent, &poller->dsi);
					//TODO ageout the uuid from vmStore and write to persistent storage
				}
			}
		}
		// 3b. remove any vm only adaptors that don't exist any more
		for (uint32_t i = 0; i < sp->vAdaptorList->num_adaptors; i++) {
			SFLAdaptor *vAdaptor = sp->vAdaptorList->adaptors[i];
			if (vAdaptor->marked & ((HVSVPortInfo *)vAdaptor->userData)->filterEnabled) {
				vAdaptor->marked = FALSE;
			}
		}
		adaptorListFreeMarked(sp->vAdaptorList, freePortInfo);
	}
}

#if defined(__cplusplus)
} /* extern "C" */
#endif