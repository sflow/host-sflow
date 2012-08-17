/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "hypervSwitch.h"
#include "readWindowsEnglishCounters.h"
#include "sflowfilter.h"
//hsflowd.h includes winsock2.h which will suppress subsequent
//inclusion of winsock.h Since Objbase.h leads to inclusion of
//winsock.h need to include Objbase.h *after* hsflowd.h
#include <Objbase.h>
#include <Wbemidl.h>

extern int debug;

#define PROP_ELEMENT_NAME L"ElementName"
#define PROP_SYSTEM_NAME L"SystemName"
#define PROP_NAME L"Name"
#define PROP_SPEED L"Speed"

/**
 * Sets the counters instance name for the SFLAdaptor representing the switch port.
 * Currently this is <switch GUID>_<port GUID>,
 * Prior to build 8130 counters instance was <switch GUID>_<port friendly name>
 */
static void setPortCountersInstance(SFLAdaptor *switchPort)
{
	HVSVPortInfo *portInfo = (HVSVPortInfo *)switchPort->userData;
	if (portInfo->switchName == NULL) {
		if (portInfo->portCountersInstance != NULL) {
			my_free(portInfo->portCountersInstance);
			portInfo->portCountersInstance = NULL;
		}
	} else {
		wchar_t *formatString = L"%s_%S";
		size_t length = wcslen(portInfo->switchName)+strlen(switchPort->deviceName)+wcslen(formatString)+1;
		wchar_t *countersInstanceName = (wchar_t *)my_calloc(length*sizeof(wchar_t));
		swprintf_s(countersInstanceName, length, formatString, portInfo->switchName, switchPort->deviceName);
		if (portInfo->portCountersInstance != NULL) {
			my_free(portInfo->portCountersInstance);
		}
		portInfo->portCountersInstance = countersInstanceName;
	}
}

/**
 * Gets the switch port info from WMI (switch port friendly name, ifSpeed) 
 * and merges into the list of existing ports.
 */
void readWMISwitchPorts(HSP *sp)
{
	myLog(LOG_INFO, "entering readWMISwitchPorts");
	BSTR path = SysAllocString(WMI_VIRTUALIZATION_NS_V2);
	HRESULT hr = S_FALSE;
	IWbemServices *pNamespace = NULL;

	hr = connectToWMI(path, &pNamespace);
	if (FAILED(hr)) {
		//only try the v2 namespace since this will only be present
		//with the extensible switch that supports sampling.
	    //don't try to get counters if there is no sampling.
		SysFreeString(path);
		myLog(LOG_INFO, "readWMISwitchPorts: virtualization namespace v2 not found");
		return;
	} else {
		SysFreeString(path);
	}

	BSTR queryLang = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM Msvm_EthernetSwitchPort");
	IEnumWbemClassObject *switchPortEnum = NULL;
	hr = pNamespace->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY, NULL, &switchPortEnum);
	SysFreeString(queryLang);
	SysFreeString(query);
	if (FAILED(hr)) {
		myLog(LOG_ERR,"readWMISwitchPorts: ExecQuery() failed for query %S error=0x%x", query, hr);
		CoUninitialize();
		return;
	}

	if (sp->vAdaptorList == NULL) {
		sp->vAdaptorList = adaptorListNew();
	}
	IWbemClassObject *switchPortObj = NULL;

	hr = WBEM_S_NO_ERROR;
	while (WBEM_S_NO_ERROR == hr) {
		SFLAdaptor *vAdaptor = NULL;
		ULONG uReturned = 1;
		hr = switchPortEnum->Next(WBEM_INFINITE, 1, &switchPortObj, &uReturned);
		if (0 == uReturned) {
			break;
		}
		wchar_t *guidString = stringFromWMIProperty(switchPortObj, PROP_NAME);
		if (guidString != NULL) {
			char portGuid[FORMATTED_GUID_LEN+1];
			guidToString(guidString, (UCHAR *)portGuid, FORMATTED_GUID_LEN);
			myLog(LOG_INFO, "readWMISwitchPorts: portGuid=%s", portGuid);
			my_free(guidString);
			vAdaptor = adaptorListGet(sp->vAdaptorList, portGuid);
		}
		if (vAdaptor != NULL) {
			HVSVPortInfo *portInfo = (HVSVPortInfo *)vAdaptor->userData;
			wchar_t *switchName = stringFromWMIProperty(switchPortObj, PROP_SYSTEM_NAME);
			if (switchName != NULL) {
				if (portInfo->switchName != NULL) {
					my_free(portInfo->switchName);
				}
				portInfo->switchName = switchName;
			}
			wchar_t *friendlyName = stringFromWMIProperty(switchPortObj, PROP_ELEMENT_NAME);
			if (friendlyName != NULL) {
				if (portInfo->portFriendlyName != NULL) {
					my_free(portInfo->portFriendlyName);
				}
				portInfo->portFriendlyName = friendlyName;
			}
			setPortCountersInstance(vAdaptor);
			wchar_t *speedString = stringFromWMIProperty(switchPortObj, PROP_SPEED);
			if (speedString != NULL) {
				ULONGLONG ifSpeed = _wcstoui64(speedString, NULL, 10);
				vAdaptor->ifSpeed = ifSpeed;
				my_free(speedString);
			}
			//could also get ifDirection but FullDuplex=True always

			//Get the MACs and VM system name when we enumerate the vms.
			myLog(LOG_INFO, 
				  "readWMISwitchPorts: updated switch port %s %S portId=%u ifIndex=%u ifSpeed=%llu counterName=%S", 
				  vAdaptor->deviceName, portInfo->portFriendlyName, portInfo->portId, vAdaptor->ifIndex, 
				  vAdaptor->ifSpeed, portInfo->portCountersInstance);
		} else {
			myLog(LOG_INFO, "readWMISwitchPorts: vAdapter not found");
		}
		switchPortObj->Release();
	}
	switchPortEnum->Release();
	pNamespace->Release();
	CoUninitialize();
}

/**
 * If the polling interval is > 0, adds an interface counter poller to 
 * sp->sFlow->agent or the adaptor representing the switch port. Returns
 * the added poller, or NULL if a poller was not added.
 */
static SFLPoller *addPoller(HSP *sp, SFLAdaptor *adaptor)
{
	uint32_t pollingInterval = sp->sFlow->sFlowSettings ? 
		sp->sFlow->sFlowSettings->pollingInterval : SFL_DEFAULT_POLLING_INTERVAL;
	if (pollingInterval <= 0) {
		return NULL;
	}
	SFLDataSource_instance switchDsi;
	SFL_DS_SET(switchDsi, SFL_DSCLASS_IFINDEX, adaptor->ifIndex, 0); 
	SFLPoller *poller = sfl_agent_addPoller(sp->sFlow->agent, 
											&switchDsi, 
											sp, 
											agentCB_getCounters);
	// remember the deviceName to make the lookups easier later.
	// We don't point directly to the SFLAdaptor object
	// in case it gets freed at some point. The deviceName is enough.
	poller->userData = my_strdup(adaptor->deviceName);
	myLog(LOG_INFO, "addPoller: added counter poller for %lu %s", 
		  adaptor->ifIndex, adaptor->deviceName);
	sfl_poller_set_sFlowCpInterval(poller, pollingInterval);
	sfl_poller_set_sFlowCpReceiver(poller, HSP_SFLOW_RECEIVER_INDEX);
	return poller;
}

void removePoller(HSP *sp, SFLAdaptor *adaptor)
{
	SFLDataSource_instance dsi;
	SFL_DS_SET(dsi, SFL_DSCLASS_IFINDEX, adaptor->ifIndex, 0);
	SFLPoller *poller = sfl_agent_getPoller(sp->sFlow->agent, &dsi);
	if (poller != NULL) {
		if (poller->userData != NULL) {
			my_free(poller->userData);
		}
		removeQueuedPoller(sp, poller);
		sfl_agent_removePoller(sp->sFlow->agent, &dsi);
		myLog(LOG_INFO, "removePoller: removing poller with ifIndex=%u (portName=%s, %S)",
				  adaptor->ifIndex,
				  adaptor->deviceName, ((HVSVPortInfo *)adaptor->userData)->portFriendlyName);
	}
}

/**
 * Allocates space in the heap for a copy of the NDIS string,
 * copies the string and returns the new string.
 */
wchar_t *ndiswcsdup(PNDIS_IF_COUNTED_STRING pstr)
{
	if (pstr == NULL) {
		return NULL;
	}
	//convert to byte length to wchar, round up and null
	uint32_t length = (pstr->Length+1)/sizeof(wchar_t) + sizeof(wchar_t); 
	wchar_t *newStr = (wchar_t *)my_calloc(length*sizeof(wchar_t));
	memcpy(newStr, pstr->String, pstr->Length);
	return newStr;
}

/**
 * Updates the vAdaptor->userData (HVSVPortInfo) with the new switchName, 
 * freeing the old switch name if present.
 * Updates the countersInstance name for this port.
 */
void updatePortSwitchName(SFLAdaptor *switchPort, wchar_t *switchName)
{
	HVSVPortInfo *portInfo = (HVSVPortInfo *)switchPort->userData;
	if (portInfo->switchName != NULL) {
		my_free(portInfo->switchName);
	}
	portInfo->switchName = my_wcsdup(switchName);
	setPortCountersInstance(switchPort);
}

/**
 * Updates the switch port list with the information in pSwitchConfig
 * obtained from the filter.
 */
void updateSwitchPorts(HSP *sp, PAllSwitchesConfig config)
{
	if (config->revision <= sp->portInfoRevision) {
		return;
	}
	if (sp->vAdaptorList == NULL) {
		sp->vAdaptorList = adaptorListNew();
	} else {
		adaptorListMarkAll(sp->vAdaptorList);
	}
	PSwitchConfig switchConfig;
	for (uint32_t switchNum = 0; switchNum < config->numSwitches; switchNum++) {
		if (switchNum == 0) {
			switchConfig = GET_FIRST_SWITCH_CONFIG(config);
		} else {
			switchConfig = GET_NEXT_SWITCH_CONFIG(switchConfig);
		}
		wchar_t *switchName = ndiswcsdup(&switchConfig->switchName);
		uint64_t switchId = switchConfig->switchID;
		for (uint32_t portNum = 0; portNum < switchConfig->numPorts; portNum++) {
			PPortEntry portEntry = GET_PORT_ENTRY_AT(switchConfig, portNum);
			uint32_t portId = portEntry->portID;
			wchar_t *portName = ndiswcsdup(&portEntry->portName);
			char portGuid[FORMATTED_GUID_LEN+1];
			guidToString(portName, (UCHAR *)portGuid, FORMATTED_GUID_LEN);
			SFLAdaptor *switchPort = adaptorListGet(sp->vAdaptorList, portGuid);
			if (switchPort == NULL) {
				//new port so add to the vadaptor list
				//convert GUID to uuid format to look up ifIndex/dsIndex
				char uuid[16];
				hexToBinary((UCHAR *)portGuid, (UCHAR *)uuid, 33);
				uint32_t ifIndex = assign_dsIndex(&sp->portStore, uuid, &sp->maxIfIndex, &sp->portStoreInvalid);
				switchPort = addVAdaptor(sp->vAdaptorList, portGuid, ifIndex);
				HVSVPortInfo *portInfo = (HVSVPortInfo *)switchPort->userData;
				portInfo->filterEnabled = TRUE;
				portInfo->portId = portId;
				portInfo->revision = portEntry->revision;
				switchPort->marked = FALSE;
				updatePortSwitchName(switchPort, switchName);
				portInfo->switchId = switchConfig->switchID;
				myLog(LOG_INFO, "updateSwitchPorts: Added new portId=%u ifIndex=%u deviceName=%s switchId=%llu switchName=%S",
					portInfo->portId, switchPort->ifIndex, switchPort->deviceName, portInfo->switchId, portInfo->switchName);
				addPoller(sp, switchPort);
			} else {
				//we already know about this port, so make sure we have a poller
				//and the current info
				SFLDataSource_instance dsi;
				SFL_DS_SET(dsi, 0, switchPort->ifIndex, 0);
				SFLPoller *poller = sfl_agent_getPoller(sp->sFlow->agent, &dsi);
				if (poller == NULL) {
					poller = addPoller(sp, switchPort);
				}
				HVSVPortInfo *portInfo = (HVSVPortInfo *)switchPort->userData;
				if (portEntry->revision > portInfo->revision) {
					updatePortSwitchName(switchPort, switchName);
					portInfo->revision = portEntry->revision;
					if (poller != NULL) {
						sfl_poller_resetCountersSeqNo(poller);
					}
					myLog(LOG_INFO, "updateSwitchPorts: revision changed: portId=%u ifIndex=%u deviceName=%s switchId=%llu switchName=%S", 
						  portInfo->portId, switchPort->ifIndex, switchPort->deviceName, portInfo->switchId, portInfo->switchName);
				}
				portInfo->filterEnabled = TRUE;
				switchPort->marked = FALSE;
			}
			my_free(portName);
		}
		my_free(switchName);
	}
	//now sweep
	//remove the pollers for non-sampling ports
	for (uint32_t i = 0; i < sp->vAdaptorList->num_adaptors; i++) {
		SFLAdaptor *vAdaptor = sp->vAdaptorList->adaptors[i];
		if (vAdaptor->marked) {
			HVSVPortInfo *portInfo = (HVSVPortInfo *)vAdaptor->userData;
			if (portInfo->filterEnabled) {
				//filter (ie sampling) has been disabled in the switch with this port
				((HVSVPortInfo *)vAdaptor->userData)->portId = 0;
				removePoller(sp, vAdaptor);
				portInfo->filterEnabled = FALSE;
				//Clear the mark so this port will not be deleted, the VM and adaptor may still exist.
				//If the adaptor does not exist, it will be removed when we next refresh the VMs.
				vAdaptor->marked = FALSE;
			} else {
				//this was a port added for a vm on a switch with the filter disabled, so
				//just clear the mark so that it will not be deleted.
				vAdaptor->marked = FALSE;
			}	
		}
	}
	//Now remove the marked adaptors and their port info from the list
	adaptorListFreeMarked(sp->vAdaptorList, freePortInfo);
	//TODO ageout the persistent ifIndex->GUID mapping and remove from vAdaptor list.
	sp->portInfoRevision = config->revision;
	readWMISwitchPorts(sp); //update the ifSpeed, MAC, VM name
	sp->refreshVms = TRUE;
}

/**
 * Retrieves the switches and ports from the filter and
 * merges the info into the existing switch port info.
 */
ULONG_PTR readFilterSwitchPorts(HSP *sp)
{
    uint32_t configBufferLength = ioctlBufferLength;
    BOOLEAN ioctlSuccess;
    PAllSwitchesConfig config = NULL;
    void *configBuffer;
    boolean done = false;
    ULONG_PTR error = ERROR_SUCCESS;
    do {
        configBuffer = my_calloc(configBufferLength);
		ioctlSuccess = DeviceIoControl(sp->filter.dev, 
									   IOCTL_SFLOW_GET_SWITCH_CONFIG,
                                       NULL, 0, configBuffer,
                                       configBufferLength,
                                       NULL, &sp->filter.ioctlOverlap);
        if (!ioctlSuccess) {
			error = GetLastError();
			if (error == ERROR_IO_PENDING) {
				// I/O pending, wait for completion
				ioctlSuccess = WaitForSingleObject(sp->filter.ioctlOverlap.hEvent, INFINITE) == WAIT_OBJECT_0;
				if (ioctlSuccess) {
					error = sp->filter.ioctlOverlap.Internal;
				}
			}
        }
        if (ioctlSuccess) {
            if (sp->filter.ioctlOverlap.InternalHigh >= sizeof(AllSwitchesConfig)) {
                config = (PAllSwitchesConfig)configBuffer;
            }
            if (sp->filter.ioctlOverlap.InternalHigh == 0) {
                // No room for any data
                configBufferLength *= 2;
                my_free(configBuffer);
            } else if (sp->filter.ioctlOverlap.InternalHigh < config->size) {
                // Not all of the data fitted in the buffer
                configBufferLength = config->size;
                my_free(configBuffer);
            } else {
                done = true;
            }
        } else {
            done = true;
        }
    } while (!done);
    if (error == ERROR_SUCCESS) {
        updateSwitchPorts(sp, config);
    } else {
		myLog(LOG_ERR, "ReadFilterSwitchPorts: error=%X", error);
	}
    my_free(configBuffer);
    return error;
}

ULONG_PTR setFilterSamplingParams(HSP *sp)
{
	BOOLEAN ioctlSuccess;
	uint32_t tries = 0;
	ULONG_PTR error = ERROR_SUCCESS;
	SFlowConfiguration sFlowConfig; 
	sFlowConfig.sampleRate = sp->sFlow->sFlowSettings->samplingRate;
	sFlowConfig.sampleHeaderLength = sp->sFlow->sFlowSettings->headerBytes;
	do {
		ioctlSuccess = DeviceIoControl(sp->filter.dev, 
									   IOCTL_SFLOW_CONFIGURE,
                                       &sFlowConfig, sizeof(SFlowConfiguration), 
									   NULL, 0,
                                       NULL, &sp->filter.ioctlOverlap);
        if (!ioctlSuccess) {
			error = GetLastError();
			if (error == ERROR_IO_PENDING) {
				// I/O pending, wait for completion
				if (WaitForSingleObject(sp->filter.ioctlOverlap.hEvent, INFINITE) == WAIT_OBJECT_0) {
					error = sp->filter.ioctlOverlap.Internal;
				}
			}
        }
		tries++;
	} while (tries < 10 && error == ERROR_GEN_FAILURE);
	if (tries >= 10 || error == ERROR_GEN_FAILURE) {
		myLog(LOG_ERR, "SetFilterSamplerSettings: failed");
	}
	return error;
}


/**
 * Creates the array of OVERLAPS
 */
static void createOverlaps(HSP *sp)
{
    uint32_t i;
    for (i = 0; i < numConcurrentReads; i++) {
		OVERLAPPED *overlap = &sp->filter.overlaps[i];
		overlap->Offset = 0;
        overlap->OffsetHigh = 0;
        overlap->Pointer = NULL;
        overlap->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    }
}

/**
 * Queues one read request.
 * @param buffer the buffer for the read request.
 * @param bufferLen the length of buffer.
 * @param overlap the overlap associated with this request.
 * @return the error number from the read request, or 0 if no error (or the result is pending).
 */
DWORD queueRead(HANDLE dev, PUCHAR buffer, DWORD bufferLen, LPOVERLAPPED overlap)
{
    BOOL success = ReadFile(dev, buffer, bufferLen, NULL, overlap);
    DWORD error = GetLastError();
    if (!success && error != ERROR_IO_PENDING) {
        myLog(LOG_ERR, "queueRead: Error creating read: %d\n", error);
        return error;
    }
    return 0;
}

/**
 * Queues all the initial read requests.
 * @return the error code if queuing a read caused an error.
 */
static DWORD queueReads(HSP *sp)
{
    uint32_t i;
    DWORD error;
    for (i = 0; i < numConcurrentReads; i++) {
		error = queueRead(sp->filter.dev,
			              sp->filter.buffers[i], 
			              sizeof(sp->filter.buffers[i]), 
						  &sp->filter.overlaps[i]);
        if (error != 0) {
            return error;
        }
    }
    return 0;
}


/**
 * Initialises the sFlow filter device for receiving packet samples.
 */
void openFilter(HSP *sp)
{
	sp->filter.dev = INVALID_HANDLE_VALUE;
	// Open the device
    sp->filter.dev = CreateFileW(SFLOW_FILTER_DEVICE, GENERIC_READ, FILE_SHARE_READ, 
		                         NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (sp->filter.dev == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
        myLog(LOG_ERR, "openFilter: could not open device file %S: %ld", 
			  SFLOW_FILTER_DEVICE, error);
	} else {
		myLog(debug, "openFilter: attached to sFlow Hyper-V Switch extension");
		//Create the ioctl overlaps for communication with the device
		sp->filter.ioctlOverlap.Internal = 0;
		sp->filter.ioctlOverlap.InternalHigh = 0;
		sp->filter.ioctlOverlap.Pointer = NULL;
		sp->filter.ioctlOverlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

		createOverlaps(sp);
		if (queueReads(sp) != 0) {
			CloseHandle(sp->filter.dev);
			sp->filter.dev = INVALID_HANDLE_VALUE;
			myLog(LOG_ERR, "openFilter: could not queue initial read requests");
		} else {
			setFilterSamplingParams(sp);
		}
	}
}

#if defined(__cplusplus)
} /* extern "C" */
#endif