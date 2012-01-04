/**
 * File: sflowfilter.h
 * Author: Stuart Johnston
 * Version: $Id: sflowfilter.h 205 2011-12-27 17:30:24Z scp $
 *
 * Header file for external interface to the sFlow filter driver.
 * Copyright (C) InMon Corporation 2011 ALL RIGHTS RESERVED
 */

#ifndef _SFLOW_FILTER_H
#define _SFLOW_FILTER_H

// Devices for user space communication
#define DEVICE_NAME L"SFLOWFILTER"
#define LINKNAME L"\\DosDevices\\" DEVICE_NAME
#define NTDEVICE L"\\Device\\" DEVICE_NAME
#define SFLOW_FILTER_DEVICE L"\\\\.\\" DEVICE_NAME

#define _NDIS_CONTROL_CODE(request, method) \
            CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, request, method, FILE_ANY_ACCESS)

// IOCTLs for controlling the filter

#define IOCTL_SFLOW_READ_LOG _NDIS_CONTROL_CODE(0, METHOD_OUT_DIRECT)
#define IOCTL_SFLOW_CONFIGURE _NDIS_CONTROL_CODE(1, METHOD_BUFFERED)
#define IOCTL_SFLOW_GET_SWITCH_CONFIG _NDIS_CONTROL_CODE(2, METHOD_BUFFERED)

/**
 * One sFlow record. recordLength is the length of the opaque
 * data for this record. This structure is followed by the opaque
 * data.
 */
typedef struct {
    // Type of this record
    ULONG recordType;
    // Length of the opaque data
    ULONG dataLength;
    // Followed by recordLength bytes of data
} SFlowRecord, *PSFlowRecord;

/**
 * SFlowSample is a collection of SFlowRecords forming one sample.
 * The records are formed as a null-terminated list (terminated
 * by a record with type NULL_RECORD_TYPE).
 */
typedef struct {
    // The version of this structure
    ULONG version;
    // The Switch ID that the sample originated from
    UINT64 switchID;
    // The nomimal sampling rated used for this sample
    ULONG sampleRate;
    // The number of samples dropped
    ULONG drops;
    // The ingress port
    UINT32 srcPort;
    // The egress port
	UINT32 destPort;
    // The first record in the list of records
    SFlowRecord firstRecord;
} SFlowSample, *PSFlowSample;

/**
 * SFlowSampledHeader is the opaque data for an SFlowRecord representing
 * an sFlow sampled header. The actual header for the sample follows this
 * structure, with length of this overall structure to the outer
 * SFlowRecord length.
 */
typedef struct {
    // Length of actual packet, including stripped
    ULONG frameLength;
    // Number of stripped bytes
    ULONG stripped;
    // Followed by data to length of record
} SFlowSampledHeader, *PSFlowSampledHeader;

// Protocol for header records
#define SFLOW_HEADER_PROTOCOL 1

/**
 * SFlowExtendedSwitch contains the data associated with an sFlow
 * extended switch record.
 */
typedef struct {
    UINT32 sourceVLAN;
    UINT32 sourcePriority;
    UINT32 destVLAN;
    UINT32 destPriority;
} SFlowExtendedSwitch, *PSFlowExtendedSwitch;

/**
 * Returns the address of the data area for the PSFlowSample
 * or PSFflowSampledHeader sample, or the portArray in a
 * SwitchInfo.
 * @param sample the PSflowSample or PSflowSampleHeader or
 * SwitchInfo to get opaque data address of.
 * @param type the type of the opaque data.
 */
#define GET_OPAQUE_DATA_ADDR(sample, type) \
    ((type)(sample+1))

/**
 * Returns the next sFlow record in the list after record.
 * @param record the sFlow record from which to get the next record.
 * @return the next sFlow record in the list.
 */
#define GET_NEXT_SFLOW_RECORD(record) \
    ((PSFlowRecord)((PUCHAR)(record+1)+record->dataLength))

// Current version of the SFlowSample record in use
#define CURRENT_SFLOW_FILTER_VERSION 1

// Type identifier for records, using sFlow v5 identifiers
// End of the list
#define NULL_RECORD_TYPE 0
// Sampled header
#define SAMPLED_HEADER_RECORD_TYPE 1
// Extended switch
#define EXTENDED_SWITCH_RECORD_TYPE 1001

// Port configuration, contained in a SwitchConfig
typedef struct {
    // Revision of the switch configuration when this port was changed
    UINT32 revision;
    // Port ID as reported by vSwitch
	UINT32 portID;
    // Port name (GUID)
    NDIS_IF_COUNTED_STRING portName;
    // Port friendly name
    NDIS_IF_COUNTED_STRING portFriendlyName;
} PortEntry, *PPortEntry;

// Switch configuration
typedef struct {
    // Revision of this switch configuration
    UINT32 revision;
    // Switch name (GUID)
    NDIS_IF_COUNTED_STRING switchName;
    // Switch ID
    UINT64 switchID;
    // Number of ports on the switch
    UINT32 numPorts;
    // Followed by PortEntry[numPorts]
} SwitchConfig, *PSwitchConfig;

/**
 * Returns the size of switchConfig.
 * @return the size of switchConfig.
 */
#define GET_SWITCH_CONFIG_SIZE(switchConfig) \
    (sizeof(SwitchConfig)+switchConfig->numPorts*sizeof(PortEntry));

/**
 * Returns a pointer to the PortEntry indexed by portNum
 * in switchConfig.
 * @param switchConfig the SwitchConfig to retrieve the port entry
 * from.
 * @param portNum the index of the port entry required.
 * @return the port entry with index portNum from switchConfig.
 */
#define GET_PORT_ENTRY_AT(switchConfig, portNum) \
    (GET_OPAQUE_DATA_ADDR(switchConfig, PPortEntry)+portNum)

typedef struct {
    // Size required for this structure, including all referenced information
    // (structure will be incomplete if buffer is not adequate)
    UINT32 size;
    // Revision number of the configuration
    UINT32 revision;
    // Number of switches in this structure
    UINT32 numSwitches;
    // Followed by SwitchConfig[numSwitches]
} AllSwitchesConfig, *PAllSwitchesConfig;

/**
 * Returns the first switch config from allConfig.
 * @param allConfig the AllSwitchesConfig to get the first
 * config from.
 * @return the first PSwitchConfig fdrom allConfig, or NULL
 * if there are none.
 */
#define GET_FIRST_SWITCH_CONFIG(allConfig) \
    (allConfig->numSwitches > 0 ? (PSwitchConfig)(allConfig+1) : NULL)

/**
 * Returns the next switch config after config in the list. This
 * must not be used if there is no next.
 * @param config the switch config before the one desired.
 * @return the next PSwitchConfig after config.
 */
#define GET_NEXT_SWITCH_CONFIG(config) \
    ((PSwitchConfig)((PUCHAR)(config+1)+config->numPorts*sizeof(PortEntry)))

/**
 * sFlow configuration, to be passed in to the configuration IOCTL.
 */
typedef struct {
    ULONG sampleRate;
    ULONG sampleHeaderLength;
} SFlowConfiguration, *PSFlowConfiguration;

#endif