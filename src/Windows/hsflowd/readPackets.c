/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"
#include "sflowfilter.h"

extern int debug;

/**
 * Convenience function for addCounterToQuery with counter object always IF_COUNTER_OBJECT.
 * Adds the counter with path constructed from IF_COUNTER_OBJECT, instance, counterName,
 * to the query, with counter query results referenced by *counter.
 * Returns PDH_STATUS from adding a counter to the query, ERROR_SUCCESS on success.
 * wchar_t *instance counter instance name (eg switchGUID-portGUID) (null terminated).
 * wchar_t *counterName English name of counter (null terminated).
 * PDH_HQUERY *query handle for the query.
 * PDH_HCOUNTER *counter handle for the counter query results.
 */
static PDH_STATUS addCounter(wchar_t *instance, wchar_t *counterName, PDH_HQUERY *query, PDH_HCOUNTER *counter)
{
	return addCounterToQuery(IF_COUNTER_OBJECT, instance, counterName, query, counter);
}

/**
 * Call back function called when it is time to sample the Hyper-V switch interface counters.
 * Uses the poller->userData to find the device name (ie switch port guid) which identifies
 * the counter instance for the switch port.
 */
void getCounters_interface(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
 {
	 HSP *sp = (HSP *)poller->magic;
    
    // device name was copied as userData
    char *deviceName = (char *)poller->userData;
	myLog(LOG_INFO, "getCounters_interface: dsClass=%u, dsIndex=%u, deviceName=%s", 
		  poller->dsi.ds_class, poller->dsi.ds_index, deviceName);

	if (deviceName) {
		//find the vadaptor for the deviceName
		SFLAdaptor *vAdaptor = adaptorListGet(sp->vAdaptorList, deviceName);
		if (vAdaptor != NULL) {
			myLog(LOG_INFO, "getCounters_interface: found adaptor index=%u", vAdaptor->ifIndex);
			wchar_t *instance = ((HVSVPortInfo *)vAdaptor->userData)->portCountersInstance;
			if (!instance) {
				myLog(LOG_INFO, "getCounters_interface: counters instance name not set for %s", deviceName);
				return;
			}
			//Get the counter data
			SFLCounters_sample_element elem = { 0 };
			elem.tag = SFLCOUNTERS_GENERIC;
			elem.counterBlock.generic.ifIndex = poller->dsi.ds_index;
			elem.counterBlock.generic.ifType = 6; // assume ethernet
			elem.counterBlock.generic.ifSpeed = vAdaptor->ifSpeed;
			elem.counterBlock.generic.ifDirection = vAdaptor->ifDirection;
			elem.counterBlock.generic.ifStatus = 3; // ifAdminStatus==up, ifOperstatus==up
			elem.counterBlock.generic.ifPromiscuousMode = vAdaptor->promiscuous;
			PDH_HQUERY query;
			if (PdhOpenQuery(NULL, 0, &query) == ERROR_SUCCESS) {
				PDH_HCOUNTER bytesIn, pktsIn, mcastsIn, bcastsIn, discardsIn;
				PDH_HCOUNTER bytesOut, pktsOut, mcastsOut, bcastsOut, discardsOut;
				if (addCounter(instance, IF_COUNTER_BYTES_IN, &query, &bytesIn) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_PACKETS_IN, &query, &pktsIn) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_MULTICASTS_IN, &query, &mcastsIn) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_BROADCASTS_IN, &query, &bcastsIn) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_DISCARDS_IN, &query, &discardsIn) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_BYTES_OUT, &query, &bytesOut) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_PACKETS_OUT, &query, &pktsOut) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_MULTICASTS_OUT, &query, &mcastsOut) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_BROADCASTS_OUT, &query, &bcastsOut) == ERROR_SUCCESS &&
					addCounter(instance, IF_COUNTER_DISCARDS_OUT, &query, &discardsOut) == ERROR_SUCCESS &&
					PdhCollectQueryData(query) == ERROR_SUCCESS) {
					elem.counterBlock.generic.ifInOctets = getRawCounterValue(&bytesIn);
					elem.counterBlock.generic.ifInUcastPkts = (uint32_t)getRawCounterValue(&pktsIn);
					elem.counterBlock.generic.ifInMulticastPkts = (uint32_t)getRawCounterValue(&mcastsIn);
					elem.counterBlock.generic.ifInBroadcastPkts = (uint32_t)getRawCounterValue(&bcastsIn);
					elem.counterBlock.generic.ifInDiscards = (uint32_t)getRawCounterValue(&discardsIn);
					elem.counterBlock.generic.ifOutOctets = getRawCounterValue(&bytesOut);
					elem.counterBlock.generic.ifOutUcastPkts = (uint32_t)getRawCounterValue(&pktsOut);
					elem.counterBlock.generic.ifOutMulticastPkts = (uint32_t)getRawCounterValue(&mcastsOut);
					elem.counterBlock.generic.ifOutBroadcastPkts = (uint32_t)getRawCounterValue(&bcastsOut);
					elem.counterBlock.generic.ifOutDiscards = (uint32_t) getRawCounterValue(&discardsOut);
				}
				PdhCloseQuery(query);
			}
			elem.counterBlock.generic.ifInErrors = UNKNOWN_COUNTER;
			elem.counterBlock.generic.ifOutErrors = UNKNOWN_COUNTER;
			elem.counterBlock.generic.ifInUnknownProtos = UNKNOWN_COUNTER;
			SFLADD_ELEMENT(cs, &elem);
			myLog(LOG_INFO, "getCounters_interface:\n\tifIndex:\t%u\n\tifType:\t%u\n\tifSpeed:\t%I64u\n"
				"\tifDirection:\t%u\n\tifStatus:\t%u\n\tpromiscuous:\t%u\n\tinOctets:\t%I64u\n\tinUcast:\t%u\n"
				"\tinMulticast:\t%u\n\tinBroadcast:\t%u\n\tinDiscards:\t%u\n\tinErrors:\t%u\n\toutOctets:\t%I64u\n"
				"\toutUcast:\t%u\n\toutMulticast:\t%u\n\toutBroadcast:\t%u\n\toutDiscards:\t%u\n\toutErrors:\t%u",
				elem.counterBlock.generic.ifIndex, elem.counterBlock.generic.ifType, elem.counterBlock.generic.ifSpeed, 
				elem.counterBlock.generic.ifDirection, elem.counterBlock.generic.ifStatus, 
				elem.counterBlock.generic.ifPromiscuousMode, elem.counterBlock.generic.ifInOctets, 
				elem.counterBlock.generic.ifInUcastPkts, elem.counterBlock.generic.ifInMulticastPkts, 
				elem.counterBlock.generic.ifInBroadcastPkts, elem.counterBlock.generic.ifInDiscards, 
				elem.counterBlock.generic.ifInErrors, elem.counterBlock.generic.ifOutOctets, 
				elem.counterBlock.generic.ifOutUcastPkts, elem.counterBlock.generic.ifOutMulticastPkts, 
				elem.counterBlock.generic.ifOutBroadcastPkts, elem.counterBlock.generic.ifOutDiscards, 
				elem.counterBlock.generic.ifOutErrors);
			sfl_poller_writeCountersSample(poller, cs);
		}
	}
}

/**
 * Searches for existing sampler with ifIndex and returns it. If there is no
 * existing sampler with the ifIndex, creates a new one (and a poller) and
 * returns it.
 */
static SFLSampler *getSampler(HSP *sp, char *devName, uint32_t ifIndex)
{
	SFLSampler *sampler = sfl_agent_getSamplerByIfIndex(sp->sFlow->agent, ifIndex);
	if (sampler == NULL) {
		SFLDataSource_instance dsi;
		SFL_DS_SET(dsi, 0, ifIndex, 0); // ds_class=0 interface
		HSPSFlow *sf = sp->sFlow;
		uint32_t samplingRate = sp->sFlow->sFlowSettings->samplingRate;
		sampler = sfl_agent_addSampler(sf->agent, &dsi);
		sampler->userData = (void *)my_strdup(devName);
		sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, samplingRate);
		sfl_sampler_set_sFlowFsReceiver(sampler, HSP_SFLOW_RECEIVER_INDEX);
	}
	return sampler;
}

/**
 * Reads a sampled packet header and associated information from
 * the buffer creates a packet sample.
 * Includes looking up the sampler from the ingress and egress
 * port information, and creating a new sampler (and poller) if
 * one does not already exist.
 */
void readPackets(HSP *sp, PUCHAR buffer)
{
	PSFlowSample sample = (PSFlowSample)buffer;
	if (sample->version != 1) {
		myLog(LOG_INFO, "readPackets: unknown filter sample version: %u", 
			  sample->version);
		return;
	}

	SFL_FLOW_SAMPLE_TYPE fs = { 0 };
	char *sampler_dev = NULL;
	uint32_t sampler_ifIndex = 0;
	// set the ingress and egress ifIndex numbers.
	// Can be "INTERNAL" (0x3FFFFFFF) or "UNKNOWN" (0).
	// mimic ingress sampling by using the ingress interface as the data source
	SFLAdaptor *in = getVAdaptorByIds(sp->vAdaptorList, sample->switchID, sample->srcPort);
	if (in) {
		fs.input = in->ifIndex;
		sampler_dev = in->deviceName;
		sampler_ifIndex = in->ifIndex;
	} 
	SFLAdaptor *out = getVAdaptorByIds(sp->vAdaptorList, sample->switchID, sample->destPort);
	if (out) {
		fs.output = out->ifIndex;
	} else {
		fs.output = 0;
	}
	// must have an ifIndex to generate a sample
	if (sampler_ifIndex) {
		SFLSampler *sampler = getSampler(sp, sampler_dev, sampler_ifIndex);
		if (sampler) {
			// submit the actual sampling rate so it goes out with the sFlow feed
			// otherwise the sampler object would fill in his own (sub-sampling) rate.
			fs.sampling_rate = sample->sampleRate;
			// estimate the sample pool from the samples. Could maybe do this
			// above with the (possibly more granular) samplingRate, but then
			// we would have to look up the sampler object every time, which
			// might be too expensive in the case where samplingRate==1.
			sampler->samplePool += sample->sampleRate;

			fs.drops = sample->drops;

			PSFlowRecord currRecord = &sample->firstRecord;
			SFLFlow_sample_element hdrElem = { 0 };
			SFLFlow_sample_element extSwElem = { 0 };
			while (currRecord->recordType != NULL_RECORD_TYPE) {
				switch(currRecord->recordType) {
				case SAMPLED_HEADER_RECORD_TYPE: {
					PSFlowSampledHeader sampledHeader = 
						GET_OPAQUE_DATA_ADDR(currRecord, PSFlowSampledHeader);
					hdrElem.tag = SFLFLOW_HEADER;
					hdrElem.flowType.header.frame_length = 
						sampledHeader->frameLength;
                    hdrElem.flowType.header.stripped = sampledHeader->stripped;
					hdrElem.flowType.header.header_protocol = SFLOW_HEADER_PROTOCOL;
					hdrElem.flowType.header.header_length = 
						currRecord->dataLength - sizeof(SFlowSampledHeader);
					hdrElem.flowType.header.header_bytes = GET_OPAQUE_DATA_ADDR(sampledHeader, PUCHAR);
					SFLADD_ELEMENT(&fs, &hdrElem);
					if (LOG_INFO <= debug) {
						 /*u_char pkt[HSP_MAX_HEADER_BYTES*2 +1]; //2 chars/byte + null
						printHex(GET_OPAQUE_DATA_ADDR(sampledHeader, PUCHAR), 
								 hdrElem.flowType.header.header_length, pkt, 
								 HSP_MAX_HEADER_BYTES*2+1, NO);*/
						myLog(LOG_INFO, "readPackets: sampler: %s index: %u headerLength: %u, frameLength: %u dropped: %u", 
							  sampler->userData, SFL_DS_INDEX(sampler->dsi), 
							  hdrElem.flowType.header.header_length, 
							  hdrElem.flowType.header.frame_length,
							  fs.drops);
					}
					break; }
				case EXTENDED_SWITCH_RECORD_TYPE: {
					PSFlowExtendedSwitch extendedSwitch =
						GET_OPAQUE_DATA_ADDR(currRecord, PSFlowExtendedSwitch);
					extSwElem.tag = SFLFLOW_EX_SWITCH;
					extSwElem.flowType.sw.src_vlan = extendedSwitch->sourceVLAN;
					extSwElem.flowType.sw.src_priority = extendedSwitch->sourcePriority;
					extSwElem.flowType.sw.dst_vlan = extendedSwitch->destVLAN;
					extSwElem.flowType.sw.dst_priority = extendedSwitch->destPriority;
					SFLADD_ELEMENT(&fs, &extSwElem);
					if (LOG_INFO <= debug) {
						myLog(LOG_INFO, "readPackets: sampler %s index %u srcVlan: %u srcPriority: %u dstVlan: %u dstPriority: %u",
							sampler->userData, SFL_DS_INDEX(sampler->dsi), 
							extSwElem.flowType.sw.src_vlan, extSwElem.flowType.sw.src_priority,
							extSwElem.flowType.sw.dst_vlan, extSwElem.flowType.sw.dst_priority);
					}
					break; }
                case EXTENDED_TUNNEL_RECORD_TYPE: {
                    PSFlowExtendedTunnel extendedTunnel =
                        GET_OPAQUE_DATA_ADDR(currRecord, PSFlowExtendedTunnel);
					if (LOG_INFO <= debug) {
						myLog(LOG_INFO, "readPackets: sampler %s index %u VSID: %u",
							sampler->userData, SFL_DS_INDEX(sampler->dsi), 
							extendedTunnel->vsid);
					}
                    break; }
				default: {
					myLog(LOG_INFO, "readPackets: unknown filter record type: %u", 
						currRecord->recordType); }
				}
				currRecord = GET_NEXT_SFLOW_RECORD(currRecord);
			}
			sfl_sampler_writeFlowSample(sampler, &fs);
		}
	}
}

#if defined(__cplusplus)
} /* extern "C" */
#endif