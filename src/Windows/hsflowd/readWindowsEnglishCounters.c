/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "readWindowsEnglishCounters.h"

extern int debug;

/**
 * Functions which use the PDH API to obtain counter values.
 * Uses the pdhAddEnglishCounter function, so can only be used post WinXP,
 * but means that callers don't need to use the registry to localise the
 * counter names for non-English locales.
 * Also uses wchar_t * paths since WMI returns identifiers (for counter instances)
 * as BSTR (wchar_t *) and since some instances could be set in a non-English locale
 * cannot assume we can convert to char *.
 */

/**
 * Returns the wchar_t * English string path to the specified counter for
 * use with the PDH API.
 * Memory is allocated for the counter path using my_calloc, so the caller 
 * must free with my_free when the path is no longer needed.
 * Does not convert the counter name to the current locale, assuming
 * that pdhAddEnglishCounter function is available (post XP).
 * wchar_t *object performance counter object
 * (eg Hyper-V Virtual Network Adapter)
 * wchar_t *instance counter instance (eg switch port name) use 
 * L"*" for a wild card, NULL for no instance.
 * wchar_t *counter name of counter.
 */
static LPWSTR getCounterPath(wchar_t *object, wchar_t *instance, wchar_t *counter)
{
	PDH_COUNTER_PATH_ELEMENTS_W cpe;
	cpe.szMachineName = NULL;
	cpe.szObjectName = object;
	cpe.szInstanceName = instance;
	cpe.szParentInstance = NULL;
	cpe.dwInstanceIndex = 0;
	cpe.szCounterName = counter;
	LPWSTR szFullPath = NULL;
	DWORD cbPathSize = 0;
	PDH_STATUS s;

	s = PdhMakeCounterPathW(&cpe, NULL, &cbPathSize, 0);
	if (s == PDH_MORE_DATA) {
		szFullPath = (wchar_t *)my_calloc(cbPathSize*sizeof(wchar_t));
		s = PdhMakeCounterPathW(&cpe, szFullPath, &cbPathSize, 0);
		//myLog(LOG_INFO, "PdhMakeCounterPathW: Counter path=%S", szFullPath);
	}
	return szFullPath;
}

/**
 * Initialises a query to access a single specified counter.
 * Returns the PDH error code resulting from PdhOpenQuery
 * and PdhAddEnglishCounterW.
 * wchar_t *object performance counter object (eg Processor)
 * wchar_t *instance counter instance (eg _Total) use 
 * L"*" for a wild card.
 * wchar_t *counterName English name of counter (eg % Processor Time).
 * PDH_HQUERY *query handle to the query that will be used in subsequent
 * calls (eg adding additional counters, running the query - PdhCollectQueryData). 
 * Set to NULL if initialising the query fails.
 * PDH_HCOUNTER *counter handle to the counter that will contain the
 * counter query results and accessed in subsequent calls (eg getRawCounterValue,
 * PdhGetFormattedCounterValue).
 */
PDH_STATUS makeSingleCounterQuery(wchar_t *object, wchar_t *instance, wchar_t *counterName,
								  PDH_HQUERY *query, PDH_HCOUNTER *counter)
{
	PDH_STATUS status = PdhOpenQuery(NULL, 0, query);
	if (ERROR_SUCCESS == status) {
		status = addCounterToQuery(object, instance, counterName, query, counter);
	}
	if (query && ERROR_SUCCESS != status) {
		PdhCloseQuery(*query);
		*query = NULL;
	}
	return status;
}

/**
 * Adds a counter, specified by the specified counter path elements, 
 * to the already opened query, specifying the handle that will be used
 * to access the counter query results.
 * Returns ERROR_SUCCESS on success or other PDH error code on failure.
 * wchar_t *object performance counter object (eg Processor)
 * wchar_t *instance counter instance (eg _Total) use 
 * L"*" for a wild card.
 * wchar_t *counterName English name of counter (eg % Processor Time).
 * PDH_HQUERY *query handle to the query that will be used in subsequent
 * calls (eg adding additional counters, running the query - PdhCollectQueryData). 
 * Set to NULL if initialising the query fails.
 * PDH_HCOUNTER *counter handle to the counter that will contain the
 * counter query results and accessed in subsequent calls (eg getRawCounterValue,
 * PdhGetFormattedCounterValue).
 */
PDH_STATUS addCounterToQuery(wchar_t *object, wchar_t *instance, wchar_t *counterName,
							 PDH_HQUERY *query, PDH_HCOUNTER *counter)
{
	LPWSTR counterPath = getCounterPath(object, instance, counterName);
	PDH_STATUS status = PdhAddEnglishCounterW(*query, counterPath, 0, counter);
	my_free(counterPath);
	return status;
}

/**
 * Returns the raw counter value accessed from the specified counter
 * handle. Returns 0 if there is an error on accessing the counter value.
 * PDH_HCOUNTER *counter handle to counter that contains the counter
 * value.
 */
LONGLONG getRawCounterValue(PDH_HCOUNTER *counter)
{
	DWORD dwType;
	PDH_RAW_COUNTER value;
	if (PdhGetRawCounterValue(*counter, &dwType, &value) == ERROR_SUCCESS) {
		return value.FirstValue;
	}
	return 0;
}

/**
 * Allocated sufficient memory for a number of raw counter items, populates 
 * these counter items with the values of the counters countained in counters. 
 * Returns the number of counters in the structure,
 * excluding the _Total instance. This is for use when the counter query has
 * been constructed using a wild card instance to collect counter values
 * for all instances.
 * Memory for the counter items should be freed using my_free when no longer needed.
 * PDH_HCOUNTER *counter handle to counter that contains the counter
 * values.
 * PPDH_RAW_COUNTER_ITEM_W *values will be assigned to structure allocated by
 * this function to contain the counter values from the counter.
 */
uint32_t getRawCounterValues(PDH_HCOUNTER *counter, PPDH_RAW_COUNTER_ITEM_W *values)
{
	DWORD bufSize = 0;
	DWORD itemCount = 0;
	uint32_t ret = 0;
	if (PdhGetRawCounterArrayW(*counter, &bufSize, &itemCount, NULL) == PDH_MORE_DATA) {
		*values = (PPDH_RAW_COUNTER_ITEM_W)my_calloc(bufSize);
		if (PdhGetRawCounterArrayW(*counter, &bufSize, &itemCount, *values) == ERROR_SUCCESS) {
			ret = itemCount;
			if (ret > 0 && wcscmp(COUNTER_INSTANCE_TOTAL, values[0][itemCount-1].szName) == 0) {
				ret--; // use readSingleCounter if you need _Total;
			}
		}
	}
	return ret;
}
	
/**
 * Returns the formatted (cooked), LONGLONG counter value obtained from the specified
 * counter, using PdhGetFormattedCounterValue.
 * If the counter cooking requires 2 counter readings and the counter only references
 * one, returns 0.
 * Returns 0 if the counter cooking fails for any other reason.
 */
LONGLONG getCookedCounterValue(PDH_HCOUNTER *counter)
{
	DWORD dwType;
	PDH_FMT_COUNTERVALUE value;
	if (ERROR_SUCCESS == PdhGetFormattedCounterValue(*counter, PDH_FMT_LARGE, &dwType, &value)) {
		return value.largeValue;
	}
	return 0;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
