/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <Shlwapi.h>
#include <process.h>
#include <KtmW32.h>

#define MAX_IPV6_STRLEN 46
#define MAX_IPV4_STRLEN 16
#define MAX_KEY_LEN 255

extern int debug;

/**
 * Looks up host name or IP address and converts to SFLAddress, storing it in the
 * specified SFLAddress. Returns TRUE on success, FALSE on failure.
 * wchar_t *name A pointer to a NULL-terminated ANSI string that contains a hostname or 
 * a numeric host address string. The numeric host address string is a dotted-decimal 
 * IPv4 address or an IPv6 hex address. Use empty string to return registered addresses
 * of local computer.
 * int family PF_INET, PF_INET6, PF_UNSPEC
 * struct sockaddr *sockaddr if not NULL used to return the sockaddr for the looked up
 * address.
 * SFLAddress *addr to contain the valid IP address
 */
static BOOL lookupAddress(char *name, int family, struct sockaddr *sockaddr, SFLAddress *addr)
{
	WSADATA wsaData;
	int iResult;
	//initialise WinSock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		myLog(LOG_ERR, "lookupAddress: WSAStartup failed: %d", iResult);
		return FALSE;
	}
	struct addrinfo *info = NULL;
	struct addrinfo hints = { 0 };
	hints.ai_socktype =  SOCK_DGRAM; //constrain so we don't get too many results
	hints.ai_family = family;
	int err = getaddrinfo(name, NULL, &hints, &info);
	if (err != 0 || info == NULL) {
		myLog(LOG_ERR, "lookupAddress getaddrinfo() for %s failed error: %d",name, err);
		WSACleanup();
		return FALSE;
	}
	//getaddrinfo returns the addresses in priority order (RFC3484) so just take
	//the first
	switch (info->ai_family) {
		case PF_INET: 
		{
			struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)info->ai_addr;
			addr->type = SFLADDRESSTYPE_IP_V4;
			addr->address.ip_v4.addr = sockaddr_ipv4->sin_addr.s_addr;
			if (sockaddr != NULL) {
				memcpy(sockaddr, info->ai_addr, info->ai_addrlen);
			}
			break;
		}
		case PF_INET6:
		{
			struct sockaddr_in6 *sockaddr_ipv6 = (struct sockaddr_in6 *)info->ai_addr;
			addr->type = SFLADDRESSTYPE_IP_V6;
			memcpy(&addr->address.ip_v6, &sockaddr_ipv6->sin6_addr, 16);
			if (sockaddr != NULL) {
				memcpy(sockaddr, info->ai_addr, info->ai_addrlen);
			}
			break;
		}
	}
	freeaddrinfo(info);
	WSACleanup();
	return TRUE;
}

void clearCollectors(HSPSFlowSettings *settings) 
{
	if (settings->collectors != NULL) {
		for (HSPCollector *collector=settings->collectors; collector;) {
			HSPCollector *nextCollector = collector->nxt;
			my_free(collector->name);
			my_free(collector);
			collector = nextCollector;
		}
	}
	settings->collectors = NULL;
	settings->numCollectors = 0;
}

/**
 * Returns zero if the collectors are equal (their names and ports are the
 * same), returns a positive value if collector1 greater than collector2, 
 * and a negative value if collector1 is less than collector2.
 * Collectors compared using string compare of names and then numerical
 * compare of ports.
 * collector1 and collector2 cannot be NULL
 */
static int collectorCmp(HSPCollector *collector1, HSPCollector *collector2)
{
	int comp = StrCmp(collector1->name, collector2->name);
	if (comp == 0) {
		return collector1->udpPort == collector2->udpPort ? 0 :
			collector1->udpPort < collector2->udpPort ? -1 : 1;
	} else {
		return comp;
	}
}

/**
 * Creates a new collector and inserts it in sorted order into the linked list of
 * collectors referenced by settings.
 * Collector name is copied into the collector struct, so name should be freed.
 * Sorted by name (read from config) in ascending order, with collectors with
 * the same name being sorted by port in ascending order.
 * NOTE this function does not perform the IP lookup on the name, so the 
 * new collector address is not populated.
 */
void insertCollector(HSPSFlowSettings *settings, CHAR *name, DWORD port)
{
	HSPCollector *newCollector = (HSPCollector *)my_calloc(sizeof(HSPCollector));
	newCollector->name = my_strdup(name);
	newCollector->udpPort = port;
	//myLog(LOG_ERR, "insertCollector %s %s %u", name, newCollector->name, port);
	HSPCollector *collector = settings->collectors;
	if (collector == NULL) {
		settings->collectors = newCollector;
		settings->numCollectors = 1;
	} else {
		if (collectorCmp(newCollector, collector) < 0) {
			settings->collectors = newCollector;
			newCollector->nxt = collector;
		} else {
			HSPCollector *prevCollector = settings->collectors;
			while (collector != NULL) {
				if (collectorCmp(newCollector, collector) < 0) {
					prevCollector->nxt = newCollector;
					newCollector->nxt = collector;
					break;
				} else if (collector->nxt == NULL) {
					collector->nxt = newCollector;
					break;
				} else {
					prevCollector = collector;
					collector = collector->nxt;
				}
			}		
		}
		settings->numCollectors++;
	}
}

/**
 * Creates a new HSPSFlow structure and attaches it to HSP *sp.
 * Does not initialise the HSPSFlowSettings structure in HSPSFlow.
 */
static HSPSFlow *newSFlow(HSP *sp)
{
	HSPSFlow *sf = (HSPSFlow *)my_calloc(sizeof(HSPSFlow));
	sf->subAgentId = 0;
	sp->sFlow = sf; // just one of these, not a list
	sf->myHSP = sp;
	return sf;
}

/**
 * Returns the EnumIPSelectionPriority associated with the given
 * SFLAddress.
 */
EnumIPSelectionPriority agentAddressPriority(SFLAddress *addr)
{
	 EnumIPSelectionPriority ipPriority = IPSP_NONE;
	 switch(addr->type) {
		 case  SFLADDRESSTYPE_IP_V4:
			 // start assuming it is a global ip
			 ipPriority = IPSP_IP4;
			 // then check for other possibilities
			 if (SFLAddress_isLoopback(addr)) {
				ipPriority = IPSP_LOOPBACK4;
			 } else {
				u_char *a = (u_char *)&(addr->address.ip_v4.addr);
				if (a[0] == 169 && a[1] == 254) {
					// for IPv4, it's 169.254.*
					ipPriority = IPSP_SELFASSIGNED4;
				}
			 }
			 break;
		 case SFLADDRESSTYPE_IP_V6:
			 // start assuming it is a global ip
			 ipPriority = IPSP_IP6_SCOPE_GLOBAL;
			 if (SFLAddress_isLoopback(addr)) {
				 ipPriority = IPSP_LOOPBACK6;
			 } else {
				 SFLIPv6 addrv6 = addr->address.ip_v6;
				 if (addrv6.addr[0] == 0xFE && ((addrv6.addr[1] & 0xC0) == 0x80)) {
					//0xFE80::/10 link local
					ipPriority = IPSP_IP6_SCOPE_LINK;
				} else if ((addrv6.addr[0] & 0xFE) == 0xFC) {
					//0xFC00::/7 unique local
					ipPriority = IPSP_IP6_SCOPE_UNIQUE;
				} else if (addrv6.addr[0] = 0xFF) { 
					//should not have a multicast as an adapter address but we'll test anyway
					//0xFF00::/8 multicast
					ipPriority = IPSP_NONE;
				} else {
					//should not really have to do this either
					uint32_t *x = (uint32_t *)addr->address.ip_v6.addr;
					if (x[0] == 0 && x[1] == 0 && x[2] == 0 && x[3] == 0) {
						//::/128 unspecified
						ipPriority = IPSP_NONE;
					}
				}
			}
		 default:
			// not v4 or v6 leave as IPSP_NONE
			break;
	 }
	 return ipPriority;
}

/**
 * Reads the sFlow configuration settings from the registry location
 * identified by key and populates sampling and polling settings
 * in settings, together with adding collectors (name and port only). 
 * Optionally uses defaults for collector port, sampling
 * rate and polling interval. 
 * Assumes that the lecacy single collector value in hkey
 * has been moved to the sub-sub-key.
 * If the registry key cannot be opened returns FALSE otherwise returns TRUE.
 * NOTE: does not validate settings.
 */
static BOOL readReg_sFlowSettings(CHAR *key, HSPSFlowSettings *settings, BOOL useDefaults)
{
	//make sure header bytes are set.
	settings->headerBytes = SFL_DEFAULT_HEADER_SIZE;
	DWORD result, cbData;
	HKEY settingsKey, collectorsKey;
	result = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		key,
		0,
		KEY_QUERY_VALUE,
		&settingsKey);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "readReg_sFlowSettings: %s registry key not found", key);
		return FALSE;
	}
	DWORD serialNumber = HSP_SERIAL_INVALID;
	cbData = sizeof(DWORD);
	result = RegQueryValueEx(
		settingsKey, 
		HSP_REGVAL_SERIAL, 
		NULL,
		NULL,
		(LPBYTE)&serialNumber, 
		&cbData);
	settings->serialNumber = serialNumber;
	result = RegOpenKeyEx(
		settingsKey,
		HSP_REGKEY_COLLECTORS,
		0,
		KEY_READ,
		&collectorsKey);
	if (result == ERROR_SUCCESS) {
		//now enumerate the sub keys (one for each collector).
		DWORD countSubKeys = 0;
		result = RegQueryInfoKey(collectorsKey, NULL, NULL, NULL, &countSubKeys, 
								 NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		for (DWORD index = 0; index < countSubKeys; index++) {
			CHAR collectorName[MAX_KEY_LEN];
			DWORD collNameLen = MAX_KEY_LEN;
			result = RegEnumKeyEx(
				collectorsKey,
				index,
				collectorName,
				&collNameLen,
				NULL,
				NULL,
				NULL,
				NULL);
			HKEY collectorKey;
			result = RegOpenKeyEx(
				collectorsKey, 
				collectorName, 
				0, 
				KEY_QUERY_VALUE, 
				&collectorKey);
			if (result == ERROR_SUCCESS) {
				char collectorStr[MAX_HOSTNAME_LEN];
				cbData = MAX_HOSTNAME_LEN;
				result = RegQueryValueEx(
					collectorKey,
					HSP_REGVAL_COLLECTOR,
					NULL,
					NULL,
					(LPBYTE)collectorStr,
					&cbData );
				if (result == ERROR_SUCCESS) {
					//now get the port and create a collector
					DWORD port = 0;
					result = RegQueryValueEx(
						collectorKey,
						HSP_REGVAL_PORT,
						NULL,
						NULL,
						(LPBYTE)&port,
						&cbData);
					if (result != ERROR_SUCCESS && useDefaults) {
						port = SFL_DEFAULT_COLLECTOR_PORT;
					}
					myLog(LOG_INFO, "readReg_sFlowSettings: %s index=%u found collector %s:%u", key, index, collectorStr, port);
					insertCollector(settings, collectorStr, (WORD)port);
				}
				RegCloseKey(collectorKey);
			}
		}
		RegCloseKey(collectorsKey);
	}
	//read the sampling and polling settings
	DWORD samplingRate = 0;
	result = RegQueryValueEx(
		settingsKey,
		HSP_REGVAL_SAMPLING_RATE,
		NULL,
		NULL,
		(LPBYTE)&samplingRate,
		&cbData);
	if (result != ERROR_SUCCESS && useDefaults) {
		samplingRate = SFL_DEFAULT_SAMPLING_RATE;
	}
	settings->samplingRate = samplingRate;
	DWORD pollingInterval = 0;
	result = RegQueryValueEx(
		settingsKey,
		HSP_REGVAL_POLLING_INTERVAL,
		NULL,
		NULL,
		(LPBYTE)&pollingInterval,
		&cbData);
	if (result != ERROR_SUCCESS && useDefaults) {
		pollingInterval = SFL_DEFAULT_POLLING_INTERVAL;
	}
	settings->pollingInterval = pollingInterval;
	RegCloseKey(settingsKey);
	return TRUE;
}

/**
 * Validates the sFlow settings, returning TRUE if they
 * are valid, FALSE otherwise.
 * This includes looking up the collector names to obtain
 * IP addresses and storing in the collector structure,
 * checking that the collector ports are valid and verifying
 * that there is at least one valid collector defined.
 */
static BOOL validateSettings(HSPSFlowSettings *settings)
{
	HSPCollector *collector = settings->collectors;
	int collectorCount = 0;
	while (collector != NULL) {
		if (!lookupAddress(collector->name, 
							PF_UNSPEC, 
							(struct sockaddr *)&collector->sendSocketAddr, 
							&collector->ipAddr)) {
			//turn off the collector by clearing the address type
			collector->ipAddr.type = SFLADDRESSTYPE_UNDEFINED;
		}
		if (collector->udpPort < 1 || collector->udpPort > 65535) {
			myLog(LOG_ERR, "validateSettings: invalid port %u for target collector %s", 
				  collector->udpPort, collector->name);
			collector->ipAddr.type = SFLADDRESSTYPE_UNDEFINED;
		}
		if (collector->ipAddr.type != SFLADDRESSTYPE_UNDEFINED) {
			collectorCount++;
		}
		collector = collector->nxt;
	}
	return collectorCount > 0;
}

/**
 * Returns TRUE if settings1 and settings2 are equal, FALSE if not.
 * Collectors are tested for equality by comparing the collector names
 * and ports (not IP addresses).
 * Assumes that the collectors are sorted by name, then port.
 */
static BOOL settingsEqual(HSPSFlowSettings *settings1, HSPSFlowSettings *settings2)
{
	if (settings1->samplingRate != settings2->samplingRate ||
		settings1->pollingInterval != settings2->pollingInterval ||
		settings1->numCollectors != settings2->numCollectors) {
		return FALSE;
	}
	if (settings1->collectors == NULL && settings2->collectors == NULL) {
		return TRUE;
	}
	//settings->collectors != NULL here
	//Since both lists are same length, just look for first mismatch
	HSPCollector *collector1 = settings1->collectors;
	HSPCollector *collector2 = settings2->collectors;
	while (collector1 != NULL && collector2 != NULL) {
		if (collectorCmp(collector1, collector2) != 0) {
			return FALSE;
		}
		collector1 = collector1->nxt;
		collector2 = collector2->nxt;
	}
	return TRUE;
}

/**
 * Reads the sFlow settings from the registry current config key
 * and installs the settings in settings.
 * If reading the registry is successful and the configuration is valid
 * returns TRUE, otherwise returns FALSE;
 */
BOOL readSFlowSettings(HSPSFlowSettings *settings)
{
	if (readReg_sFlowSettings(HSP_REGKEY_CURRCONFIG, settings, FALSE)) {
		return validateSettings(settings);
	} else {
		return FALSE;
	}
}

/**
 * Writes the sFlow settings to the registry location identified by
 * key. The write is performed as a single transaction.
 * The settings are only written out if there are any changes.
 * Returns the serial number of the saved settings or HSP_SERIAL_INVALID
 * if the save failed.
 * This is a naive implementation, in that if any difference is detected
 * between the saved settings and the current settings, then the
 * saved settings are completely rewritten (ie all the collectors are
 * deleted and rewritten.
 */
static DWORD writeReg_sFlowSettings(CHAR *key, HSPSFlowSettings *settings)
{
	HSPSFlowSettings savedSettings = { 0 };
	readReg_sFlowSettings(key, &savedSettings, FALSE);
	if (settingsEqual(settings, &savedSettings)) {
		clearCollectors(&savedSettings);
		return savedSettings.serialNumber;
	}
	clearCollectors(&savedSettings);
	DWORD result;
	HKEY settingsKey, collectorsKey;
	HANDLE transaction =  CreateTransaction(NULL, 0, NULL, 0, 0, INFINITE, NULL);
	result = RegCreateKeyTransacted(
		HKEY_LOCAL_MACHINE,
		key,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&settingsKey,
		NULL,
		transaction,
		NULL);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "writeReg_sFlowSettings: cannot open registry key=%s error=%u", key, result);
		CloseHandle(transaction);
		return HSP_SERIAL_INVALID;
	}
	result = RegCreateKeyTransacted(
		settingsKey,
		HSP_REGKEY_COLLECTORS,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&collectorsKey,
		NULL,
		transaction,
		NULL);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "writeReg_sFlowSettings: cannot open registry key=%s\\%s error=%u", 
			  key, HSP_REGKEY_COLLECTORS, result);
		RegCloseKey(settingsKey);
		CloseHandle(transaction);
		return HSP_SERIAL_INVALID;
	}
	DWORD serialNumber = HSP_SERIAL_INVALID;
	DWORD cbData = sizeof(DWORD);
	result = RegQueryValueEx(
		settingsKey,
		HSP_REGVAL_SERIAL,
		NULL,
		NULL,
		(LPBYTE)&serialNumber,
		&cbData);
	//delete all the existing collectors
	result = RegDeleteTree(collectorsKey, NULL);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "writeReg_sFlowSettings: cannot remove existing collectors; error=%u", result);
		RegCloseKey(collectorsKey);
		RegCloseKey(settingsKey);
		CloseHandle(transaction);
		return HSP_SERIAL_INVALID;
	}
	int i = 1;
	for (HSPCollector *collector = settings->collectors;
		collector != NULL; collector = collector->nxt) {
		HKEY collectorKey;
		CHAR collectorKeyName[MAX_KEY_LEN];
		sprintf_s(collectorKeyName, "collector%d", i);
		result = RegCreateKeyTransacted(
				collectorsKey,
				collectorKeyName,
				0,
				NULL,
				REG_OPTION_NON_VOLATILE,
				KEY_WRITE,
				NULL,
				&collectorKey,
				NULL,
				transaction,
				NULL);
		if (result == ERROR_SUCCESS) {
			size_t len = strnlen_s(collector->name, MAX_HOSTNAME_LEN) + 1; //room for terminating null
			result = RegSetValueEx(
				collectorKey,
				HSP_REGVAL_COLLECTOR,
				0,
				REG_SZ,
				(LPBYTE)collector->name,
				(DWORD)len); 
			if (result != ERROR_SUCCESS) {
				myLog(LOG_ERR, "writeReg_sFlowSettings: cannot save collector %s in %s\\%s\\%s error=%u",
					collector->name, key, HSP_REGKEY_COLLECTORS, collectorKeyName, result);
			} 
			result = RegSetValueEx(
				collectorKey,
				HSP_REGVAL_PORT,
				0,
				REG_DWORD,
				(LPBYTE)&collector->udpPort,
				sizeof(UINT32));
			if (result != ERROR_SUCCESS) {
				myLog(LOG_ERR, "writeReg_sFlowSettings: cannot save collector port %u in %s\\%s\\%s error=%u",
					  collector->udpPort, key, HSP_REGKEY_COLLECTORS, collectorKeyName, result);
			}
			RegCloseKey(collectorKey);
			i++;
		}
	}
	RegCloseKey(collectorsKey);
	//now save the sampling and polling settings
	result = RegSetValueEx(
		settingsKey,
		HSP_REGVAL_SAMPLING_RATE,
		0,
		REG_DWORD,
		(LPBYTE)&settings->samplingRate,
		sizeof(UINT32));
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "writeReg_sFlowSettings: cannot save sampling rate %u in %s\\%s error=%u",
			  settings->samplingRate, key, HSP_REGVAL_SAMPLING_RATE, result);
	}
	result = RegSetValueEx(
		settingsKey,
		HSP_REGVAL_POLLING_INTERVAL,
		0,
		REG_DWORD,
		(LPBYTE)&settings->pollingInterval,
		sizeof(UINT32));
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "writeReg_sFlowSettings: cannot save polling interval %u in %s\\%s error=%u",
			  settings->pollingInterval, key, HSP_REGVAL_POLLING_INTERVAL, result);
	}
	//finally increment and save the serial number since the settings have changed
	serialNumber++;
	//test for wrap
	if (serialNumber == HSP_SERIAL_INVALID) {
		serialNumber++;
	}
	result = RegSetValueEx(
		settingsKey,
		HSP_REGVAL_SERIAL,
		0,
		REG_DWORD,
		(LPBYTE)&serialNumber,
		sizeof(DWORD));
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "writeReg: cannot save serial Number %u in %s\\%s error=%u",
			  serialNumber, key, HSP_REGVAL_SERIAL, result);
	}
	if (!CommitTransaction(transaction)) {
			serialNumber = HSP_SERIAL_INVALID;
	}
	RegCloseKey(settingsKey);
	CloseHandle(transaction);
	return serialNumber;
}

unsigned __stdcall runDNSSD(void *magic)
{
	HSP *sp = (HSP *)magic;
	sp->DNSSD_countdown = sfl_random(sp->DNSSD_startDelay);
	time_t clk = time(NULL);
	while (TRUE) {
		Sleep(999);
		time_t test_clk = time(NULL);
		if ((test_clk < clk) || (test_clk - clk) > HSP_MAX_TICKS) {
			// avoid a flurry of ticks if the clock jumps
			myLog(LOG_INFO, "time jump detected (DNSSD) %ld->%ld", clk, test_clk);
			clk = test_clk - 1;
		}
		time_t ticks = test_clk - clk;
		clk = test_clk;
		if (sp->DNSSD_countdown > ticks) {
			sp->DNSSD_countdown -= ticks;
		} else {
			//initiate server-discovery
			//since we are just using HSPSFlowSettings struct to accumulate
			//DNSSD info into then write out to the registry, allocate on the stack
			HSPSFlowSettings settings = { 0 };
			settings.pollingInterval = 0;
			settings.samplingRate = 0;
			settings.headerBytes = SFL_DEFAULT_HEADER_SIZE;
			// we want the min ttl so clear it here
			sp->DNSSD_ttl = 0;
			int numServers = dnsSD(sp, &settings);
			//numServers == -1 DNS query failed so keep current config
			if (numServers != -1) {  
				//(i) numServers == 0 write out the config and stop monitoring
				//(ii) numServers > 0 write out the config and use it.
				if (writeReg_sFlowSettings(HSP_REGKEY_CURRCONFIG, &settings) == HSP_SERIAL_INVALID) {
					myLog(LOG_ERR, "runDNSSD: saving DNS_SD config failed");
				}
			}
			clearCollectors(&settings);
			//we might have a valid ttl from the TXT records
			sp->DNSSD_countdown = sp->DNSSD_ttl ? sp->DNSSD_ttl : sp->DNSSD_retryDelay;
			// but make sure it is sane
			if (sp->DNSSD_countdown < HSP_DEFAULT_DNSSD_MINDELAY) {
				myLog(LOG_INFO, "forcing minimum DNS polling delay");
				sp->DNSSD_countdown = HSP_DEFAULT_DNSSD_MINDELAY;
			}
		}
	}
	_endthreadex(0);
	return 0;
}

/**
 * Compares the serial number in the registery current config registry settings
 * with the serial number in settings and returns TRUE if the registry
 * serial number is greater or smaller (to handle wrap).
 * If the registry location cannot be opened, returns FALSE.
 */
BOOL newerSettingsAvailable(HSPSFlowSettings *settings)
{
	HKEY settingsKey;
	DWORD result;
	result = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		HSP_REGKEY_CURRCONFIG,
		0,
		KEY_QUERY_VALUE,
		&settingsKey);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_INFO, "newerSettingsAvailable: cannot open registry %s", HSP_REGKEY_CURRCONFIG);
		return FALSE;
	}
	DWORD serialNumber = HSP_SERIAL_INVALID;
	DWORD cbData = sizeof(DWORD);
	result = RegQueryValueEx(
		settingsKey,
		HSP_REGVAL_SERIAL,
		NULL,
		NULL,
		(LPBYTE)&serialNumber,
		&cbData);
	RegCloseKey(settingsKey);
	if (result == ERROR_SUCCESS && serialNumber != HSP_SERIAL_INVALID) {
		return settings == NULL || serialNumber != settings->serialNumber;
	} else {
		myLog(LOG_ERR, "newerSettingsAvailable: cannot access %s\\%s", HSP_REGKEY_CURRCONFIG, HSP_REGVAL_SERIAL);
		return FALSE;
	}
}

/**
 * Converts the legacy registry settings to the current format.
 * Moves the single collector and port to a sub-key under the
 * collectors sub-key.
 * Returns TRUE on success, FALSE on failure
 */
static BOOL convertReg(CHAR *key)
{
	HKEY hkey;
	DWORD result, cbData;
	result = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		key,
		0,
		KEY_ALL_ACCESS,
		&hkey);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "convertReg: failed to open key=%s error=%u", key, result);
		return FALSE;
	}
	char collectorStr[MAX_HOSTNAME_LEN];
	cbData = MAX_HOSTNAME_LEN;
	result = RegQueryValueEx(
		hkey,
		HSP_REGVAL_COLLECTOR,
		NULL,
		NULL,
		(LPBYTE)collectorStr,
		&cbData);
	if (result == ERROR_SUCCESS) {
		//legacy config
		//now create the collectors sub-key
		HKEY collectorsKey;
		result = RegCreateKeyEx(
			hkey,
			HSP_REGKEY_COLLECTORS,
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_WRITE,
			NULL,
			&collectorsKey,
			NULL);
		if (result != ERROR_SUCCESS) {
			myLog(LOG_ERR, "convertReg: cannot create %s\\%s error=%u",
				  key, HSP_REGKEY_COLLECTORS, result);
			RegCloseKey(hkey);
			return FALSE;
		}
		HKEY collectorKey;
		CHAR *collectorKeyName = "collector1";
		result = RegCreateKeyEx(
			collectorsKey,
			collectorKeyName,
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_SET_VALUE,
			NULL,
			&collectorKey,
			NULL);
		if (result != ERROR_SUCCESS) {
			myLog(LOG_ERR, "convertReg: cannot create %s\\%s\\%s error=%u",
				  key, HSP_REGKEY_COLLECTORS, collectorKeyName, result);
			RegCloseKey(hkey);
			RegCloseKey(collectorsKey);
			return FALSE;
		}
		result = RegSetValueEx(
			collectorKey,
			HSP_REGVAL_COLLECTOR,
			0,
			REG_SZ,
			(LPBYTE)collectorStr,
			cbData);
		if (result != ERROR_SUCCESS) {
			myLog(LOG_ERR, "convertReg: cannot set collector value %s\\%s\\%s %s error=%u",
				  key, HSP_REGKEY_COLLECTORS, collectorStr, collectorStr, result);
			RegCloseKey(hkey);
			RegCloseKey(collectorsKey);
			return FALSE;
		}
		DWORD port = 0;
		result = RegQueryValueEx(
			hkey,
			HSP_REGVAL_PORT,
			NULL,
			NULL,
			(LPBYTE)&port,
			&cbData);
		if (result == ERROR_SUCCESS) {
			result = RegSetValueEx(
				collectorKey,
				HSP_REGVAL_PORT,
				0,
				REG_DWORD,
				(LPBYTE)&port,
				cbData);
			if (result != ERROR_SUCCESS) {
				myLog(LOG_ERR, "convertReg: cannot set collector port value %s\\%s\\%s %u error=%u",
					  key, HSP_REGKEY_COLLECTORS, collectorStr, port, result);
				RegCloseKey(hkey);
				RegCloseKey(collectorsKey);
				return FALSE;
			}
		}
		RegDeleteValue(hkey, HSP_REGVAL_COLLECTOR);
		RegDeleteValue(hkey, HSP_REGVAL_PORT);
		RegCloseKey(collectorKey);
		RegCloseKey(collectorsKey);
		RegCloseKey(hkey);
		return TRUE;
	} else {
		//nothing to convert
		RegCloseKey(hkey);
		return TRUE;
	}
}

/**
 * Reads the initial configuration from the registry - agent address,
 * DNS-SD settings and if DNS-SD config is not enabled, reads the manual
 * manual sFlow settings (converting from old style if necessary), saving it
 * saving it to the registry under the current config key (without validating).
 * Returns TRUE if all registry reads (and writes) are successful, 
 * FALSE if the agent address cannot be determined.
 * agent address is determined as follows:
*  if set in the registry and valid (IPv4, IPv6 or hostname),
 * use this (without checking whether it is an address owned by this host),
 * otherwise, pick the best IP address from the current adapters.
 * readSFlowSettings(HSPSFlowSettings) must be called to obtain validated
 * sFlow configuration.
 */
BOOL readConfig(HSP *sp)
{
	convertReg(HSP_REGKEY_PARMS);
	DWORD result,cbData;
	HKEY hkey;
	result = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		HSP_REGKEY_PARMS,
		0,
		KEY_QUERY_VALUE,
		&hkey);
	if (result != ERROR_SUCCESS) {
		myLog(LOG_ERR, "readConfig: %s registry key not found", HSP_REGKEY_PARMS);
		return FALSE;
	}

	newSFlow(sp);

	//set the agent address
	//If the agent address is set in the registry, just go with that
	//even if it is not an address associated with an adapter.
	//Otherwise choose the best IPv4 or IPv6 address from the adapters
	//Using the priorities defined in EnumIpSelectionPriority
	char agentStr[MAX_IPV6_STRLEN];
	memset(agentStr, 0, MAX_IPV6_STRLEN);
	cbData = MAX_IPV6_STRLEN;;
	result = RegQueryValueEx(
		hkey,
		HSP_REGVAL_AGENT,
		NULL,
		NULL,
		(LPBYTE)agentStr,
        &cbData);
	if (result == ERROR_SUCCESS) {
		lookupAddress(agentStr, NULL, PF_UNSPEC, &sp->sFlow->agentIP);
	}

	if (sp->sFlow->agentIP.type == 0) {
		SFLAdaptor *selectedAdaptor = NULL;
		EnumIPSelectionPriority selectedPriority = IPSP_NONE;
	
		for (uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
			SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
			if (adaptor && adaptor->userData) {
				EnumIPSelectionPriority ipPriority = 
					((HSPAdaptorNIO *)adaptor->userData)->ipPriority;
				if (ipPriority && ipPriority > selectedPriority) {
					selectedAdaptor = adaptor;
					selectedPriority = ipPriority;
				}
			}
		}
		if (selectedAdaptor) { //we know it has userData from above
			HSPAdaptorNIO *adapterState = (HSPAdaptorNIO *)selectedAdaptor->userData;
			sp->sFlow->agentIP = adapterState->ipAddr;
			sp->sFlow->agentDevice = my_strdup(selectedAdaptor->deviceName);
		}
	}

	if (sp->sFlow->agentIP.type == 0) { //still no agent IP
		myLog(LOG_ERR, "readConfig: no agent IP defined");
		RegCloseKey(hkey);
		return FALSE;
	}

	//Check to see whether config should be obtained via DNS-SD
	sp->DNSSD = FALSE;
	char dnssdStr[HSP_REGVAL_OFF_LEN];
	cbData = HSP_REGVAL_OFF_LEN;
	result = RegQueryValueEx(
		hkey,
		HSP_REGVAL_DNSSD,
		NULL,
		NULL,
		(LPBYTE)dnssdStr,
		&cbData);
	if (result == ERROR_SUCCESS) {
		if (StrCmpI(dnssdStr, HSP_REGVAL_OFF) != 0 && StrCmpI(dnssdStr, HSP_REGVAL_ON) != 0) {
			myLog(LOG_ERR, "readConfig: invalid setting for %s, expected \'%s\' or \'%s\', found %s",
				  HSP_REGVAL_DNSSD, HSP_REGVAL_ON, HSP_REGVAL_OFF, dnssdStr);
		} else {
			sp->DNSSD = StrCmpI(dnssdStr, HSP_REGVAL_ON) == 0;
		}
		if (sp->DNSSD) {
			//now look to see if the domain is overridden
			char domain[MAX_HOSTNAME_LEN];
			memset(domain, 0, MAX_HOSTNAME_LEN);
			cbData = MAX_HOSTNAME_LEN;
			result = RegQueryValueEx(
				hkey,
				HSP_REGVAL_DNSSD_DOMAIN,
				NULL,
				NULL,
				(LPBYTE)domain,
				&cbData);
			if (result == ERROR_SUCCESS) {
				sp->DNSSD_domain = my_strdup(domain);
			}
		}
		myLog(debug, "readConfig use DNS-SD=%s domain=%s", dnssdStr, sp->DNSSD_domain);
	} else {
		//registry setting not found so DNS-SD defaults to off.
		//myLog(LOG_ERR, "readConfig: error reading DNSSD value");
	}
	RegCloseKey(hkey);
	if (!sp->DNSSD) {
		HSPSFlowSettings settings = { 0 };
		readReg_sFlowSettings(HSP_REGKEY_PARMS, &settings, TRUE);
		//save the running config
		DWORD serialNumber = writeReg_sFlowSettings(HSP_REGKEY_CURRCONFIG, &settings);
		if (serialNumber == HSP_SERIAL_INVALID) {
			myLog(LOG_ERR, "readConfig: failed to save current config to %s", HSP_REGKEY_CURRCONFIG);
		}
		clearCollectors(&settings);
	}
	return TRUE;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
