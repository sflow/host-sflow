/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#define MAX_IPV6_STRLEN 46
#define MAX_IPV4_STRLEN 16

extern int debug;
 
/**
 * Looks up host name or IP address and converts to SFLAddress, storing it in the
 * specified SFLAddress. Returns TRUE on success, FALSE on failure.
 * char *name A pointer to a NULL-terminated ANSI string that contains a hostname or 
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
    
/**
 * Initialises the sFlow settings (polling interval and sampling rate)
 * with defaults.
 */
static HSPSFlowSettings *newSFlowSettings(HSPSFlow *sf) 
{
	HSPSFlowSettings *st = (HSPSFlowSettings *)my_calloc(sizeof(HSPSFlowSettings));
	st->pollingInterval = SFL_DEFAULT_POLLING_INTERVAL;
	st->samplingRate = SFL_DEFAULT_SAMPLING_RATE;
	st->headerBytes = SFL_DEFAULT_HEADER_SIZE;
	return st;
}

static HSPSFlow *newSFlow(HSP *sp)
{
	HSPSFlow *sf = (HSPSFlow *)my_calloc(sizeof(HSPSFlow));
	sf->sFlowSettings = newSFlowSettings(sf);
	sf->subAgentId = 0;
	sp->sFlow = sf; // just one of these, not a list
	sf->myHSP = sp;
	return sf;
}

static HSPCollector *newCollector(HSPSFlow *sf)
{
	HSPCollector *col = (HSPCollector *)my_calloc(sizeof(HSPCollector));
	ADD_TO_LIST(sf->collectors, col);
	sf->numCollectors++;
	col->udpPort = SFL_DEFAULT_COLLECTOR_PORT;
	return col;
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
 * Reads the saved sFlow configuration from the registry settings.
 * Returns TRUE if all settings are valid, FALSE if the agent address
 * cannot be determined or there is no collector address
 * agent address - if set in the registry and valid (IPv4, IPv6 or hostname),
 * use this (without checking for is it is an address owned by this host),
 * otherwise, pick the best IPv4 address from the current adapters.
 * Note that in this case we are limited to IPv4 because the
 * SFLAdaptor struct only supports IPv4.
 * Collector address can be IPv4, IPv6 or hostname
 */
BOOL readConfig(HSP *sp)
{
	DWORD dwRet,cbData;
	HKEY hkey;
	dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						 HSP_REG_KEY,
						 0,
						 KEY_QUERY_VALUE,
						 &hkey);
	if (dwRet != ERROR_SUCCESS) {
		myLog(LOG_ERR, "readConfig: %s registry key not found", HSP_REG_KEY);
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
	dwRet = RegQueryValueEx(hkey,
                            HSP_REGVAL_AGENT,
                            NULL,
                            NULL,
                            (LPBYTE)agentStr,
                            &cbData);
	if (dwRet == ERROR_SUCCESS) {
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
	//Read the collector address from the registry
	newCollector(sp->sFlow);
	HSPCollector *collector = sp->sFlow->collectors;
	char collectorStr[MAX_HOSTNAME_LEN];
	memset(collectorStr, 0, MAX_HOSTNAME_LEN);
	cbData = MAX_HOSTNAME_LEN;
	dwRet = RegQueryValueEx(hkey,
                            HSP_REGVAL_COLLECTOR,
                            NULL,
                            NULL,
                            (LPBYTE)collectorStr,
                            &cbData );
	if (dwRet != ERROR_SUCCESS) {
		myLog(LOG_ERR, "readConfig: No collector");
		RegCloseKey(hkey);
		return FALSE;
	}
	lookupAddress(collectorStr, PF_UNSPEC, (struct sockaddr *)&collector->sendSocketAddr, &collector->ipAddr);
	if (collector->ipAddr.type == 0) {
		myLog(LOG_ERR, "readConfig: invalid collector %s", collectorStr);
		RegCloseKey(hkey);
		return FALSE;
	}

	//Read the sampling rate and polling interval from the registry.
	//If values do not exist, we will use the already initialised
	//defaults (see newSFlowSettings()).
	DWORD dwSamplingRate = 0;
	dwRet = RegQueryValueEx(hkey,
							HSP_REGVAL_SAMPLING_RATE,
							NULL,
							NULL,
							(LPBYTE)&dwSamplingRate,
							&cbData);
	if (dwRet == ERROR_SUCCESS) {
		sp->sFlow->sFlowSettings->samplingRate = dwSamplingRate;
	}

	DWORD dwPollingInterval = 0;
	dwRet = RegQueryValueEx(hkey,
							HSP_REGVAL_POLLING_INTERVAL,
							NULL,
							NULL,
							(LPBYTE)&dwPollingInterval,
							&cbData);
	if (dwRet == ERROR_SUCCESS) {
		sp->sFlow->sFlowSettings->pollingInterval = dwPollingInterval;
	}
	RegCloseKey(hkey);

	memset(agentStr, 0, MAX_IPV6_STRLEN);
	memset(collectorStr, 0, MAX_HOSTNAME_LEN);
	if (sp->sFlow->agentIP.type == SFLADDRESSTYPE_IP_V4) {
		InetNtop(AF_INET, &sp->sFlow->agentIP.address.ip_v4.addr, agentStr, MAX_IPV6_STRLEN);
	} else if (sp->sFlow->agentIP.type == SFLADDRESSTYPE_IP_V6) {
		InetNtop(AF_INET6, &sp->sFlow->agentIP.address.ip_v6, agentStr, MAX_IPV6_STRLEN); 
	}
	if (collector->ipAddr.type == SFLADDRESSTYPE_IP_V4) {
		InetNtop(AF_INET, &collector->ipAddr.address.ip_v4.addr, collectorStr, MAX_IPV6_STRLEN); 
	} else if (collector->ipAddr.type == SFLADDRESSTYPE_IP_V6) {
		InetNtop(AF_INET6, &collector->ipAddr.address.ip_v6, collectorStr, MAX_IPV6_STRLEN); 
	}
	myLog(debug, "readConfig: agent=%s collector=%s samplingRate=%u pollingInterval=%u",
		  agentStr, collectorStr, sp->sFlow->sFlowSettings->samplingRate, 
		  sp->sFlow->sFlowSettings->pollingInterval);
    return TRUE;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
