/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <windns.h>

#define HSF_MIN_DNAME 4  /* what is the shortest FQDN you can have? */
#define HSF_MIN_TXT 4  /* what is the shortest meaingful TXT record here? */
#define HSF_MAX_TXT_LEN 255 //include NULL

/**
 * Parses the DNS TXT record, txt, to extract the sampling rate and
 * polling interval settings which are then used to populate the
 * HSPSFlowSettings, settings.
 */
static void dnsSD_parseTxt(HSPSFlowSettings *settings,
						   CHAR *txt)
{
	//each TXT record should be of the form key=value
	size_t len;
	len = strcspn(txt, "=");
	if (len == 0 || len >= strnlen_s(txt, HSF_MAX_TXT_LEN)) {
		myLog(LOG_ERR, "dnsSD_parseTxt: invalid TXT record %s", txt);
	} else {
		CHAR *key;
		CHAR *value;
		key = txt;
		value= txt+len+1;
		if (strncmp("txtvers", key, len-1) == 0) {
			//don't do anything with this one yet
		} else if (strncmp("sampling", key, len-1) == 0) {
			settings->samplingRate = strtol(value, NULL, 10);
		} else if (strncmp("polling", key, len-1) == 0) {
			settings->pollingInterval = strtol(value, NULL, 10);
		}
		//TODO application polling and sampling "polling.*" and "sampling.*"
	}
}

/**
 * Issues the DNS request to discover the sFlow service settings
 * (collector addresses and ports, sampling rates and polling intervals).
 * The DNS request is configured to bypass the DNS cache and go straight
 * to the wire to avoid using stale entries.
 * If the request succeeds, updates the min TTL in HSP *sp, parses the response,
 * and returns the number of records returned, populating HSPSFlowSettings *settings
 * with the parsed result.
 * If the request fails, returns -1.
 * char *dname contains the DNS query (fully qualified)
 * WORD dtype the DNS query type (SRV for collectors or TEXT for sampling rates
 * and polling intervals)
 * Note that we are using the DnsQuery function to make the DNS request.
 * This function does not take into account the system DNS search path, so the
 * DNS query must be fully qualified (ie include the domain to search).
 */
static int dnsSD_Request(HSP *sp, HSPSFlowSettings *settings,
						 char *dname, WORD rtype)
{
	PDNS_RECORD pDnsRecord;
	DNS_FREE_TYPE dnsFreeType;
	dnsFreeType = DnsFreeRecordListDeep;
	DNS_STATUS status = DnsQuery(dname, rtype, DNS_QUERY_WIRE_ONLY, NULL, &pDnsRecord, NULL);
	if (status) {
		//fail
		logErr(LOG_ERR, status, "dnsSD_Request: DNSQuery(%s, %u) failed error=%u", dname, rtype, status);
		return -1;
	} else {
		 //process results and free
		int answerCount = 0;
		PDNS_RECORD nextRecord = pDnsRecord;
		while (nextRecord != NULL) {
			//update the minimum ttl
			DWORD ttl = nextRecord->dwTtl;
			if (sp->DNSSD_ttl == 0 || ttl < sp->DNSSD_ttl) {
				sp->DNSSD_ttl = ttl;
			}
			switch(rtype) {
			case DNS_TYPE_TEXT:
				if (nextRecord->wType == DNS_TYPE_TEXT) {
					answerCount++;
					DWORD stringCount = nextRecord->Data.TXT.dwStringCount;
					for (DWORD i = 0; i < stringCount; i++) {
						if (LOG_INFO <= debug) {
							myLog(LOG_INFO, "dnsDS_Request: DNS_TYPE_TEXT %s",
								nextRecord->Data.TXT.pStringArray[i]);
						}
						dnsSD_parseTxt(settings,
									   nextRecord->Data.TXT.pStringArray[i]);
					}
				}
				break;
			case DNS_TYPE_SRV:
				if (nextRecord->wType == DNS_TYPE_SRV) {
					answerCount++;
					if (LOG_INFO <= debug) {
						myLog(LOG_INFO, "dnsDS_Request: DNS_TYPE_SRV %s %u",
							nextRecord->Data.SRV.pNameTarget, nextRecord->Data.SRV.wPort);
					}
					insertCollector(settings, nextRecord->Data.SRV.pNameTarget, 
						nextRecord->Data.SRV.wPort);
				}
				break;
			default:
				DnsRecordListFree(pDnsRecord, dnsFreeType);
				myLog(LOG_ERR, "dnsDS_Request: unsupported query type %u", rtype);
				return -1;
			}
			nextRecord = nextRecord->pNext;
		}
		DnsRecordListFree(pDnsRecord, dnsFreeType);
		return answerCount;
	}
}

/**
 * Runs the DNS-SD sequence to discover the sFlow server settings,
 * collector addresses and ports and sampling rates and polling interval
 * settings.
 * The DNS query is scoped to query for entries in the domain (zone)
 * configured as the domain override in the registry (if set), or the
 * primary domain name configured on the system if there is no domain
 * override.
 * Note that the DNS query could fail or return no results if we are
 * unable to discover the primary domain of the system.
 * HSP *sp used to update the min TTL for DNS entries so that the
 * next DNS request can be scheduled.
 * HSPSFlowSettings *settings in which sFlow collector addresses and ports
 * and sampling and polling settings will be populated.
 * Returns the number of sFlow collectors discovered or -1 on failure.
 */
int dnsSD(HSP *sp, HSPSFlowSettings *settings)
{
    char request[HSP_MAX_DNS_LEN];
	if (sp->DNSSD_domain) {
		sprintf_s(request, HSP_MAX_DNS_LEN, "%s%s", SFLOW_DNS_SD, sp->DNSSD_domain);
	} else {
		char domain[MAX_HOSTNAME_LEN];
		memset(domain, 0, MAX_HOSTNAME_LEN);
		DWORD len = MAX_HOSTNAME_LEN;
		char *dot = "";
		if (GetComputerNameEx(ComputerNameDnsDomain, domain, &len) == 0) {
			DWORD err = GetLastError();
			logErr(LOG_ERR, err, "dnsSD: cannot determined DNS domain for this computer error=%u", err);
		} else if (len == 0) {
			myLog(LOG_ERR, "dnsSD: DNS domain for this computer not set");
		} else {
			dot = ".";
		}
		sprintf_s(request, HSP_MAX_DNS_LEN, "%s%s%s", SFLOW_DNS_SD, dot, domain);
	}
	myLog(LOG_INFO, "dnsSD: request=%s", request);
    int num_servers = dnsSD_Request(sp, settings, request, DNS_TYPE_SRV);
    dnsSD_Request(sp, settings, request, DNS_TYPE_TEXT);
    // it's ok even if only the SRV request succeeded
    return num_servers; //  -1 on error
}

#if defined(__cplusplus)
} /* extern "C" */
#endif