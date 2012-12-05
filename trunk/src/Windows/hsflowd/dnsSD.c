/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <windns.h>

extern int debug;

#define HSF_MIN_DNAME 4  /* what is the shortest FQDN you can have? */
#define HSF_MIN_TXT 4  /* what is the shortest meaingful TXT record here? */
#define HSF_MAX_TXT_LEN 255 //include NULL

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

static int dnsSD_Request(HSP *sp, HSPSFlowSettings *settings,
						 char *dname, WORD rtype)
{
	PDNS_RECORD pDnsRecord;
	DNS_FREE_TYPE dnsFreeType;
	dnsFreeType = DnsFreeRecordListDeep;
	DNS_STATUS status = DnsQuery(dname, rtype, DNS_QUERY_WIRE_ONLY, NULL, &pDnsRecord, NULL);
	if (status) {
		//fail
		myLog(LOG_ERR, "dnsSD_Request: DNSQuery(%s, %u) failed error=%u", dname, rtype, status);
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

int dnsSD(HSP *sp, HSPSFlowSettings *settings)
{
    char request[HSP_MAX_DNS_LEN];
	if (sp->DNSSD_domain) {
		sprintf_s(request, HSP_MAX_DNS_LEN, "%s%s", SFLOW_DNS_SD, sp->DNSSD_domain);
	} else {
		void *buff;
		DWORD len;
		DNS_STATUS status;
		status = DnsQueryConfig(DnsConfigPrimaryDomainName_A, DNS_CONFIG_FLAG_ALLOC, NULL, NULL, &buff, &len);
		char *domain;
		char *dot = "";
		if (status) {
			domain = "";
			myLog(LOG_ERR, "dnsSD: DnsQueryConfig(DnsConfigPrimaryDomainName_A) failed error=%u", status);
			// status == ERROR_OUTOFMEMORY if domain is not configured 
			//(set domain in Control Panel>System, change computer name, full name under More
		} else {
			domain = (char *)buff;
			dot = ".";
		}
		sprintf_s(request, HSP_MAX_DNS_LEN, "%s%s%s", SFLOW_DNS_SD, dot, domain);
		LocalFree(buff);
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