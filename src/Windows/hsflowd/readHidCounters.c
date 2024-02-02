/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <VersionHelpers.h>

/**
 * Populates the host_descr structure with, computer name for hostname,
 * processor architecture, os_name (Windows), os version, and BIOS UUID.
 */
void readHidCounters(HSP *sp, SFLHost_hid_counters *hid){
	DWORD dwRes;
	OSVERSIONINFO osvi;
	SYSTEM_INFO si;
#define MAX_FDQN_CHARS 255
	char dnsBuf[MAX_FDQN_CHARS+1];
	DWORD dnsLen = MAX_FDQN_CHARS;

	if (GetComputerNameEx(ComputerNameDnsHostname,dnsBuf,&dnsLen)) {
		uint32_t copyLen = dnsLen < SFL_MAX_HOSTNAME_CHARS ? dnsLen :  SFL_MAX_HOSTNAME_CHARS;
		memcpy(hid->hostname.str, dnsBuf, copyLen);
		hid->hostname.str[copyLen] = '\0';
		hid->hostname.len = copyLen;
	}

	hid->os_name = SFLOS_windows;

	if (GetComputerNameExA(ComputerNameDnsHostname, dnsBuf, &dnsLen)) {
		uint32_t copyLen = dnsLen < SFL_MAX_HOSTNAME_CHARS ? dnsLen : SFL_MAX_HOSTNAME_CHARS;
		memcpy(hid->hostname.str, dnsBuf, copyLen);
		hid->hostname.str[copyLen] = '\0';
		hid->hostname.len = copyLen;
	}

	hid->os_name = SFLOS_windows;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (IsWindows10OrGreater()) {
		sprintf_s(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS, "%s", "Windows 10 or later");
	}
	else if (IsWindows8Point1OrGreater()) {
		sprintf_s(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS, "%s", "Windows 8.1 or later");
	}
	else if (IsWindows8OrGreater()) {
		sprintf_s(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS, "%s", "Windows 8 or later");
	}
	else if (IsWindows7SP1OrGreater()) {
		sprintf_s(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS, "%s", "Windows 7 SP1 or later");
	}
	else if (IsWindowsVistaSP2OrGreater()) {
		sprintf_s(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS, "%s", "Windows Vista SP2 or later");
	}
	else {
		sprintf_s(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS, "%d.%d.%d %s",
			osvi.dwMajorVersion,
			osvi.dwMinorVersion,
			osvi.dwBuildNumber,
			osvi.szCSDVersion);
	}

	hid->os_release.len = (uint32_t)strnlen(hid->os_release.str, SFL_MAX_OSRELEASE_CHARS);

	GetNativeSystemInfo(&si);
	hid->machine_type = SFLMT_unknown;
	switch(si.wProcessorArchitecture){
		case PROCESSOR_ARCHITECTURE_AMD64:
			hid->machine_type = SFLMT_x86_64;
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			hid->machine_type = SFLMT_ia64;
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			hid->machine_type = SFLMT_x86;
			break;
	}

	dwRes = readSystemUUID(hid->uuid);
	if (LOG_INFO <= debug) {
		u_char uuidbuf[FORMATTED_GUID_LEN+1];
		printUUID(hid->uuid, uuidbuf, FORMATTED_GUID_LEN);
		myLog(LOG_INFO,"readHidCounters:\n\thostname:\t%s\n\trelease:\t%s\n\tmachine_type:\t%d\n\tuuid:\t%s\n",
			hid->hostname.str, hid->os_release.str, hid->machine_type, uuidbuf);
	}
}

#if defined(__cplusplus)
} /* extern "C" */
#endif

