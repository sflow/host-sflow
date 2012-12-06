/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef HSFLOWD_H
#define HSFLOWD_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <tchar.h>
#include <ws2tcpip.h>
#include <WinSock2.h>
#include <windows.h> 
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <iphlpapi.h>
#include <Winsvc.h>
#include <pdh.h>
#include <pdhmsg.h>

#include "util.h"
#include "sflow_api.h"
#include "loadAverage.h"
#include "hypervUtil.h"
#include "../version.h"

#define HSP_VERSION VER_PRODUCT_VERSION_STR
#define HSP_SERVICE_NAME "hsflowd"
#define HSP_PUBLISHER L"Host sFlow Project"
#define HSP_PRODUCT_NAME L"Host sFlow Agent"
#define HSP_DEFAULT_LOGFILE "hsflowd.log"
#define HSP_DEFAULT_VMSTORE L"vms.txt"
#define HSP_DEFAULT_PORTSTORE L"ports.txt"
#define HSP_REGKEY_PARMS "system\\currentcontrolset\\services\\hsflowd\\Parameters"
#define HSP_REGKEY_CURRCONFIG "system\\currentcontrolset\\services\\hsflowd\\currentconfig"
#define HSP_REGKEY_COLLECTORS "collectors"
#define HSP_REGVAL_SERIAL "serialNumber"
#define HSP_REGVAL_COLLECTOR "collector"
#define HSP_REGVAL_PORT "port"
#define HSP_REGVAL_SAMPLING_RATE "samplingRate"
#define HSP_REGVAL_POLLING_INTERVAL "pollingInterval"
#define HSP_REGVAL_AGENT "agentAddress"
#define HSP_REGVAL_DNSSD "DNSSD"
#define HSP_REGVAL_DNSSD_DOMAIN "DNSSD_Domain"
#define HSP_REGVAL_ON "on"
#define HSP_REGVAL_OFF "off"
#define HSP_REGVAL_OFF_LEN 4 //include room for terminating NULL

// only one receiver, so the receiverIndex is a constant
#define HSP_SFLOW_RECEIVER_INDEX 1
/* Numbering to avoid clash. See http://www.sflow.org/developers/dsindexnumbers.php */
#define HSP_DEFAULT_PHYSICAL_DSINDEX 1
#define HSP_DEFAULT_LOGICAL_DSINDEX_START 100000

#define HSP_REFRESH_ADAPTORS 180
#define HSP_REFRESH_VMS 60
#define HSP_REFRESH_PORTS 5

/* Upper limit on the number of VIFs per VM */
#define HSP_MAX_VIFS 32

//Is the sFlow sampling filter active?
#define HSP_FILTER_ACTIVE(filter) (filter).dev!=INVALID_HANDLE_VALUE

#define HSP_MAX_TICKS 60
#define HSP_DEFAULT_DNSSD_STARTDELAY 30
#define HSP_DEFAULT_DNSSD_RETRYDELAY 300
#define HSP_DEFAULT_DNSSD_MINDELAY 10

//timeout for interval between checking for samples, signals and whether
//to generate next tick. Set so that we loop around several times/s.
#define HSP_TIMEOUT 200 

#define UNKNOWN_COUNTER    0xFFFFFFFF 
#define UNKNOWN_COUNTER_64 0xFFFFFFFFFFFFFFFF
#define UNKNOWN_GAUGE    0xFFFFFFFF 
#define UNKNOWN_GAUGE_64 0xFFFFFFFFFFFFFFFF
#define UNKNOWN_PERCENT -1
#define UNKNOWN_INT 0
#define UNKNOWN_FLOAT -1

#define WMI_WMI_NS L"root\\wmi"
#define WMI_CIMV2_NS L"root\\cimv2"
#define WMI_STD_CIMV2_NS L"root\\standardcimv2"
#define WMI_VIRTUALIZATION_NS_V1 L"root\\virtualization"
#define WMI_VIRTUALIZATION_NS_V2 L"root\\virtualization\\v2"

  // forward declarations
  struct _HSPSFlow;
  struct _HSP;

  typedef struct _HSPCollector {
    struct _HSPCollector *nxt;
	CHAR *name; //IP or DNS name read from config
    SFLAddress ipAddr;
    uint32_t udpPort;
    struct sockaddr_in6 sendSocketAddr;
  } HSPCollector;

  typedef struct _HSPSFlowSettings {
#define HSP_SERIAL_INVALID 0UL
	DWORD serialNumber;
	HSPCollector *collectors;
    uint32_t numCollectors;
    uint32_t pollingInterval;
	uint32_t samplingRate;
	uint32_t headerBytes;
#define HSP_MAX_HEADER_BYTES 256
  } HSPSFlowSettings;

  typedef struct _HSPSFlow {
    struct _HSP *myHSP;
    SFLAgent *agent;
    SFLPoller *poller;
    HSPSFlowSettings *sFlowSettings;
	uint32_t revision;
    uint32_t subAgentId;
    char *agentDevice;
    SFLAddress agentIP;
  } HSPSFlow; 

  typedef enum {
	  HSPSTATE_READCONFIG = 0,
	  HSPSTATE_WAITCONFIG,
	  HSPSTATE_RUN,
	  HSPSTATE_END
  } EnumHSPState;

  typedef enum { 
	  IPSP_NONE=0,
	  IPSP_LOOPBACK6, //::1/128
	  IPSP_LOOPBACK4,
	  IPSP_SELFASSIGNED4,
	  IPSP_IP6_SCOPE_LINK, //FE80::/10
	  IPSP_IP6_SCOPE_UNIQUE, //FC00::/7
	  IPSP_IP6_SCOPE_GLOBAL,
	  IPSP_IP4,
  } EnumIPSelectionPriority;

   // cache nio counters per adaptor
  typedef struct _HSPAdaptorNIO {
    wchar_t *countersInstance; //Win32_NetworkAdapter.Name with reserved chars replaced
	SFLAddress ipAddr;
	EnumIPSelectionPriority ipPriority;
	BOOL isVirtual;
    int32_t bond_master;
	SFLHost_nio_counters new_nio;
    SFLHost_nio_counters nio;
    SFLHost_nio_counters last_nio;
    uint32_t last_bytes_in32;
    uint32_t last_bytes_out32;
#define HSP_MAX_NIO_DELTA32 0x7FFFFFFF
#define HSP_MAX_NIO_DELTA64 (uint64_t)(1.0e13)
    time_t last_update;
  } HSPAdaptorNIO;

/**
 * Contains the info we need to read from the sFlow Filter device
 * to receive samples
 */
typedef struct {
  HANDLE dev;
  #define numConcurrentReads 32
  #define bufferLength 256 //TODO needs to be longer than max header bytes
  #define ioctlBufferLength 256
  OVERLAPPED overlaps[numConcurrentReads];
  UCHAR buffers[numConcurrentReads][bufferLength];
  OVERLAPPED ioctlOverlap;
} HSPFilter;

/**
 * Used to queue counter poller callbacks so that servicing packet samples
 * and counter callbacks can be scheduled and avoid samples being dropped
 * if we are busy servicing counter poller callbacks.
 */
typedef struct _HSPPollerQ {
	_HSPPollerQ *nxt;
	void *magic;
	SFLPoller *poller; 
} HSPPollerQ;

typedef struct _HSP {
    HSPSFlow *sFlow;
	time_t clk;
	HSPPollerQ *pollerQHead;
	HSPPollerQ *pollerQTail;
    // interfaces and MACs
    SFLAdaptorList *adaptorList;
	time_t nio_last_update;
	time_t nio_polling_secs;
#define HSP_NIO_POLLING_SECS_32BIT 3
	BOOL hyperV; //set when HyperV is detected as running
	// virtual adaptors and switch ports
	uint32_t portInfoRevision; //global revision for filter info
	SFLAdaptorList *vAdaptorList;
	//VMs
	uint32_t num_partitions;
	BOOL refreshVms;
	//persistent state
	uint32_t maxIfIndex;
	WCHAR *portStoreFile;
	FILE *f_portStore;
	GuidStore *portStore;
	BOOL portStoreInvalid;
	uint32_t maxDsIndex;
	WCHAR *vmStoreFile;
	FILE *f_vmStore;
	GuidStore *vmStore;
	BOOL vmStoreInvalid;
	//config params via DNS-SD
	BOOL DNSSD;
	CHAR *DNSSD_domain;
	time_t DNSSD_countdown;
	uint32_t DNSSD_startDelay;
	uint32_t DNSSD_retryDelay;
	uint32_t DNSSD_ttl; //only accessed on DNS thread
    // UDP send sockets
    SOCKET socket4;
    SOCKET socket6;
	SFLHost_hid_counters host_hid;
	//filter for sampling
	HSPFilter filter;
  } HSP;

// config parser
BOOL readConfig(HSP *sp);
BOOL readSFlowSettings(HSPSFlowSettings *settings);
BOOL newerSettingsAvailable(HSPSFlowSettings *settings);
void insertCollector(HSPSFlowSettings *settings, CHAR *name, DWORD port);
void clearCollectors(HSPSFlowSettings *settings);
unsigned __stdcall runDNSSD(void *magic);
void removeQueuedPoller(HSP *sp, SFLPoller *poller);

void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);
void getCounters_host(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);
void getCounters_interface(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);
void getCounters_vm(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);

// read functions
void readInterfaces(HSP *sp, BOOL getIpAddr);
void readCpuCounters(SFLHost_cpu_counters *cpu);
BOOL readMemoryCounters(SFLHost_mem_counters *mem);
void readDiskCounters(SFLHost_dsk_counters *dsk);
BOOL readNioCounters(HSP *sp, SFLHost_nio_counters *dsk);
void updateNioCounters(HSP *sp);
void readHidCounters(HSP *sp, SFLHost_hid_counters *hid);
BOOL readSystemUUID(u_char *uuidbuf);
void readVms(HSP *sp);

EnumIPSelectionPriority agentAddressPriority(SFLAddress *addr);

// using DNS SRV+TXT records
#define SFLOW_DNS_SD "_sflow._udp"
#define HSP_MAX_DNS_LEN 255
int dnsSD(HSP *sp, HSPSFlowSettings *settings);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */
