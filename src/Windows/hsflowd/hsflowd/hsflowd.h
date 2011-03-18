/* Copyright (c) 2009 InMon Corp. ALL RIGHTS RESERVED */
/* License: http://www.inmon.com/products/virtual-probe/license.php */

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

#define YES 1
#define NO 0

#define HSP_VERSION "1.0.0"
#define HSP_DAEMON_NAME "hsflowd"
#define HSP_DEFAULT_PIDFILE "/var/run/hsflowd.pid"
#define HSP_DEFAULT_CONFIGFILE "/etc/hsflowd.conf"

#define UNKNOWN_COUNTER    0xFFFFFFFF 
#define UNKNOWN_COUNTER_64 0xFFFFFFFFFFFFFFFF
#define UNKNOWN_GAUGE    0xFFFFFFFF 
#define UNKNOWN_GAUGE_64 0xFFFFFFFFFFFFFFFF
#define UNKNOWN_PERCENT -1
#define UNKNOWN_INT 0
#define UNKNOWN_FLOAT -1



  // forward declarations
  struct _HSPSFlow;
  struct _HSP;

  typedef struct _HSPSFlowSettings {
    uint32_t pollingInterval;
  } HSPSFlowSettings;

  typedef struct _HSPCollector {
    struct _HSPCollector *nxt;
    SFLAddress ipAddr;
    uint32_t udpPort;
    struct sockaddr_in6 sendSocketAddr;
  } HSPCollector;

  typedef struct _HSPSFlow {
    struct _HSP *myHSP;
    SFLAgent *agent;
    SFLPoller *poller;
    HSPCollector *collectors;
    uint32_t numCollectors;
    HSPSFlowSettings *sFlowSettings;
    uint32_t subAgentId;
    SFLAdaptor *agentDevice;
    SFLAddress agentIP;
  } HSPSFlow; 

  typedef struct _HSP {
    HSPSFlow *sFlow;
    char *configFile;
    char *pidFile;
    // interfaces and MACs
    SFLAdaptorList *adaptorList;
    // UDP send sockets
    int socket4;
    int socket6;
	SFLHost_hid_counters host_hid;
  } HSP;

  // config parser
  int HSPReadConfig(HSP *sp);

  // read functions
  int readInterfaces(HSP *sp);
  int readCpuCounters(SFLHost_cpu_counters *cpu);
  int readMemoryCounters(SFLHost_mem_counters *mem);
  int readDiskCounters(SFLHost_dsk_counters *dsk);
  int readNioCounters(SFLHost_nio_counters *dsk);
  int readHidCounters(HSP *sp, SFLHost_hid_counters *hid);
  int readSystemUUID(u_char *uuidbuf);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */
