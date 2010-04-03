/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef HSFLOWD_H
#define HSFLOWD_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>

#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> // for PRIu64 etc.

#include "sflow_api.h"

#define YES 1
#define NO 0

#define HSP_VERSION "1.0.0"
#define HSP_DAEMON_NAME "hsflowd"
#define HSP_DEFAULT_PIDFILE "/var/run/hsflowd.pid"
#define HSP_DEFAULT_CONFIGFILE "/etc/hsflowd.conf"

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
  } HSP;

  // config parser
  int HSPReadConfigFile(HSP *sp);

  // logger
  void myLog(int syslogType, char *fmt, ...);

  // read functions
  int readInterfaces(HSP *sp);
  int readCpuCounters(SFLHost_cpu_counters *cpu);
  int readMemoryCounters(SFLHost_mem_counters *mem);
  int readDiskCounters(SFLHost_dsk_counters *dsk);
  int readNioCounters(SFLHost_nio_counters *dsk);
  int readHidCounters(SFLHost_hid_counters *dsk, char *buf, int bufLen);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */
