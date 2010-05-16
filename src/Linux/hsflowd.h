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
#include "sys/mman.h" // for mlockall

#include "sflow_api.h"

#ifdef __XEN_TOOLS__
#include "xs.h"
#include "xenctrl.h"
#include "dirent.h"
#endif

#define YES 1
#define NO 0

#define HSP_VERSION "1.0.0"
#define HSP_DAEMON_NAME "hsflowd"
#define HSP_DEFAULT_PIDFILE "/var/run/hsflowd.pid"
#define HSP_DEFAULT_CONFIGFILE "/etc/hsflowd.conf"
#define HSP_DEFAULT_SUBAGENTID 100
#define HSP_MAX_SUBAGENTID 1000000

  // only one receiver, so the receiverIndex is a constant
#define HSP_SFLOW_RECEIVER_INDEX 1

// just assume the sector size is 512 bytes
#define HSP_SECTOR_BYTES 512

// upper limit on number of VIFs per VM
#define HSP_MAX_VIFS 64

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
    int refreshAdaptorList;
    int refreshVMList;
    // UDP send sockets
    int socket4;
    int socket6;
#ifdef __XEN_TOOLS__
    int xc_handle; // libxc
    struct xs_handle *xs_handle; // xenstore
    uint32_t page_size;
    uint32_t num_domains;
#endif
  } HSP;

// userData structure to store state for VM data-sources
typedef struct _HSPVMState {
  uint32_t network_count;
  int32_t marked;
  uint32_t vm_index;
} HSPVMState;

  // config parser
  int HSPReadConfigFile(HSP *sp);
  int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen);

  // logger
  void myLog(int syslogType, char *fmt, ...);

  // read functions
  int readInterfaces(HSP *sp);
  int readCpuCounters(SFLHost_cpu_counters *cpu);
  int readMemoryCounters(SFLHost_mem_counters *mem);
  int readDiskCounters(SFLHost_dsk_counters *dsk);
  int readNioCounters(SFLHost_nio_counters *dsk, char *devFilter);
  int readHidCounters(SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */
