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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>

#include <sys/mman.h> // for mlockall()
#include <pwd.h> // for getpwnam()
#include <grp.h>
#include <sys/resource.h> // for setrlimit()
#include <limits.h> // for UINT_MAX

// for signal backtrace
#include <execinfo.h>
#include <signal.h>
#include <ucontext.h>

#include <stdarg.h> // for va_start()
#include "util.h"
#include "sflow_api.h"

#ifdef HSF_XEN
// xs.h because xenstore.h
#ifdef HSF_XENSTORE_H
#include "xenstore.h"
#else
#include "xs.h"
#endif
#include "xenctrl.h"
#include "dirent.h"
#include "regex.h" // for vif detection
// The pattern on a xenserver is usually just "vif%d.%d" but
// different platforms may have different strings here, so
// make it a regular expression that can be changed at
// compile time.  This expression looks for anything that
// has "vif" in it and ends with domid.netid,  which might
// actually work for all xen variants.
#define HSF_XEN_VIF_REGEX "vif[^0-9]*([0-9]+)\\.([0-9]+)$"
#define HSF_XEN_VIF_REGEX_NMATCH 3 // fields-to-extract + 1
#endif

#ifdef HSF_VRT
#include "libvirt.h"
#include "libxml/xmlreader.h"
#endif

#ifdef HSF_DOCKER
#define HSF_CAPABILITIES
/* Typically need libcap-dev[el] package */
#include <linux/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sched.h>

#include "cJSON.h"
  typedef struct _HSFNameVal {
    char *nv_name;
    int nv_found;
    uint64_t nv_val64;
  } HSFNameVal;

  // forward declarations
  struct _HSPSFlow;
  struct _HSP;

  typedef struct _HSPContainer {
    struct _HSPContainer *nxt;
    char *id;
    char *longId;
    char *name;
    char *hostname;
    char uuid[16];
    uint32_t dsIndex;
    pid_t pid;
      int running:1;
      int marked:1;
    uint64_t memoryLimit;
  } HSPContainer;
#define HSF_DOCKER_CMD "/usr/bin/docker"
#define HSF_NETNS_DIR "/var/run/netns"
#define HSF_IP_CMD "/usr/sbin/ip"
#define HSF_DOCKER_MAX_FNAME_LEN 255
#define HSF_DOCKER_MAX_LINELEN 512
#define HSF_DOCKER_SHORTID_LEN 12
#endif

#ifdef HSF_CUMULUS
#define HSP_ETHTOOL_STATS 1
#define HSP_SWITCHPORT_CONFIG 1
#define HSP_SWITCHPORT_CONFIG_PROG  "/usr/lib/cumulus/portsamp"
#include "regex.h" // for switchport detection
#define HSP_SWITCHPORT_REGEX "^swp[0-9s]+$"
  // uses ULOG (netlink) channel, so make sure that is enabled:
#ifndef HSF_NFLOG
#define HSF_ULOG 1
#define HSP_DEFAULT_ULOG_GROUP 1
#endif
  // starting in CL 2.5, uses NFLOG, also defaulting to group==1
#define HSP_DEFAULT_NFLOG_GROUP 1
#endif

#if (HSF_ULOG || HSF_NFLOG || HSF_PCAP)
#include <linux/types.h>
#include <linux/netlink.h>
#include <net/if.h>
#define HSP_READPACKET_BATCH 10000
#endif

#ifdef HSF_ULOG
#include <linux/netfilter_ipv4/ipt_ULOG.h>
#define HSP_MAX_ULOG_MSG_BYTES 10000
#define HSP_ULOG_RCV_BUF 8000000
#endif /* HSF_ULOG */

#ifdef HSF_NFLOG
/* Set this to 65K+ to make sure we handle the
   case where virtual port TSOs coallesce packets
   (ignoring MTU constraints). */
#define HSP_MAX_NFLOG_MSG_BYTES 65536 + 128
#define HSP_NFLOG_RCV_BUF 8000000

#include <linux/netfilter/nfnetlink_log.h>
#include <libnfnetlink.h>
#endif /* HSF_NFLOG */

#ifdef HSF_PCAP
#include <pcap.h>
  typedef struct _BPFSoc {
    struct _BPFSoc *nxt;
    struct _HSP *myHSP;
    char *deviceName;
    int soc;
    uint32_t samplingRate;
    uint32_t subSamplingRate;
    uint32_t drops;
    uint32_t isBridge:1;
    pcap_t *pcap;
    char pcap_err[PCAP_ERRBUF_SIZE];
  } BPFSoc;
#endif /* HSF_PCAP */

#ifdef HSF_JSON
#include "cJSON.h"
#define HSP_MAX_JSON_MSG_BYTES 10000
#define HSP_READJSON_BATCH 100
#define HSP_JSON_RCV_BUF 2000000

  typedef struct _HSPApplication {
    struct _HSPApplication *ht_nxt;
    char *application;
    uint32_t hash;
    uint32_t dsIndex;
    uint16_t servicePort;
    uint32_t service_port_clash;
    uint32_t settings_revisionNo;
    int json_counters;
    int json_ops_counters;
    time_t last_json_counters;
    time_t last_json;
#define HSP_COUNTER_SYNTH_TIMEOUT 120
#define HSP_JSON_APP_TIMEOUT 7200
    SFLSampler *sampler;
    SFLPoller *poller;
    SFLCounters_sample_element counters;
  } HSPApplication;

#endif /* HSF_JSON */

#ifdef HSF_NVML
  #include <nvml.h>
#endif // HSF_NVML

#define ADD_TO_LIST(linkedlist, obj) \
  do { \
    obj->nxt = linkedlist; \
    linkedlist = obj; \
  } while(0)

#define HSP_DAEMON_NAME "hsflowd"
#define HSP_DEFAULT_PIDFILE "/var/run/hsflowd.pid"
#define HSP_DEFAULT_CONFIGFILE "/etc/hsflowd.conf"
#define HSP_DEFAULT_OUTPUTFILE "/etc/hsflowd.auto"
#define HSP_DEFAULT_VMSTORE_FILE "/etc/hsflowd.data"
#define HSP_DEFAULT_CRASH_FILE "/etc/hsflowd.crash"

#ifndef HSP_DEFAULT_ULOG_GROUP
#define HSP_DEFAULT_ULOG_GROUP 0
#endif
#ifndef HSP_DEFAULT_NFLOG_GROUP
#define HSP_DEFAULT_NFLOG_GROUP 0
#endif
#define HSP_DEFAULT_JSON_PORT 0

/* Numbering to avoid clash. See http://www.sflow.org/developers/dsindexnumbers.php */
#define HSP_DEFAULT_PHYSICAL_DSINDEX 1
#define HSP_DEFAULT_SUBAGENTID 100000
#define HSP_MAX_SUBAGENTID 199999
#define HSP_DEFAULT_LOGICAL_DSINDEX_START 100000
#define HSP_DEFAULT_APP_DSINDEX_START 150000
#define HSP_MAX_TICKS 60
#define HSP_DEFAULT_DNSSD_STARTDELAY 30
#define HSP_DEFAULT_DNSSD_RETRYDELAY 300
#define HSP_DEFAULT_DNSSD_MINDELAY 10
#define HSP_DNSSD_STACKSIZE 2000000
#define HSP_REFRESH_VMS 60
#define HSP_FORGET_VMS 180
#define HSP_REFRESH_ADAPTORS 180

// set to 1 to allow agent.cidr setting in DNSSD TXT record.
// This is currently considered out-of-scope for the DNSSD config,
// so for now the agent.cidr setting is only allowed in hsflowd.conf.
#define HSP_DNSSD_AGENTCIDR 0

// the limit we will request before calling mlockall()
// calling res_search() seems to allocate about 11MB
// (not sure why), so set the limit accordingly.
// #define HSP_RLIMIT_MEMLOCK (1024 * 1024 * 15)
// set to 0 to disable the memlock feature
#define HSP_RLIMIT_MEMLOCK 0

// only one receiver, so the receiverIndex is a constant
#define HSP_SFLOW_RECEIVER_INDEX 1

// space to ask for in output sockets
#define HSP_SFLOW_SND_BUF 2000000

// just assume the sector size is 512 bytes
#define HSP_SECTOR_BYTES 512

// upper limit on number of VIFs per VM
// constrain this to make sure we can't overflow the sFlow datagram
// if we include lots of interfaces that should be left out. Each
// adaptor takes 16 bytes, so this sets the limit for the adaptorList
// structure to 516 bytes (see sflow_receiver.c)
#define HSP_MAX_VIFS 32
// similar constraint on the number of adaptors that we will
// list for a physical host
#define HSP_MAX_PHYSICAL_ADAPTORS 32

  // For when a switch-port is configured using the default
  // (calculated) sampling-rate (based on link speed)
#define HSP_SPEED_SAMPLING_RATIO 1000000
#define HSP_SPEED_SAMPLING_MIN 100

  typedef struct _HSPCollector {
    struct _HSPCollector *nxt;
    SFLAddress ipAddr;
    uint32_t udpPort;
    struct sockaddr_in6 sendSocketAddr;
  } HSPCollector;

  typedef struct _HSPPcap {
    struct _HSPPcap *nxt;
    char *dev;
  } HSPPcap;

  typedef struct _HSPCIDR {
    struct _HSPCIDR *nxt;
    SFLAddress ipAddr;
    SFLAddress mask;
    uint32_t maskBits;
  } HSPCIDR;

#define SFL_UNDEF_COUNTER(c) c=(typeof(c))-1
#define SFL_UNDEF_GAUGE(c) c=0

  typedef struct _HSPApplicationSettings {
    struct _HSPApplicationSettings *nxt;
    char *application;
    int got_sampling_n;
    uint32_t sampling_n;
    int got_polling_secs;
    uint32_t polling_secs;
  } HSPApplicationSettings;

  typedef struct _HSPSFlowSettings {
    HSPCollector *collectors;
    uint32_t numCollectors;
    HSPPcap *pcaps;
    uint32_t numPcaps;
    uint32_t samplingRate;
    uint32_t pollingInterval;
    uint32_t headerBytes;
    uint32_t datagramBytes;

    // performance tuning options for Xen
    int xen_update_dominfo; // update dominfo for every VM at poll-time?
    int xen_dsk; // include disk counters?
    // may include flags to turn off hostname and MAC lookup calls
    // to xs_read(),  but surely those are not so slow?

    // option to control switch-port sampling direction
    int samplingDirection;
#define HSF_DIRN_UNDEFINED 0
#define HSF_DIRN_IN 1
#define HSF_DIRN_OUT 2
#define HSF_DIRN_BOTH (HSF_DIRN_IN | HSF_DIRN_OUT)

#define HSP_MAX_HEADER_BYTES 256
    HSPApplicationSettings *applicationSettings;
    uint32_t ulogGroup;
    double ulogProbability;
    uint32_t ulogSamplingRate;
    uint32_t ulogSubSamplingRate;
    uint32_t ulogActualSamplingRate;

    uint32_t nflogGroup;
    double nflogProbability;
    uint32_t nflogSamplingRate;
    uint32_t nflogSubSamplingRate;
    uint32_t nflogActualSamplingRate;

    uint32_t jsonPort;
    char *jsonFIFO;
    HSPCIDR *agentCIDRs;
  } HSPSFlowSettings;

  typedef struct _HSPSFlow {
    struct _HSP *myHSP;
    SFLAgent *agent;
    SFLPoller *poller;

    HSPSFlowSettings *sFlowSettings_file;
    HSPSFlowSettings *sFlowSettings_dnsSD; // owned by DNS-SD thread
    HSPSFlowSettings *sFlowSettings; // owned by DNS-SD if running, else main
    char *sFlowSettings_str;  // owned by DNS-SD if running, else main

    uint32_t revisionNo;

    uint32_t subAgentId;
    char *agentDevice;
    SFLAddress agentIP;
    int explicitAgentDevice;
    int explicitAgentIP;
  } HSPSFlow; 

  typedef enum { HSPSTATE_READCONFIG=0,
		 HSPSTATE_WAITCONFIG,
		 HSPSTATE_RUN,
		 HSPSTATE_END
  } EnumHSPState;

#ifdef HSFLOWD_MAIN
  static const char *HSPStateNames[] = {
    "READCONFIG",
    "WAITCONFIG",
    "RUN",
    "END"
  };
#endif

  // persistent state for mapping VM domIds to
  // sFlow datasource indices
#define HSP_MAX_VMSTORE_LINELEN 100
#define HSP_VMSTORE_SEPARATORS " \t\r\n="
  typedef struct _HSPVMStore {
    struct _HSPVMStore *nxt;
    char uuid[16];
    uint32_t dsIndex;
  } HSPVMStore;
  

  // userData structure to store state for VM data-sources
  typedef struct _HSPVMState {
    uint32_t network_count;
    int32_t marked;
    uint32_t vm_index;
    uint32_t domId;
    SFLAdaptorList *interfaces;
    UTStringArray *volumes;
    UTStringArray *disks;
#ifdef HSF_XEN
    xc_domaininfo_t domaininfo;
#endif
#ifdef HSF_DOCKER
    HSPContainer *container;
#endif
  } HSPVMState;
    
  typedef enum { IPSP_NONE=0,
		 IPSP_LOOPBACK6,
		 IPSP_LOOPBACK4,
		 IPSP_SELFASSIGNED4,
		 IPSP_IP6_SCOPE_LINK,
		 IPSP_VLAN6,
		 IPSP_VLAN4,
		 IPSP_IP6_SCOPE_UNIQUE,
		 IPSP_IP6_SCOPE_GLOBAL,
		 IPSP_IP4,
		 IPSP_NUM_PRIORITIES,
  } EnumIPSelectionPriority;

#ifdef HSP_ETHTOOL_STATS
  typedef struct _HSP_ethtool_counters {
    uint64_t mcasts_in;
    uint64_t mcasts_out;
    uint64_t bcasts_in;
    uint64_t bcasts_out;
  } HSP_ethtool_counters;
#endif

  typedef enum { HSPDEV_OTHER=0,
		 HSPDEV_PHYSICAL,
		 HSPDEV_VETH,
		 HSPDEV_VIF,
		 HSPDEV_OVS,
		 HSPDEV_BRIDGE } EnumHSPDevType;
  
  // cache nio counters per adaptor
  typedef struct _HSPAdaptorNIO {
    SFLAddress ipAddr;
    uint32_t /*EnumIPSelectionPriority*/ ipPriority;
    EnumHSPDevType devType;
    uint32_t up:1;
    uint32_t loopback:1;
    uint32_t bond_master:1;
    uint32_t bond_slave:1;
    uint32_t switchPort:1;
    uint32_t vm_or_container:1;
    int32_t vlan;
#define HSP_VLAN_ALL -1
    SFLHost_nio_counters nio;
    SFLHost_nio_counters last_nio;
    uint32_t last_bytes_in32;
    uint32_t last_bytes_out32;
#define HSP_MAX_NIO_DELTA32 0x7FFFFFFF
#define HSP_MAX_NIO_DELTA64 (uint64_t)(1.0e13)
    time_t last_update;
#if (HSP_ETHTOOL_STATS || HSF_DOCKER)
    uint32_t et_nctrs; // how many in total
    uint32_t et_nfound; // how many of the ones we wanted
#endif
#ifdef HSP_ETHTOOL_STATS
    // the offsets within the ethtool stats block
    uint8_t et_idx_mcasts_in;
    uint8_t et_idx_mcasts_out;
    uint8_t et_idx_bcasts_in;
    uint8_t et_idx_bcasts_out;
    // latched counter for delta calculation
    HSP_ethtool_counters et_last;
    HSP_ethtool_counters et_total;
#endif
    // LACP/bonding data
    SFLLACP_counters lacp;
    // switch ports that are sending individual interface
    // counters will keep a pointer to their sflow poller.
    SFLPoller *poller;
    // and those sending packet-samples will have a sampler.
    SFLSampler *sampler;
    uint32_t sampling_n;
    uint32_t sampling_n_set;
    uint32_t netlink_drops;
  } HSPAdaptorNIO;

  typedef struct _HSPDiskIO {
    uint64_t last_sectors_read;
    uint64_t last_sectors_written;
    uint64_t bytes_read;
    uint64_t bytes_written;
  } HSPDiskIO;
    
#ifdef HSF_NVML
  typedef struct _HSPNVML {
    unsigned int gpu_count;
    uint32_t nvml_gpu_time; // mS. accumulator
    uint32_t nvml_mem_time; // mS. accumulator
    uint32_t nvml_energy;  // mJ. accumulator
  } HSPNVML;
#endif

  typedef struct _HSP {
    EnumHSPState state;
    time_t clk;
    HSPSFlow *sFlow;
    char *configFile;
    char *outputFile;
    char *pidFile;
    int dropPriv;
    uint32_t outputRevisionNo;
    FILE *f_out;
    // crashdump
    char *crashFile;
    // Identity
    char hostname[SFL_MAX_HOSTNAME_CHARS+1];
    char os_release[SFL_MAX_OSRELEASE_CHARS+1];
    uint32_t machine_type;
    char uuid[16];

    // interfaces and MACs
    UTHash *adaptorsByName; // global namespace only
    UTHash *adaptorsByIndex;
    UTHash *adaptorsByPeerIndex;
    UTHash *adaptorsByMac;

    // have to poll the NIO counters fast enough to avoid 32-bit rollover
    // of the bytes counters.  On a 10Gbps interface they can wrap in
    // less than 5 seconds.  On a virtual interface the data rate could be
    // higher still. The program may decide to turn this off. For example,
    // if it finds evidence that the counters are already 64-bit in the OS,
    // or if it decides that all interface speeds are limited to 1Gbps or less.
    time_t nio_last_update;
    time_t nio_polling_secs;
#define HSP_NIO_POLLING_SECS_32BIT 3

    int refreshAdaptorList; // request flag
    uint32_t refreshAdaptorListSecs; // poll interval
    int refreshVMList; // request flag
    uint32_t refreshVMListSecs; // poll interval
    uint32_t forgetVMSecs; // age-out idle VM or container

    // 64-bit diskIO accumulators
    HSPDiskIO diskIO;
    // UDP send sockets
    int socket4;
    int socket6;
#ifdef HSF_XEN
    regex_t vif_regex;
    regmatch_t vif_match[HSF_XEN_VIF_REGEX_NMATCH];

#ifdef XENCTRL_HAS_XC_INTERFACE
    xc_interface *xc_handle;
#else
    int xc_handle; // libxc
#endif
    struct xs_handle *xs_handle; // xenstore
    uint32_t page_size;
#endif
#ifdef HSF_VRT
    virConnectPtr virConn;
#endif
    // physical host / hypervisor characteristics
    uint32_t num_domains;
    uint32_t cpu_mhz;
    uint32_t cpu_cores;
    uint64_t mem_total;
    uint64_t mem_free;
    // persistent state
    uint32_t maxDsIndex;
    char *vmStoreFile;
    FILE *f_vmStore;
    int vmStoreInvalid;
    HSPVMStore *vmStore;
#ifdef HSF_DOCKER
    uint32_t num_containers;
    HSPContainer *containers;
#endif
    // inter-thread communication
    pthread_mutex_t *config_mut;
    int DNSSD;
    char *DNSSD_domain;
    uint32_t previousPollingInterval;
    // the DNSSD thread and his private state
    pthread_t *DNSSD_thread;
    int DNSSD_countdown;
    uint32_t DNSSD_startDelay;
    uint32_t DNSSD_retryDelay;
    uint32_t DNSSD_ttl;
#ifdef HSF_ULOG
    // ULOG packet-sampling
    int ulog_soc;
    uint32_t ulog_seqno;
    uint32_t ulog_drops;
    struct sockaddr_nl ulog_bind;
    struct sockaddr_nl ulog_peer;
#endif
#ifdef HSF_NFLOG
    // nflog packet sampling
    struct nfnl_handle *nfnl;
    int nflog_soc;
    uint32_t nflog_seqno;
    uint32_t nflog_drops;
#endif // HSG_NFLOG

#ifdef HSF_PCAP
    BPFSoc *bpf_socs;
#endif
    
#ifdef HSP_SWITCHPORT_REGEX
    regex_t swp_regex;
#endif

#ifdef HSF_JSON
    int json_soc;
    int json_soc6;
    int json_fifo;
    HSPApplication **applicationHT;
    uint32_t applicationHT_size;
#define HSP_INITIAL_JSON_APP_HT_SIZE 16
    uint32_t applicationHT_entries;
#endif
#ifdef HSF_NVML
    HSPNVML nvml;
#endif //HSF_NVML
  } HSP;

  // expose some config parser fns
  int HSPReadConfigFile(HSP *sp);
  HSPSFlowSettings *newSFlowSettings(void);
  HSPCollector *newCollector(HSPSFlowSettings *sFlowSettings);
  void clearCollectors(HSPSFlowSettings *settings);
  HSPPcap *newPcap(HSPSFlowSettings *sFlowSettings);
  void clearPcaps(HSPSFlowSettings *settings);
  void freeSFlowSettings(HSPSFlowSettings *sFlowSettings);
  void setApplicationSampling(HSPSFlowSettings *settings, char *app, uint32_t n);
  void setApplicationPolling(HSPSFlowSettings *settings, char *app, uint32_t secs);
  void clearApplicationSettings(HSPSFlowSettings *settings);
  int lookupApplicationSettings(HSPSFlowSettings *settings, char *prefix, char *app, uint32_t *p_sampling, uint32_t *p_polling);
  uint32_t lookupPacketSamplingRate(SFLAdaptor *adaptor, HSPSFlowSettings *settings);
  uint32_t agentAddressPriority(HSP *sp, SFLAddress *addr, int vlan, int loopback);
  int selectAgentAddress(HSP *sp, int *p_changed);
  void addAgentCIDR(HSPSFlowSettings *settings, HSPCIDR *cidr);
  void clearAgentCIDRs(HSPSFlowSettings *settings);
    
  // using DNS SRV+TXT records
#define SFLOW_DNS_SD "_sflow._udp"
#define HSP_MAX_DNS_LEN 255
  typedef void (*HSPDnsCB)(HSP *sp, uint16_t rtype, uint32_t ttl, u_char *key, int keyLen, u_char *val, int valLen, HSPSFlowSettings *settings);
  int dnsSD(HSP *sp, HSPDnsCB callback, HSPSFlowSettings *settings);

  // read functions
  int readInterfaces(HSP *sp, uint32_t *p_added, uint32_t *p_removed, uint32_t *p_cameup, uint32_t *p_wentdown, uint32_t *p_changed);
  int readCpuCounters(SFLHost_cpu_counters *cpu);
  int readMemoryCounters(SFLHost_mem_counters *mem);
  int readDiskCounters(HSP *sp, SFLHost_dsk_counters *dsk);
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter, SFLAdaptorList *adList);
  HSPAdaptorNIO *getAdaptorNIO(SFLAdaptorList *adaptorList, char *deviceName);
  void updateBondCounters(HSP *sp, SFLAdaptor *bond);
  void readBondState(HSP *sp);
  void syncBondPolling(HSP *sp);
  void updateNioCounters(HSP *sp);
  int readHidCounters(HSP *sp, SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen);
#ifdef HSF_ULOG
  int readPackets_ulog(HSP *sp);
#endif
#ifdef HSF_NFLOG
  int readPackets_nflog(HSP *sp);
#endif
#ifdef HSF_PCAP
  int readPackets_pcap(HSP *sp, BPFSoc *bpfs);
#endif
  int configSwitchPorts(HSP *sp);
  int readJSON(HSP *sp, int soc);
  void json_app_timeout_check(HSP *sp);
  int readTcpipCounters(HSP *sp, SFLHost_ip_counters *c_ip, SFLHost_icmp_counters *c_icmp, SFLHost_tcp_counters *c_tcp, SFLHost_udp_counters *c_udp);

#ifdef HSF_NVML
  void nvml_init(HSP *sp);
  void nvml_stop(HSP *sp);
  void nvml_tick(HSP *sp);
  int readNvmlCounters(HSP *sp, SFLHost_gpu_nvml *nvml);
#endif

#ifdef HSF_CUMULUS
  int readBroadcomCounters(HSP *sp, SFLBCM_tables *bcm);
#endif

#ifdef HSF_DOCKER
  int readContainerCounters(char *cgroup, char *longId, char *fname, int nvals, HSFNameVal *nameVals);
  int readContainerCountersMulti(char *cgroup, char *longId, char *fname, int nvals, HSFNameVal *nameVals);
  int readContainerInterfaces(HSP *sp, HSPVMState *vm);
  int readContainerInterfaces2(HSP *sp, HSPVMState *vm);
#endif

  SFLAdaptor *nioAdaptorNew(char *dev, u_char *macBytes, uint32_t ifIndex);
#define ADAPTOR_NIO(ad) ((HSPAdaptorNIO *)(ad)->userData)
  SFLAdaptor *adaptorByName(HSP *sp, char *dev);
  SFLAdaptor *adaptorByMac(HSP *sp, SFLMacAddress *mac);
  SFLAdaptor *adaptorByIndex(HSP *sp, uint32_t ifIndex);
  SFLAdaptor *adaptorByPeerIndex(HSP *sp, uint32_t ifIndex);
  void deleteAdaptor(HSP *sp, SFLAdaptor *ad, int freeFlag);
  int deleteMarkedAdaptors(HSP *sp, UTHash *adaptorHT, int freeFlag);
  int deleteMarkedAdaptors_adaptorList(HSP *sp, SFLAdaptorList *adList);
  void adaptorHTPrint(UTHash *ht, char *prefix);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */

