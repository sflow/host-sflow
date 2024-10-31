/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#define HSP_MAX_SAMPLING_N 10000000
#define HSP_MAX_POLLING_S 300
#define HSP_MAX_NOTIFY_RATELIMIT 10000

#define HSP_MAX_LINELEN 2048
#define HSP_MAX_CONFIG_DEPTH 3
#define HSP_SEPARATORS " \t\r\n=;"

  typedef enum { HSPTOKENTYPE_UNDEFINED=0,
		 HSPTOKENTYPE_SYNTAX,
		 HSPTOKENTYPE_OBJ,
		 HSPTOKENTYPE_ATTRIB } EnumHSPTokenType;

  // read the special tokens include twice,
  // first to generate the enum, then to
  // populate the special token lookup table
  typedef enum {
#define HSPTOKEN_DATA(tag, token, type, deprecated) tag,
#include "hsflowtokens.h"
#undef HSPTOKEN_DATA
    HSPTOKEN_NUM_TOKENS } EnumHSPSpecialToken;

  typedef struct _HSPSpecialToken {
    EnumHSPSpecialToken tag;
    char *str;
    EnumHSPTokenType type;
    char *deprecated;
  } HSPSpecialToken;

  static const HSPSpecialToken HSPSpecialTokens[] = {
#define HSPTOKEN_DATA(tag, token, type, deprecated) { tag, token, type, deprecated },
#include "hsflowtokens.h"
#undef HSPTOKEN_DATA
  };

  typedef struct _HSPToken {
    struct _HSPToken *nxt;
    uint32_t lineNo;
    char *str;
    EnumHSPSpecialToken stok;
  } HSPToken;

  typedef enum {
    HSPOBJ_HSP=0,
    HSPOBJ_SFLOW,
    HSPOBJ_DNSSD,
    HSPOBJ_COLLECTOR,
    HSPOBJ_JSON,
    HSPOBJ_XEN,
    HSPOBJ_KVM,
    HSPOBJ_DOCKER,
    HSPOBJ_CONTAINERD,
    HSPOBJ_K8S,
    HSPOBJ_ULOG,
    HSPOBJ_NFLOG,
    HSPOBJ_PSAMPLE,
    HSPOBJ_DROPMON,
    HSPOBJ_PCAP,
    HSPOBJ_TCP,
    HSPOBJ_CUMULUS,
    HSPOBJ_DENT,
    HSPOBJ_NVML,
    HSPOBJ_OVS,
    HSPOBJ_OS10,
    HSPOBJ_OPX,
    HSPOBJ_SONIC,
    HSPOBJ_DBUS,
    HSPOBJ_SYSTEMD,
    HSPOBJ_EAPI,
    HSPOBJ_PORT,
    HSPOBJ_NLROUTE,
    HSPOBJ_VPP
  } EnumHSPObject;

  static const char *HSPObjectNames[] = {
    "host-sflow-probe",
    "sflow",
    "dns-sd",
    "collector",
    "json",
    "xen",
    "kvm",
    "docker",
    "containerd",
    "k8s",
    "ulog",
    "nflog",
    "psample",
    "dropmon",
    "pcap",
    "tcp",
    "cumulus",
    "dent",
    "nvml",
    "ovs",
    "os10",
    "opx",
    "sonic",
    "dbus",
    "systemd",
    "eapi",
    "port",
    "nlroute",
    "vpp"
  };

  static void copyApplicationSettings(HSPSFlowSettings *from, HSPSFlowSettings *to);
  static void copyAgentCIDRs(HSPSFlowSettings *from, HSPSFlowSettings *to);

  /*_________________---------------------------__________________
    _________________      parseError           __________________
    -----------------___________________________------------------
  */

  static void parseError(HSP *sp, HSPToken *tok, char *msg1, char *msg2)
  {
    myLog(LOG_ERR, "parse error at <%s><%s> on line %d of %s : %s %s",
	  tok->str,
	  tok->nxt ? tok->nxt->str : "",
	  tok->lineNo,
	  sp->configFile,
	  msg1,
	  msg2);
  }

  /*_________________---------------------------__________________
    _________________      unexpected           __________________
    -----------------___________________________------------------
  */

  static void unexpectedToken(HSP *sp, HSPToken *tok, EnumHSPObject level)
  {
    myLog(LOG_ERR, "parse error at <%s><%s> on line %d of %s : unexpected %s setting",
	  tok->str,
	  tok->nxt ? tok->nxt->str : "",
	  tok->lineNo,
	  sp->configFile,
	  HSPObjectNames[level]);
  }

  /*_________________---------------------------__________________
    _________________   attribute extraction    __________________
    -----------------___________________________------------------
  */

  // expectToken

  static HSPToken *expectToken(HSP *sp, HSPToken *tok, EnumHSPSpecialToken stok)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || t->stok != stok) {
      parseError(sp, tok, "expected ", HSPSpecialTokens[stok].str);
      return NULL;
    }
    return t;
  }

  // expectInteger32

  static uint32_t getMultiplier32(char *str)
  {
    uint32_t mult = 1;
    uint32_t len = my_strlen(str);
    char last = toupper(str[len - 1]);
    if(last == 'K' || last == 'M' || last == 'G') {
      // number of the form "100M" or "1G"
      str[len - 1] = '\0'; // blat the K, M or G
      if(last == 'K') mult = 1000;
      if(last == 'M') mult = 1000000;
      if(last == 'G') mult = 1000000000;
    }
    return mult;
  }

  static HSPToken *expectInteger32(HSP *sp, HSPToken *tok, uint32_t *arg, uint32_t minVal, uint32_t maxVal)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || !isdigit(t->str[0])) {
      parseError(sp, tok, "expected integer", "");
      return NULL;
    }
    char *str = my_strdup(t->str); // take a copy so we can modify it
    uint32_t mult = getMultiplier32(str);
    *arg = (mult * strtol(str, NULL, 0));
    my_free(str);
    if(*arg < minVal || *arg > maxVal) {
      parseError(sp, tok, "range error", "");
      return NULL;
    }
    return t;
  }


  static uint64_t getMultiplier64(char *str)
  {
    uint64_t mult = 1;
    uint32_t len = my_strlen(str);
    char last = toupper(str[len - 1]);
    if(last == 'K' || last == 'M' || last == 'G' || last == 'T' || last == 'P') {
      // number of the form "100M" or "1G"
      str[len - 1] = '\0'; // blat the K, M, G, T or P
      if(last == 'K') mult = 1000LL;
      if(last == 'M') mult = 1000000LL;
      if(last == 'G') mult = 1000000000LL;
      if(last == 'T') mult = 1000000000000LL;
      if(last == 'P') mult = 1000000000000000LL;
    }
    return mult;
  }

#if 0  // expectInteger64 not needed yet

  static HSPToken *expectInteger64(HSP *sp, HSPToken *tok, uint64_t *arg, uint64_t minVal, uint64_t maxVal)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || !isdigit(t->str[0])) {
      parseError(sp, tok, "expected integer", "");
      return NULL;
    }
    char *str = my_strdup(t->str); // take a copy so we can modify it
    uint64_t mult = getMultiplier64(str);
    *arg = (mult * strtoll(str, NULL, 0));
    my_free(str);
    if(*arg < minVal || *arg > maxVal) {
      parseError(sp, tok, "range error", "");
      return NULL;
    }
    return t;
  }

#endif // expectInteger64

  static HSPToken *expectIntegerRange64(HSP *sp, HSPToken *tok, uint64_t *arg1, uint64_t *arg2, uint64_t minVal, uint64_t maxVal)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || !isdigit(t->str[0])) {
      parseError(sp, tok, "expected integer", "");
      return NULL;
    }
    char *str = my_strdup(t->str); // take a copy so we can modify it
    int len = my_strlen(str);
    int len1 = strcspn(str, "-");
    str[len1] = '\0';
    uint64_t mult1 = getMultiplier64(str);
    *arg1 = (mult1 * strtoll(str, NULL, 0));
    if(*arg1 < minVal || *arg1 > maxVal) {
      parseError(sp, tok, "range error", "");
      return NULL;
    }
    if(len > len1) {
      // we have at least a trailing '-' such as "1G-"
      char *str2 = str + len1 + 1;
      if(my_strlen(str2) == 0) {
	// trailing dash. Allow that to mean "<max>"
	*arg2 = maxVal;
      }
      else {
	uint64_t mult2 = getMultiplier64(str2);
	*arg2 = (mult2 * strtoll(str2, NULL, 0));
	if(*arg2 < minVal || *arg2 > maxVal) {
	  parseError(sp, tok, "range error", "");
	  return NULL;
	}
      }
    }
    else {
      // no second number - indicate by setting arg2 to 0
      *arg2 = 0;
    }
    my_free(str);
    return t;
  }

  // expectDouble
  static HSPToken *expectDouble(HSP *sp, HSPToken *tok, double *arg, double minVal, double maxVal)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || !isdigit(t->str[0])) {
      parseError(sp, tok, "expected floating-point number", "");
      return NULL;
    }
    *arg = strtod(t->str, NULL);
    if(*arg < minVal || *arg > maxVal) {
      parseError(sp, tok, "range error", "");
      return NULL;
    }
    return t;
  }

  // expectIP

  static HSPToken *expectIP(HSP *sp, HSPToken *tok, SFLAddress *addr, struct sockaddr *sa)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || lookupAddress(t->str, sa, addr, 0) == NO) {
      parseError(sp, tok, "expected hostname or IP", "");
      return NULL;
    }
    return t;
  }

  // expectCIDR

  static HSPToken *expectCIDR(HSP *sp, HSPToken *tok, HSPCIDR *cidr)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL
       || t->str == NULL) {
      parseError(sp, tok, "expected IP CIDR", "");
      return NULL;
    }
    char *cidrStr = t->str;
    cidr->notFlag = NO;
    if(cidrStr[0] == '!') {
      cidr->notFlag = YES;
      cidrStr++;
    }
    if(SFLAddress_parseCIDR(cidrStr, &cidr->ipAddr, &cidr->mask, &cidr->maskBits) == NO) {
      parseError(sp, tok, "expected IP CIDR", "");
      return NULL;
    }
    return t;
  }

  // expectONOFF

  static HSPToken *expectONOFF(HSP *sp, HSPToken *tok, bool *arg)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || (strcasecmp(t->str, "on") != 0 && strcasecmp(t->str, "off") != 0)) {
      parseError(sp, tok, "expected 'on' or 'off'", "");
      return NULL;
    }
    (*arg) = (strcasecmp(t->str, "on") == 0);
    return t;
  }

  // expectDirection

  static HSPToken *expectDirection(HSP *sp, HSPToken *tok, int *arg)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t && strcasecmp(t->str, "in") == 0) (*arg) = HSP_DIRN_IN;
    else if(t && strcasecmp(t->str, "out") == 0) (*arg) = HSP_DIRN_OUT;
    else if(t && strcasecmp(t->str, "both") == 0) (*arg) = HSP_DIRN_BOTH;
    else {
      parseError(sp, tok, "expected 'in' or 'out' or 'both'", "");
      return NULL;
    }
    return t;
  }

  // expectDNSSD_domain

  static HSPToken *expectDNSSD_domain(HSP *sp, HSPToken *tok)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t && t->str) {
      if(sp->DNSSD.domain) my_free(sp->DNSSD.domain);
      sp->DNSSD.domain = my_strdup(t->str);
      return t;
    }
    parseError(sp, tok, "expected domain", "");
    return NULL;
  }

  // expectLoopback

  static HSPToken *expectLoopback(HSP *sp, HSPToken *tok)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || (strcasecmp(t->str, "on") != 0 && strcasecmp(t->str, "off") != 0)) {
      parseError(sp, tok, "expected 'on' or 'off'", "");
      return NULL;
    }
    // this flag is effectively always-on now. So just consume and ignore it.
    // enable or disable the inclusion of loopback interfaces
    // sp->loopback = (strcasecmp(t->str, "on") == 0);
    // have to force another read here, otherwise we have to wait for ever
    // sp->refreshAdaptorList = YES;
    return t;
  }

  // expectDevice

  static HSPToken *expectDevice(HSP *sp, HSPToken *tok, char **p_devName)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t && t->str) {
      *p_devName = my_strdup(t->str);
      return t;
      // We now read the config file before we read the interfaces, so checking
      // to ensure that this is a valid deviceName is now done later. Could therefore
      // just use expectString() for this, but leave it here as a placeholder in
      // case we want to tighten up the checks.
    }
    parseError(sp, tok, "expected device name", "");
    return NULL;
  }

  // expectUUID

  static HSPToken *expectUUID(HSP *sp, HSPToken *tok, char *uuid)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || parseUUID(t->str, uuid) == NO) {
      parseError(sp, tok, "expected UUID", "");
      return NULL;
    }
    return t;
  }

  // expectFile

  static HSPToken *expectFile(HSP *sp, HSPToken *tok, char **p_fileName)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t && t->str) {
      struct stat statBuf;
      if(stat(t->str, &statBuf) != 0) {
	parseError(sp, tok, "WARNING:", "path does not exist");
	// not a show-stopper. Let it go through.
      }
      *p_fileName = my_strdup(t->str);
      return t;
    }
    parseError(sp, tok, "expected file name", "");
    return NULL;
  }

  // expectString

  static HSPToken *expectString(HSP *sp, HSPToken *tok, char **p_str, char *tokenType)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t && t->str) {
      *p_str = my_strdup(t->str);
      return t;
    }
    parseError(sp, tok, "expected", tokenType);
    return NULL;
  }


  // expectRegex

  static HSPToken *expectRegex(HSP *sp, HSPToken *tok, regex_t **pattern)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t && t->str) {
      *pattern = UTRegexCompile(t->str);
      return (*pattern) ? t : NULL;
    }
    parseError(sp, tok, "expected regex pattern", "");
    return NULL;
  }

  /*_________________---------------------------__________________
    _________________     new object fns        __________________
    -----------------___________________________------------------
  */

  HSPCollector *newCollector(HSPSFlowSettings *sFlowSettings) {
    HSPCollector *col = (HSPCollector *)my_calloc(sizeof(HSPCollector));
    ADD_TO_LIST(sFlowSettings->collectors, col);
    sFlowSettings->numCollectors++;
    col->udpPort = SFL_DEFAULT_COLLECTOR_PORT;
    col->namespace = NULL;
    col->deviceName = NULL;
    return col;
  }

  void clearCollectors(HSPSFlowSettings *settings)
  {
    for(HSPCollector *coll = settings->collectors; coll; ) {
      HSPCollector *nextColl = coll->nxt;
      if(coll->socket > 0) {
	// treat this as an error condition.  The sockets should
	// be closed or zeroed in advance. This way it is easier
	// to create and free configs without incurring unwelcome
	// side effects.
	myLog(LOG_ERR, "clearCollectors: socket still open");
      }
      if(coll->namespace)
	my_free(coll->namespace);
      if(coll->deviceName)
	my_free(coll->deviceName);
      my_free(coll);
      coll = nextColl;
    }
    settings->collectors = NULL;
  }

  static void copyCollectors(HSPSFlowSettings *from, HSPSFlowSettings *to)
  {
    for(HSPCollector *coll = from->collectors; coll; coll = coll->nxt) {
      HSPCollector *newColl = newCollector(to);
      HSPCollector *nxtPtr = newColl->nxt;
      // shallow copy - note this may also copy open socket fd.
      *newColl = *coll;
      // post copy
      newColl->nxt = nxtPtr;
      newColl->namespace = my_strdup(newColl->namespace);
      newColl->deviceName = my_strdup(newColl->deviceName);
    }
  }

  static HSPPcap *newPcap(HSP *sp) {
    HSPPcap *col = (HSPPcap *)my_calloc(sizeof(HSPPcap));
    ADD_TO_LIST(sp->pcap.pcaps, col);
    sp->pcap.numPcaps++;
    return col;
  }

  static HSPPort *newOPXPort(HSP *sp) {
    HSPPort *prt = (HSPPort *)my_calloc(sizeof(HSPPort));
    ADD_TO_LIST(sp->opx.ports, prt);
    sp->opx.numPorts++;
    return prt;
  }

  /*_________________---------------------------__________________
    _________________  sFlowSettings lifecycle  __________________
    -----------------___________________________------------------
  */

  HSPSFlowSettings *newSFlowSettings(void) {
    HSPSFlowSettings *st = (HSPSFlowSettings *)my_calloc(sizeof(HSPSFlowSettings));
    // initialize defaults
    st->samplingRate = SFL_DEFAULT_SAMPLING_RATE;
    st->pollingInterval = SFL_DEFAULT_POLLING_INTERVAL;
    st->headerBytes = SFL_DEFAULT_HEADER_SIZE;
    st->datagramBytes = SFL_DEFAULT_DATAGRAM_SIZE;
    st->samplingDirection = HSP_DIRN_IN;
    return st;
  }

  void freeSFlowSettings(HSPSFlowSettings *sFlowSettings) {
    if(sFlowSettings) {
      clearApplicationSettings(sFlowSettings);
      clearAgentCIDRs(sFlowSettings);
      clearCollectors(sFlowSettings);
      if(sFlowSettings->agentDevice)
	my_free(sFlowSettings->agentDevice);
      my_free(sFlowSettings);
    }
  }

  HSPSFlowSettings *copySFlowSettings(HSPSFlowSettings *from) {
    HSPSFlowSettings *to = newSFlowSettings();
    if(from) {
      *to = *from;
      to->collectors = NULL;
      copyCollectors(from, to);
      to->applicationSettings = NULL;
      copyApplicationSettings(from, to);
      to->agentCIDRs = NULL;
      copyAgentCIDRs(from, to);
      to->agentDevice = NULL;
      if(from->agentDevice)
	to->agentDevice = my_strdup(from->agentDevice);
    }
    return to;
  }


  /*_________________---------------------------__________________
    _________________   sFlowSettingsString     __________________
    -----------------___________________________------------------
   Only print the config fields that can be overridden dynamically
   (e.g. via DNS-SD or from mod_sonic)
  */

  char *sFlowSettingsString(HSP *sp, HSPSFlowSettings *settings)
  {
    UTStrBuf *buf = UTStrBuf_new();

    if(settings) {
      char ipbuf[64];
      UTStrBuf_printf(buf, "hostname=%s\n", sp->hostname);
      UTStrBuf_printf(buf, "sampling=%u\n", settings->samplingRate);
      UTStrBuf_printf(buf, "header=%u\n", settings->headerBytes);
      UTStrBuf_printf(buf, "datagram=%u\n", settings->datagramBytes);
      UTStrBuf_printf(buf, "polling=%u\n", settings->pollingInterval);
      // make sure the application specific ones always come after the general ones - to simplify the override logic there
      for(HSPApplicationSettings *appSettings = settings->applicationSettings; appSettings; appSettings = appSettings->nxt) {
	if(appSettings->got_sampling_n) {
	  UTStrBuf_printf(buf, "sampling.%s=%u\n", appSettings->application, appSettings->sampling_n);
	}
	if(appSettings->got_polling_secs) {
	  UTStrBuf_printf(buf, "polling.%s=%u\n", appSettings->application, appSettings->polling_secs);
	}
      }

      // agentIP and/or agentDevice can override the config file (and auto-selection) if set.
      // If these overrides are removed again in another dynamic update then we simply leave them
      // out here and it should trigger a return to the previous behavior.
      if(settings->agentIP.type)
	UTStrBuf_printf(buf, "agentIP=%s\n", SFLAddress_print(&settings->agentIP, ipbuf, 63));
      if(settings->agentDevice)
	UTStrBuf_printf(buf, "agent=%s\n", settings->agentDevice);

      // the DNS-SD responses seem to be reordering the collectors every time, so we have to take
      // another step here to make sure they are sorted.  Otherwise we think the config has changed
      // every time(!)
      UTStringArray *iplist = strArrayNew();
      for(HSPCollector *collector = settings->collectors; collector; collector = collector->nxt) {
	// make sure we ignore any where the foward lookup failed
	// this might mean we write a .auto file with no collectors in it,
	// so let's hope the slave agents all do the right thing with that(!)
	if(collector->ipAddr.type != SFLADDRESSTYPE_UNDEFINED) {
	  char collectorStr[HSP_MAX_LINELEN];
	  // the evt_config_line syntax uses collector=ip/port/deviceName/namespace
	  // and the dnsSD and SONiC modules pass config lines around that way, but here we
	  // need to preserve the original collector=IP[ PORT] syntax so that unmodified
	  // sub-agents reading this file (such as mod_sflow for apache, nginx-sflow-module
	  // and jmx-sflow-agent) all see what they were expecting. At least, that's
	  // OK provided the dev and namespace are not set. If dev/namespace _are_ set then we
	  // need the sub-agents to interpret them correctly or not at all.  So that's how
	  // we end up here, using the old syntax if it's just ip and port, but adopting
	  // the new syntax when we need to express ip/port/dev/ns.
	  SFLAddress_print(&collector->ipAddr, ipbuf, 63);
	  if(collector->deviceName == NULL
	     && collector->namespace == NULL) {
	    // old syntax:  collector=IP or collector=IP PORT
	    if(collector->udpPort == SFL_DEFAULT_COLLECTOR_PORT)
	      snprintf(collectorStr, HSP_MAX_LINELEN, "collector=%s\n", ipbuf);
	    else
	      snprintf(collectorStr, HSP_MAX_LINELEN, "collector=%s %u\n", ipbuf, collector->udpPort);
	  }
	  else {
	    // new syntax: collector=IP/PORT/DEV/NS
	    snprintf(collectorStr, HSP_MAX_LINELEN, "collector=%s/%u/%s/%s\n",
		    ipbuf,
		    collector->udpPort,
		    collector->deviceName ?: "",
		    collector->namespace ?: "");
	  }
	  strArrayAdd(iplist, collectorStr);
	}
      }
      strArraySort(iplist);
      char *arrayStr = strArrayStr(iplist, NULL/*start*/, NULL/*quote*/, NULL/*delim*/, NULL/*end*/);
      UTStrBuf_printf(buf, "%s", arrayStr);
      my_free(arrayStr);
      strArrayFree(iplist);
    }
    return UTStrBuf_unwrap(buf);
  }

  /*_________________---------------------------__________________
    _________________      newSFlow             __________________
    -----------------___________________________------------------
  */

  static void newSFlow(HSP *sp) {
    sp->sFlowSettings_file = newSFlowSettings();
    sp->subAgentId = HSP_DEFAULT_SUBAGENTID;
    sp->xen.update_dominfo = 0;
    sp->xen.dsk = 1;
    sp->xen.vbd = STRINGIFY_DEF(HSP_XEN_VBD_PATH);
  }

  /*_________________---------------------------__________________
    _________________     newToken              __________________
    -----------------___________________________------------------
  */

  static HSPToken *newToken(char *str, int len) {
    HSPToken *token = (HSPToken *)my_calloc(sizeof(HSPToken));
    token->str = (char *)my_calloc(len + 1);
    memcpy(token->str, str, len);
    // if it is special token, then record the index number here too
    for(uint32_t i = 0; i < HSPTOKEN_NUM_TOKENS; i++) {
      if(strcasecmp(token->str, HSPSpecialTokens[i].str) == 0) {
	token->stok = (EnumHSPSpecialToken)i;
      }
    }
    return token;
  }

  /*_________________---------------------------__________________
    _________________   getApplicationSettings  __________________
    -----------------___________________________------------------
  */

  static HSPApplicationSettings *getApplicationSettings(HSPSFlowSettings *settings, char *app, bool create)
  {
    HSPApplicationSettings *appSettings = settings->applicationSettings;
    for(; appSettings; appSettings = appSettings->nxt) if(my_strequal(app, appSettings->application)) break;
    if(appSettings == NULL && create) {
      appSettings = (HSPApplicationSettings *)my_calloc(sizeof(HSPApplicationSettings));
      appSettings->application = my_strdup(app);
      appSettings->nxt = settings->applicationSettings;
      settings->applicationSettings = appSettings;
    }
    return appSettings;
  }

  /*_________________----------------------------__________________
    _________________   clearApplicationSettings __________________
    -----------------____________________________------------------
  */

  void clearApplicationSettings(HSPSFlowSettings *settings)
  {
    for(HSPApplicationSettings *appSettings = settings->applicationSettings; appSettings; ) {
      HSPApplicationSettings *nextAppSettings = appSettings->nxt;
      my_free(appSettings->application);
      my_free(appSettings);
      appSettings = nextAppSettings;
    }
    settings->applicationSettings = NULL;
  }

  /*_________________----------------------------__________________
    _________________  copyApplicationSettings   __________________
    -----------------____________________________------------------
  */

  void copyApplicationSettings(HSPSFlowSettings *from, HSPSFlowSettings *to)
  {
    for(HSPApplicationSettings *appSettings = from->applicationSettings; appSettings; appSettings = appSettings->nxt) {
      HSPApplicationSettings *newAppSettings = getApplicationSettings(to, appSettings->application, YES);
      newAppSettings->got_sampling_n = appSettings->got_sampling_n;
      newAppSettings->sampling_n = appSettings->sampling_n;
      newAppSettings->got_polling_secs = appSettings->got_polling_secs;
      newAppSettings->polling_secs = appSettings->polling_secs;
    }
  }

  /*_________________----------------------------__________________
    _________________   setApplicationSampling   __________________
    -----------------____________________________------------------
  */

  void setApplicationSampling(HSPSFlowSettings *settings, char *app, uint32_t n)
  {
    HSPApplicationSettings *appSettings = getApplicationSettings(settings, app, YES);
    appSettings->sampling_n = n;
    appSettings->got_sampling_n = YES;
  }

  /*_________________----------------------------__________________
    _________________   setApplicationPolling    __________________
    -----------------____________________________------------------
  */

  void setApplicationPolling(HSPSFlowSettings *settings, char *app, uint32_t secs)
  {
    HSPApplicationSettings *appSettings = getApplicationSettings(settings, app, YES);
    appSettings->polling_secs = secs;
    appSettings->got_polling_secs = YES;
  }

  /*_________________----------------------------__________________
    _________________  lookupApplicationSettings __________________
    -----------------____________________________------------------
    return a deepest match lookup, so that
    a setting of sampling.app.xyz.pqr = 100 will apply to
    an application named "app.xyz.pqr.abc" and take precendence
    over a setting of sampling.app.xyz = 200
  */

  int lookupApplicationSettings(HSPSFlowSettings *settings, char *prefix, char *app, uint32_t *p_sampling, uint32_t *p_polling)
  {
    // in the config, the sFlow-APPLICATION settings should always start with sampling.app.<name> or polling.app.<name>
    // so add the .app prefix here before we start searching...
    char *search = app;
    int search_len = my_strlen(app);
    if(prefix) {
      search_len = my_strlen(app) + my_strlen(prefix) + 1;
      search = my_calloc(search_len + 1);
      snprintf(search, search_len + 1, "%s.%s", prefix, app);
    }
    // the top level settings are the defaults
    if(p_polling) *p_polling = settings->pollingInterval;
    if(p_sampling) *p_sampling = settings->samplingRate;
    // now search for the deepest match
    HSPApplicationSettings *deepest = NULL;
    uint32_t deepest_len = 0;
    for(HSPApplicationSettings *appSettings = settings->applicationSettings; appSettings; appSettings = appSettings->nxt) {
      int len = my_strlen(appSettings->application);
      if(len > deepest_len
	 && len <= search_len
	 && my_strnequal(search, appSettings->application, len)) {
	// has to be an exact match, or one that matches up to a '.'
	if(len == search_len || search[len] == '.') {
	  deepest = appSettings;
	  deepest_len = len;
	}
      }
    }

    if(prefix) {
      my_free(search);
    }

    if(deepest) {
      if(p_polling && deepest->got_polling_secs) *p_sampling = deepest->polling_secs;
      if(p_sampling && deepest->got_sampling_n) *p_sampling = deepest->sampling_n;
      return YES;
    }
    return NO;
  }

  /*_________________----------------------------__________________
    _________________  lookupPacketSamplingRate  __________________
    -----------------____________________________------------------
  */

  uint32_t lookupPacketSamplingRate(SFLAdaptor *adaptor, HSPSFlowSettings *settings)
  {
    assert(settings != NULL); // too soon! wait for config to be established

    // This falls back on the default "sampling=<n>" setting if the speed is unknown or zero
    uint32_t sampling_n = settings->samplingRate;
    char *method = "global_default";
    if(adaptor) {
      HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);

      if(adaptorNIO->up == NO) {
	sampling_n = 0;
	method = "interface_down";
      }
      else {
	if(adaptor->ifSpeed) {
	  char speedStr[51];
	  if(printSpeed(adaptor->ifSpeed, speedStr, 50)
	     && lookupApplicationSettings(settings, NULL, speedStr, &sampling_n, NULL)) {
	    method = speedStr;
	  }
	  else {
	    // calcuate default sampling rate based on link speed.  This ensures
	    // that a network switch comes up with manageable defaults even if
	    // the config file is empty...
	    uint32_t bpsRatio = 0;
	    if(lookupApplicationSettings(settings, NULL, HSP_BPS_RATIO, &bpsRatio, NULL)) {
	      // sampling.bps_ratio=0 turns off the behavior, falling back on global default
	      if(bpsRatio > 0) {
		sampling_n = adaptor->ifSpeed / bpsRatio;
		if(sampling_n == 0)
		  sampling_n = 1;
		method = HSP_BPS_RATIO;
	      }
	    }
	    else {
	      // use default bpsratio
	      sampling_n = adaptor->ifSpeed / HSP_SPEED_SAMPLING_RATIO;
	      if(sampling_n < HSP_SPEED_SAMPLING_MIN) {
		sampling_n = HSP_SPEED_SAMPLING_MIN;
	      }
	      method = "speed_default";
	    }
	  }
	}
      }

      myDebug(1, "%s (speed=%"PRIu64") using %s sampling rate = %u",
	      adaptor->deviceName,
	      adaptor->ifSpeed,
	      method,
	      sampling_n);
    }
    return sampling_n;
  }

  /*_________________---------------------------__________________
    _________________     addAgentCIDR          __________________
    -----------------___________________________------------------
  */

  void addAgentCIDR(HSPSFlowSettings *settings, HSPCIDR *cidr, bool atEnd)
  {
    HSPCIDR *mycidr = (HSPCIDR *)my_calloc(sizeof(HSPCIDR));
    *mycidr = *cidr;
    // ordering is important here. We want them in reverse order, but
    // when we copy we have to preserve the order,  so allow either way:
    if(atEnd && settings->agentCIDRs) {
      HSPCIDR *last = settings->agentCIDRs;
      while(last->nxt) last = last->nxt;
      mycidr->nxt = NULL;
      last->nxt = mycidr;
    }
    else {
      // at front
      mycidr->nxt = settings->agentCIDRs;
      settings->agentCIDRs = mycidr;
    }
  }

  /*_________________---------------------------__________________
    _________________    clearAgentCIDRs        __________________
    -----------------___________________________------------------
  */

  void clearAgentCIDRs(HSPSFlowSettings *settings)
  {
    for(HSPCIDR *cidr = settings->agentCIDRs; cidr; ) {
      HSPCIDR *next_cidr = cidr->nxt;
      my_free(cidr);
      cidr = next_cidr;
    }
    settings->agentCIDRs = NULL;
  }
  
  /*_________________---------------------------__________________
    _________________    copyAgentCIDRs         __________________
    -----------------___________________________------------------
  */
  
  static void copyAgentCIDRs(HSPSFlowSettings *from, HSPSFlowSettings *to)
  {
    for(HSPCIDR *cidr = from->agentCIDRs; cidr; cidr=cidr->nxt) {
      addAgentCIDR(to, cidr, YES); // atEnd to preserve order
    }
  }

  /*_________________---------------------------__________________
    _________________      readTokens           __________________
    -----------------___________________________------------------
  */

  static HSPToken *nextToken(char *p, char **out)
  {
    char *r = p;
    HSPToken *token = NULL;
#define HSP_MAX_TOKEN_LEN 255
    char buf[HSP_MAX_TOKEN_LEN+1];

    // allow quoted strings so that a regex can have any chars (including "{}") in it
    uint32_t pre_seps = strspn(r, HSP_SEPARATORS);
    char *str = parseNextTok(&r, HSP_SEPARATORS, NO, '"', YES, buf, HSP_MAX_TOKEN_LEN);
    if(str
       && *str != '\0') {
      // found non-empty string, but watch out for a contiguous '{' or '}' token.
      // If we find one then we'll just consume part of str...
      uint32_t len = strcspn(str, "{}" HSP_SEPARATORS);
      if(len == 0) len = 1; // => str started with '{' or '}'
      token = newToken(str, len);
      // tell the caller how many chars we actually consumed
      *out = (p + pre_seps + len);
    }
    // return token or NULL
    return token;
  }

  static  HSPToken *reverseTokens(HSPToken *tokens)
  {
    HSPToken *rev = NULL;
    for(HSPToken *tok = tokens; tok; ) {
      HSPToken *nextTok = tok->nxt;
      ADD_TO_LIST(rev, tok);
      tok = nextTok;
    }
    return rev;
  }

  static HSPToken *readTokens(HSP *sp)
  {
    FILE *cfg = NULL;
    if((cfg = fopen(sp->configFile, "r")) == NULL) {
      myLog(LOG_ERR,"cannot open config file %s : %s", sp->configFile, strerror(errno));
      return NULL;
    }

    // collect the tokens in a (reversed) list
    HSPToken *tokens = newToken("start", 5);
    char line[HSP_MAX_LINELEN];
    uint32_t lineNo = 0;
    int truncated;
    while(my_readline(cfg, line, HSP_MAX_LINELEN, &truncated) != EOF) {
      lineNo++;
      char *p = line;
      // comments start with '#'
      p[strcspn(p, "#")] = '\0';
      HSPToken *tok;
      while((tok = nextToken(p, &p)) != NULL) {
	tok->lineNo = lineNo;
	ADD_TO_LIST(tokens, tok);
      }
    }
    fclose(cfg);

    // get them in the right order
    tokens = reverseTokens(tokens);

    return tokens;
  }
  
  /*_________________---------------------------__________________
    _________________  agentAddressPriority     __________________
    -----------------___________________________------------------
  */

  uint32_t agentAddressPriority(HSP *sp, SFLAddress *addr, int vlan, int loopback)
  {
    EnumIPSelectionPriority ipPriority = IPSP_NONE;

    switch(addr->type) {
    case SFLADDRESSTYPE_IP_V4:
      // start assuming it's a global ip
      ipPriority = IPSP_IP4;
      // then check for other possibilities
      if(loopback) {
	ipPriority = IPSP_LOOPBACK4;
      }
      else if (SFLAddress_isSelfAssigned(addr)) {
	ipPriority = IPSP_SELFASSIGNED4;
      }
      else if(vlan != HSP_VLAN_ALL) {
	ipPriority = IPSP_VLAN4;
      }
      else if(SFLAddress_isRFC1918(addr)) {
	ipPriority = IPSP_IP4_RFC1918;
      }
      else if(SFLAddress_isClassE(addr)) {
	ipPriority = IPSP_CLASS_E;
      }
      else if(SFLAddress_isMulticast(addr)) {
	ipPriority = IPSP_MULTICAST;
      }
      break;

    case SFLADDRESSTYPE_IP_V6:
      // start by assuming it's a global IP
      ipPriority = IPSP_IP6_SCOPE_GLOBAL;
      // then check for other possibilities

      // now allow the other parameters to override
      if(loopback || SFLAddress_isLoopback(addr)) {
	ipPriority = IPSP_LOOPBACK6;
      }
      else if (SFLAddress_isLinkLocal(addr)) {
	ipPriority = IPSP_IP6_SCOPE_LINK;
      }
      else if (SFLAddress_isUniqueLocal(addr)) {
	ipPriority = IPSP_IP6_SCOPE_UNIQUE;
      }
      else if(vlan != HSP_VLAN_ALL) {
	ipPriority = IPSP_VLAN6;
      }
      else if(SFLAddress_isMulticast(addr)) {
	ipPriority = IPSP_MULTICAST;
      }
      break;
    default:
      // not a v4 or v6 ip address at all
      break;
    }

    // just make sure we can't get a multicast in here (somehow)
    if(SFLAddress_isMulticast(addr)) {
      ipPriority = IPSP_NONE;
    }

    uint32_t boosted_priority = ipPriority;

    // allow the agent.cidr settings to boost the priority
    // of this address.  The cidrs are in reverse order.
    // Allow dynamic config to override the config file if
    // agent.cidr entries are specified there.
    HSPCIDR *cidr = NULL;
    if(sp->sFlowSettings)
      cidr = sp->sFlowSettings->agentCIDRs;
    if(cidr == NULL && sp->sFlowSettings_file)
      cidr = sp->sFlowSettings_file->agentCIDRs;

    if(cidr) {
      uint32_t cidrIndex = 1;
      for(; cidr; cidrIndex++, cidr=cidr->nxt) {
	myDebug(1, "testing CIDR at index %d", cidrIndex);
	if(SFLAddress_maskEqual(addr, &cidr->mask, &cidr->ipAddr)) break;
      }
      
      if(cidr) {
	myDebug(1, "CIDR at index %d matched: adjusting priority", cidrIndex);
	if(cidr->notFlag)
	  boosted_priority = IPSP_NONE; // not exactly a boost
	else
	  boosted_priority += (cidrIndex * IPSP_NUM_PRIORITIES);
      }
    }

    return boosted_priority;
  }


/*________________---------------------------__________________
  ________________  setAddressPriorities     __________________
  ----------------___________________________------------------
*/

  static void setAddressPriorities(HSP *sp, UTHash *addrHT) {
    myDebug(2, "setAddressPriorities");
    if(addrHT) {
      HSPLocalIP *lip;
      UTHASH_WALK(addrHT, lip) {
	lip->ipPriority = 0;
	lip->minIfIndex = 0xFFFFFFFF;
	lip->minSelectionPriority = 0xFFFFFFFF;
	for(uint32_t ii=0; ii<strArrayN(lip->devs); ii++) {
	  char *dev = strArrayAt(lip->devs, ii);
	  SFLAdaptor *adaptor = adaptorByName(sp, dev);
	  if(adaptor) {
	    HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
	    if(adaptorNIO) {
	      uint32_t priority = agentAddressPriority(sp,
						       &lip->ipAddr,
						       adaptorNIO->vlan,
						       adaptorNIO->loopback);
	      // remember the highest priority score (and which dev it was)
	      if(priority > lip->ipPriority) {
		lip->ipPriority = priority;
		lip->priorityDev = ii;
	      }
	      // for SONiC tie-breaker: lowest non-zero selectionPriority seen
	      if(adaptorNIO->selectionPriority
		 && adaptorNIO->selectionPriority < lip->minSelectionPriority)
		lip->minSelectionPriority = adaptorNIO->selectionPriority;
	      // for tie-breaker: lowest ifIndex seen
	      if(adaptor->ifIndex < lip->minIfIndex)
		lip->minIfIndex = adaptor->ifIndex;

	      char ipbuf[51];
	      myDebug(2, "setAddressPriorities: ip=%s discoveryIdx=%u dev=%s priority=%u minIfIndex=%u minSONiCPriority=%u",
		      SFLAddress_print(&lip->ipAddr, ipbuf, 50),
		      lip->discoveryIndex,
		      dev,
		      lip->ipPriority,
		      lip->minIfIndex,
		      lip->minSelectionPriority);
	    }
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________      priorityHigher       __________________
    -----------------___________________________------------------
  */

  static bool priorityHigher(HSP *sp, HSPLocalIP *localIP, HSPLocalIP *challenger, char *peggedDev) {
    if(localIP == NULL)
      return YES;
    int pri_local = localIP->ipPriority;
    int pri_challenge = challenger->ipPriority;
    if(peggedDev) {
      char ipbuf[51];
      if(strArrayContains(challenger->devs, peggedDev)) {
	pri_challenge += IPSP_NUM_PRIORITIES;
	myDebug(2, "%s boosted (dev=%s)", SFLAddress_print(&challenger->ipAddr, ipbuf, 50), peggedDev);
      }
      if(strArrayContains(localIP->devs, peggedDev)) {
	pri_local += IPSP_NUM_PRIORITIES;
	myDebug(2, "%s boosted (dev=%s)", SFLAddress_print(&localIP->ipAddr, ipbuf, 50), peggedDev);
      }
    }
    if(pri_challenge < pri_local)
      return NO;
    if(pri_challenge > pri_local)
      return YES;

    // tiebreaker (1) : lower SONiC selectionPriority wins
    if(challenger->minSelectionPriority != localIP->minSelectionPriority)
      return (challenger->minSelectionPriority < localIP->minSelectionPriority);

    // tiebreaker (2) : lower ifIndex wins
    if(challenger->minIfIndex != localIP->minIfIndex)
      return (challenger->minIfIndex < localIP->minIfIndex);

    // tiebreaker (3) : discovered first wins
    return (challenger->discoveryIndex < localIP->discoveryIndex);
  }

  /*_________________---------------------------__________________
    _________________     selectAgentAddress    __________________
    -----------------___________________________------------------
  */

  bool selectAgentAddress(HSP *sp, bool *p_changed, bool *p_mismatch) {

    SFLAddress *ip = NULL;
    HSPSFlowSettings *st = sp->sFlowSettings;
    HSPSFlowSettings *st_file = sp->sFlowSettings_file;
    SFLAdaptor *selectedAdaptor = NULL;

    myDebug(1, "selectAgentAddress");
    
    // set base priority (and tiebreaker) info for all known local addresses
    setAddressPriorities(sp, sp->localIP);
    setAddressPriorities(sp, sp->localIP6);

    // see if config specifies ip or adaptor
    if(st
       && st->agentIP.type) {
      myDebug(1, "selectAgentAddress in current settings");
      ip = &st->agentIP;
      selectedAdaptor = adaptorByIP(sp, ip);
    }
    else if(st_file
	    && st_file->agentIP.type) {
      myDebug(1, "selectAgentAddress hard-coded in config file");
      ip = &st_file->agentIP;
      selectedAdaptor = adaptorByIP(sp, ip);
    }
    else if(st
	    && st->agentDevice) {
      myDebug(1, "selectAgentAddress pegged to device %s in current settings", st->agentDevice);
      selectedAdaptor = adaptorByName(sp, st->agentDevice);
      if(selectedAdaptor == NULL)
	selectedAdaptor = adaptorByAlias(sp, st->agentDevice);
      if(selectedAdaptor == NULL
	 && p_mismatch) {
	myDebug(1, "device name mismatch");
	*p_mismatch = YES;
      }
    }
    else if(st_file
	    && st_file->agentDevice) {
      myDebug(1, "selectAgentAddress pegged to device %s in config file", st_file->agentDevice);
      selectedAdaptor = adaptorByName(sp, st_file->agentDevice);
      if(selectedAdaptor == NULL)
	selectedAdaptor = adaptorByAlias(sp, st_file->agentDevice);
      if(selectedAdaptor == NULL
	 && p_mismatch) {
	myDebug(1, "device name mismatch");
	*p_mismatch = YES;
      }
    }
    
    if(ip == NULL) {
      // Elect an IP (or IPv6) address based on priority (maybe pegged to one dev)
      char *peggedDev = selectedAdaptor ? selectedAdaptor->deviceName : NULL;
      HSPLocalIP *selectedLocalIP = NULL;
      HSPLocalIP *lip;
      char ipbuf[51];
      UTHASH_WALK(sp->localIP, lip) {
	if(priorityHigher(sp, selectedLocalIP, lip, peggedDev)) {
	  myDebug(2, "%s preferred", SFLAddress_print(&lip->ipAddr, ipbuf, 50));
	  selectedLocalIP = lip;
	}
      }
      UTHASH_WALK(sp->localIP6, lip) {
	if(priorityHigher(sp, selectedLocalIP, lip, peggedDev)) {
	  myDebug(2, "%s preferred", SFLAddress_print(&lip->ipAddr, ipbuf, 50));
	  selectedLocalIP = lip;
	}
      }
      if(selectedLocalIP) {
	// picked one.  Fill in ip and adaptor
	ip = &selectedLocalIP->ipAddr;
	char *selectedDev = strArrayAt(selectedLocalIP->devs, selectedLocalIP->priorityDev);
	if(selectedDev)
	  selectedAdaptor = adaptorByName(sp, selectedDev);
      }
    }

    // record the agentDevice name
    if(sp->agentDevice) {
      my_free(sp->agentDevice);
      sp->agentDevice = NULL;
    }
    if(selectedAdaptor) {
      sp->agentDevice = my_strdup(selectedAdaptor->deviceName);
    }

    // see if this represents a change
    bool changed = (SFLAddress_equal(ip, &sp->agentIP) == NO);
    if(p_changed) *p_changed = changed;

    if(ip) {
      char ipbuf1[51];
      char ipbuf2[51];
      myDebug(1, "selectAgentAddress selected agentIP with highest priority: device=%s, address=%s, previous=%s, changed=%s",
	      sp->agentDevice ?: "<none>",
	      SFLAddress_print(ip, ipbuf1, 50),
	      SFLAddress_print(&sp->agentIP, ipbuf2, 50),
	      changed ? "YES" : "NO");

      // write it into place
      sp->agentIP = *ip;
    }
    else {
      myDebug(1, "selectAgentAddress selection failed");
    }

    // return true if we were successful
    return (ip ? YES : NO);
  }

  /*_________________---------------------------__________________
    _________________      readConfigFile       __________________
    -----------------___________________________------------------
  */

  int HSPReadConfigFile(HSP *sp)
  {
    EnumHSPObject level[HSP_MAX_CONFIG_DEPTH + 5];
    int depth = 0;
    level[depth] = HSPOBJ_HSP;

    // could have used something like bison to make a complete parser with
    // strict rules,  but for simplicity we just allow the current object
    // to double as a state variable that determines what is allowed next.

    HSPToken *tok = sp->config_tokens = readTokens(sp);
    for( ; tok; tok = tok->nxt) {

      if(tok->stok
	 && HSPSpecialTokens[tok->stok].deprecated)
	myDebug(1, "line %u: %s setting is now deprecated and may be ignored. Prefer: \"%s\"",
		tok->lineNo,
		tok->str,
		HSPSpecialTokens[tok->stok].deprecated);

      if(depth > HSP_MAX_CONFIG_DEPTH) {
	// depth overrun
	parseError(sp, tok, "too many '{'s", "");
	return NO;
      }
      else if(tok->stok == HSPTOKEN_ENDOBJ) {
	// end of level, pop the stack
	if(depth > 0) --depth;
	else {
	  parseError(sp, tok, "too many '}'s ", "");
	  return NO;
	}
      }
      else switch(level[depth]) {
	case HSPOBJ_HSP:
	  // must start by opening an sFlow object
	  if((tok = expectToken(sp, tok, HSPTOKEN_SFLOW)) == NULL) return NO;
	  if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	  newSFlow(sp);
	  level[++depth] = HSPOBJ_SFLOW;
	  break;

	case HSPOBJ_SFLOW:

	  switch(tok->stok) {

	    // Perhaps these sp->xxx settings should be outside the sflow { } block?
	    // ======================================================================
	  case HSPTOKEN_MODULES:
	    if((tok = expectFile(sp, tok, &sp->modulesPath)) == NULL) return NO;
	    break;
	  case HSPTOKEN_LOOPBACK:
	    if((tok = expectLoopback(sp, tok)) == NULL) return NO;
	    break;
	  case HSPTOKEN_DNSSD:
	    if((tok = expectONOFF(sp, tok, &sp->DNSSD.DNSSD)) == NULL) return NO;
	    break;
	  case HSPTOKEN_DNSSD_DOMAIN:
	    if((tok = expectDNSSD_domain(sp, tok)) == NULL) return NO;
	    break;
	  case HSPTOKEN_REFRESH_ADAPTORS:
	    if((tok = expectInteger32(sp, tok, &sp->refreshAdaptorListSecs, 60, 3600)) == NULL) return NO;
	    break;
	  case HSPTOKEN_CHECK_ADAPTORS:
	    if((tok = expectInteger32(sp, tok, &sp->checkAdaptorListSecs, 1, 3600)) == NULL) return NO;
	    break;
	  case HSPTOKEN_REFRESH_VMS:
	    if((tok = expectInteger32(sp, tok, &sp->refreshVMListSecs, 60, 3600)) == NULL) return NO;
	    break;
	  case HSPTOKEN_FORGET_VMS:
	    if((tok = expectInteger32(sp, tok, &sp->forgetVMSecs, 60, 0xFFFFFFFF)) == NULL) return NO;
	    break;
	    // ======================================================================
	  case HSPTOKEN_DNS_SD:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->DNSSD.DNSSD = YES;
	    level[++depth] = HSPOBJ_DNSSD;
	    break;
	  case HSPTOKEN_COLLECTOR:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    newCollector(sp->sFlowSettings_file);
	    level[++depth] = HSPOBJ_COLLECTOR;
	    break;
	  case HSPTOKEN_KVM:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->kvm.kvm = YES;
	    level[++depth] = HSPOBJ_KVM;
	    break;
	  case HSPTOKEN_XEN:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->xen.xen = YES;
	    level[++depth] = HSPOBJ_XEN;
	    break;
	  case HSPTOKEN_DOCKER:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->docker.docker = YES;
	    level[++depth] = HSPOBJ_DOCKER;
	    break;
	  case HSPTOKEN_CONTAINERD:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->containerd.containerd = YES;
	    level[++depth] = HSPOBJ_CONTAINERD;
	    break;
	  case HSPTOKEN_K8S:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->k8s.k8s = YES;
	    level[++depth] = HSPOBJ_K8S;
	    break;
	  case HSPTOKEN_ULOG:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->ulog.ulog = YES;
	    level[++depth] = HSPOBJ_ULOG;
	    break;
	  case HSPTOKEN_NFLOG:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->nflog.nflog = YES;
	    level[++depth] = HSPOBJ_NFLOG;
	    break;
	  case HSPTOKEN_PSAMPLE:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->psample.psample = YES;
	    sp->psample.group = 1;
	    sp->psample.ingress = YES;
	    sp->psample.egress = NO;
	    level[++depth] = HSPOBJ_PSAMPLE;
	    break;
	  case HSPTOKEN_DROPMON:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->dropmon.dropmon = YES;
	    sp->dropmon.start = YES;
	    sp->dropmon.limit = HSP_DEFAULT_DROPLIMIT;
	    sp->dropmon.max = HSP_DEFAULT_DROPTRAP_MAX;
	    sp->dropmon.sw = YES;
	    sp->dropmon.hw = YES;
	    sp->dropmon.rn = YES;
	    sp->dropmon.hw_unknown = NO;
	    sp->dropmon.hw_function = NO;
	    sp->dropmon.sw_passive = NO;
	    sp->dropmon.hw_passive = NO;
	    level[++depth] = HSPOBJ_DROPMON;
	    break;
	  case HSPTOKEN_PCAP:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->pcap.pcap = YES;
	    newPcap(sp);
	    level[++depth] = HSPOBJ_PCAP;
	    break;
	  case HSPTOKEN_TCP:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->tcp.tcp = YES;
	    level[++depth] = HSPOBJ_TCP;
	    break;
	  case HSPTOKEN_CUMULUS:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->cumulus.cumulus = YES;
	    level[++depth] = HSPOBJ_CUMULUS;
	    break;
	  case HSPTOKEN_DENT:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->dent.dent = YES;
	    level[++depth] = HSPOBJ_DENT;
	    break;
	  case HSPTOKEN_OVS:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->ovs.ovs = YES;
	    level[++depth] = HSPOBJ_OVS;
	    break;
	  case HSPTOKEN_JSON:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->json.json = YES;
	    level[++depth] = HSPOBJ_JSON;
	    break;
	  case HSPTOKEN_NVML:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->nvml.nvml = YES;
	    level[++depth] = HSPOBJ_NVML;
	    break;
	  case HSPTOKEN_OS10:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->opx.opx = YES; // os10 now maps to opx internally
	    level[++depth] = HSPOBJ_OS10;
	    break;
	  case HSPTOKEN_OPX:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->opx.opx = YES;
	    level[++depth] = HSPOBJ_OPX;
	    break;
	  case HSPTOKEN_SONIC:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->sonic.sonic = YES;
	    sp->sonic.unixsock = YES;
	    sp->sonic.waitReady = HSP_SONIC_DEFAULT_WAITREADY_SECS;
	    sp->sonic.suppressOther = YES;
	    level[++depth] = HSPOBJ_SONIC;
	    break;
	  case HSPTOKEN_DBUS:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->dbus.dbus = YES;
	    level[++depth] = HSPOBJ_DBUS;
	    break;
	  case HSPTOKEN_SYSTEMD:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->systemd.systemd = YES;
	    level[++depth] = HSPOBJ_SYSTEMD;
	    break;
	  case HSPTOKEN_EAPI:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->eapi.eapi = YES;
	    level[++depth] = HSPOBJ_EAPI;
	    break;
	  case HSPTOKEN_NLROUTE:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->nlroute.nlroute = YES;
	    sp->nlroute.limit = HSP_DEFAULT_NLROUTE_LIMIT;
	    level[++depth] = HSPOBJ_NLROUTE;
	    break;
	  case HSPTOKEN_VPP:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->vpp.vpp = YES;
	    sp->vpp.ifOffset = HSP_DEFAULT_VPP_IFINDEX_OFFSET;
	    level[++depth] = HSPOBJ_VPP;
	    break;
	  case HSPTOKEN_SAMPLING:
	  case HSPTOKEN_PACKETSAMPLINGRATE:
	    if((tok = expectInteger32(sp, tok, &sp->sFlowSettings_file->samplingRate, 0, HSP_MAX_SAMPLING_N)) == NULL) return NO;
	    break;
	  case HSPTOKEN_POLLING:
	  case HSPTOKEN_COUNTERPOLLINGINTERVAL:
	    if((tok = expectInteger32(sp, tok, &sp->sFlowSettings_file->pollingInterval, 0, HSP_MAX_POLLING_S)) == NULL) return NO;
	    break;
	  case HSPTOKEN_AGENTIP:
	    if((tok = expectIP(sp, tok, &sp->sFlowSettings_file->agentIP, NULL)) == NULL) return NO;
	    break;
	  case HSPTOKEN_AGENTCIDR:
	    {
	      HSPCIDR cidr = { 0 };
	      if((tok = expectCIDR(sp, tok, &cidr)) == NULL) return NO;
	      addAgentCIDR(sp->sFlowSettings_file, &cidr, NO);
	    }
	    break;
	  case HSPTOKEN_AGENT:
	    if((tok = expectDevice(sp, tok, &sp->sFlowSettings_file->agentDevice)) == NULL) return NO;
	    break;
	  case HSPTOKEN_SUBAGENTID:
	    if((tok = expectInteger32(sp, tok, &sp->subAgentId, 0, HSP_MAX_SUBAGENTID)) == NULL) return NO;
	    break;
	  case HSPTOKEN_UUID:
	    if((tok = expectUUID(sp, tok, sp->uuid)) == NULL) return NO;
	    break;
	  case HSPTOKEN_HEADERBYTES:
	    if((tok = expectInteger32(sp, tok, &sp->sFlowSettings_file->headerBytes, 0, HSP_MAX_HEADER_BYTES)) == NULL) return NO;
	    break;
	  case HSPTOKEN_DATAGRAMBYTES:
	    if((tok = expectInteger32(sp, tok, &sp->sFlowSettings_file->datagramBytes, SFL_MIN_DATAGRAM_SIZE, SFL_MAX_DATAGRAM_SIZE)) == NULL) return NO;
	    break;
	  case HSPTOKEN_XEN_UPDATE_DOMINFO:
	    if((tok = expectONOFF(sp, tok, &sp->xen.update_dominfo)) == NULL) return NO;
	    break;
	  case HSPTOKEN_XEN_DSK:
	    if((tok = expectONOFF(sp, tok, &sp->xen.dsk)) == NULL) return NO;
	    break;
	  case HSPTOKEN_ULOGGROUP:
	    if((tok = expectInteger32(sp, tok, &sp->ulog.group, 1, 32)) == NULL) return NO;
	    break;
	  case HSPTOKEN_NFLOGGROUP:
	    if((tok = expectInteger32(sp, tok, &sp->nflog.group, 1, 0xFFFFFFFF)) == NULL) return NO;
	    break;
	  case HSPTOKEN_ULOGPROBABILITY:
	    if((tok = expectDouble(sp, tok, &sp->ulog.probability, 0.0, 1.0)) == NULL) return NO;
	    break;
	  case HSPTOKEN_NFLOGPROBABILITY:
	    if((tok = expectDouble(sp, tok, &sp->nflog.probability, 0.0, 1.0)) == NULL) return NO;
	    break;
	  case HSPTOKEN_JSONPORT:
	    if((tok = expectInteger32(sp, tok, &sp->json.port, 1025, 65535)) == NULL) return NO;
	    break;
	  case HSPTOKEN_JSONFIFO:
	    // expect a file name such as "/tmp/hsflowd_json_fifo" that was created using mkfifo(1)
	    if((tok = expectFile(sp, tok, &sp->json.FIFO)) == NULL) return NO;
	    break;
	  case HSPTOKEN_SAMPLINGDIRECTION:
	    // deprecated, will be ignored. But still parse to consume without error.
	    if((tok = expectDirection(sp, tok, &sp->sFlowSettings_file->samplingDirection)) == NULL) return NO;
	    break;
	  default:
	    // handle wildcards here - allow sampling.<app>=<n> and polling.<app>=<secs>
	    if(tok->str && strncasecmp(tok->str, "sampling.", 9) == 0) {
	      char *app = tok->str + 9;
	      uint32_t sampling_n=0;
	      if((tok = expectInteger32(sp, tok, &sampling_n, 0, HSP_MAX_SAMPLING_N)) == NULL) return NO;
	      setApplicationSampling(sp->sFlowSettings_file, app, sampling_n);
	    }
	    else if(tok->str && strncasecmp(tok->str, "polling.", 8) == 0) {
	      char *app = tok->str + 8;
	      uint32_t polling_secs=0;
	      if((tok = expectInteger32(sp, tok, &polling_secs, 0, HSP_MAX_POLLING_S)) == NULL) return NO;
	      setApplicationPolling(sp->sFlowSettings_file, app, polling_secs);
	    }
	    else {
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	    }
	    break;
	  }
	  break;

	case HSPOBJ_DNSSD:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_DNSSD_DOMAIN:
	    case HSPTOKEN_DOMAIN:
	      if((tok = expectDNSSD_domain(sp, tok)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_COLLECTOR:
	  {
	    HSPCollector *col = sp->sFlowSettings_file->collectors;
	    switch(tok->stok) {
	    case HSPTOKEN_IP:
	      if((tok = expectIP(sp, tok, &col->ipAddr, (struct sockaddr *)&col->sendSocketAddr)) == NULL) return NO;
	      break;
	    case HSPTOKEN_UDPPORT:
	      if((tok = expectInteger32(sp, tok, &col->udpPort, 1, 65535)) == NULL) return NO;
	      break;
	    case HSPTOKEN_NAMESPACE:
	      if((tok = expectString(sp, tok, &col->namespace, "namespace")) == NULL) return NO;
	      break;
	    case HSPTOKEN_DEV:
	      if((tok = expectDevice(sp, tok, &col->deviceName)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_KVM:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_REFRESH_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->kvm.refreshVMListSecs, 60, 3600)) == NULL) return NO;
	      break;
	    case HSPTOKEN_FORGET_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->kvm.forgetVMSecs, 60, 0xFFFFFFFF)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_XEN:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_XEN_UPDATE_DOMINFO:
	    case HSPTOKEN_UPDATE_DOMINFO:
	      if((tok = expectONOFF(sp, tok, &sp->xen.update_dominfo)) == NULL) return NO;
	      break;
	    case HSPTOKEN_XEN_DSK:
	    case HSPTOKEN_DSK:
	      if((tok = expectONOFF(sp, tok, &sp->xen.dsk)) == NULL) return NO;
	      break;
	    case HSPTOKEN_SWITCHPORT:
	      if((tok = expectRegex(sp, tok, &sp->xen.vif_regex)) == NULL) return NO;
	      sp->xen.vif_regex_str = my_strdup(tok->str);
	      break;
	    case HSPTOKEN_VBD:
	      if((tok = expectFile(sp, tok, &sp->xen.vbd)) == NULL) return NO;
	      break;
	    case HSPTOKEN_REFRESH_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->xen.refreshVMListSecs, 60, 3600)) == NULL) return NO;
	      break;
	    case HSPTOKEN_FORGET_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->xen.forgetVMSecs, 60, 0xFFFFFFFF)) == NULL) return NO;
	      break;

	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_DOCKER:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_REFRESH_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->docker.refreshVMListSecs, 60, 3600)) == NULL) return NO;
	      break;
	    case HSPTOKEN_FORGET_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->docker.forgetVMSecs, 60, 0xFFFFFFFF)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HOSTNAME:
	      if((tok = expectONOFF(sp, tok, &sp->docker.hostname)) == NULL) return NO;
	      break;
	    case HSPTOKEN_CGROUP_TRAFFIC:
	      if((tok = expectONOFF(sp, tok, &sp->docker.markTraffic)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_CONTAINERD:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_FORGET_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->containerd.forgetVMSecs, 60, 0xFFFFFFFF)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HOSTNAME:
	      if((tok = expectONOFF(sp, tok, &sp->containerd.hostname)) == NULL) return NO;
	      break;
	    case HSPTOKEN_CGROUP_TRAFFIC:
	      if((tok = expectONOFF(sp, tok, &sp->containerd.markTraffic)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_K8S:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_CGROUP_TRAFFIC:
	      if((tok = expectONOFF(sp, tok, &sp->k8s.markTraffic)) == NULL) return NO;
	      break;
	    case HSPTOKEN_EOF:
	      if((tok = expectONOFF(sp, tok, &sp->k8s.eof)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_ULOG:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_GROUP:
	    case HSPTOKEN_ULOGGROUP:
	      if((tok = expectInteger32(sp, tok, &sp->ulog.group, 1, 32)) == NULL) return NO;
	      break;
	    case HSPTOKEN_PROBABILITY:
	    case HSPTOKEN_ULOGPROBABILITY:
	      if((tok = expectDouble(sp, tok, &sp->ulog.probability, 0.0, 1.0)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_NFLOG:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_GROUP:
	    case HSPTOKEN_NFLOGGROUP:
	      if((tok = expectInteger32(sp, tok, &sp->nflog.group, 1, 32)) == NULL) return NO;
	      break;
	    case HSPTOKEN_PROBABILITY:
	    case HSPTOKEN_NFLOGPROBABILITY:
	      if((tok = expectDouble(sp, tok, &sp->nflog.probability, 0.0, 1.0)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_PSAMPLE:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_GROUP:
	      if((tok = expectInteger32(sp, tok, &sp->psample.group, 1, 32)) == NULL) return NO;
	      break;
	    case HSPTOKEN_INGRESS:
	      if((tok = expectONOFF(sp, tok, &sp->psample.ingress)) == NULL) return NO;
	      break;
	    case HSPTOKEN_EGRESS:
	      if((tok = expectONOFF(sp, tok, &sp->psample.egress)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_DROPMON:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_GROUP:
	      // deprecated, ignore as long as it is well-formed. Must still
	      // parse to consume the arg.
	      {
		uint32_t ignore;
		if((tok = expectInteger32(sp, tok, &ignore, 1, 0xFFFFFFFF)) == NULL) return NO;
	      }
	      break;
	    case HSPTOKEN_START:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.start)) == NULL) return NO;
	      break;
	    case HSPTOKEN_SW:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.sw)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HW:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.hw)) == NULL) return NO;
	      break;
	    case HSPTOKEN_RN:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.rn)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HW_UNKNOWN:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.hw_unknown)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HW_FUNCTION: {
	      // deprecated but still parse to consume cleanly if well-formed */
	      bool ignore;
	      if((tok = expectONOFF(sp, tok, &ignore)) == NULL) return NO;
	    }
	      break;
	    case HSPTOKEN_SW_PASSIVE:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.sw_passive)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HW_PASSIVE:
	      if((tok = expectONOFF(sp, tok, &sp->dropmon.hw_passive)) == NULL) return NO;
	      break;
	    case HSPTOKEN_HIDE:
	      if((tok = expectRegex(sp, tok, &sp->dropmon.hide_regex)) == NULL) return NO;
	      sp->dropmon.hide_regex_str = my_strdup(tok->str);
	      break;
	    case HSPTOKEN_LIMIT:
	      if((tok = expectInteger32(sp, tok, &sp->dropmon.limit, 1, HSP_MAX_NOTIFY_RATELIMIT)) == NULL) return NO;
	      break;
	    case HSPTOKEN_MAX:
	      if((tok = expectInteger32(sp, tok, &sp->dropmon.max, 1, 0xFFFFFFFF)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_PCAP:
	  {
	    HSPPcap *pc = sp->pcap.pcaps;
	    switch(tok->stok) {
	    case HSPTOKEN_DEV:
	      if((tok = expectDevice(sp, tok, &pc->dev)) == NULL) return NO;
	      break;
	    case HSPTOKEN_PROMISC:
	      if((tok = expectONOFF(sp, tok, &pc->promisc)) == NULL) return NO;
	      break;
	    case HSPTOKEN_VPORT:
	      if((tok = expectONOFF(sp, tok, &pc->vport)) == NULL) return NO;
	      pc->vport_set = YES;
	      break;
	    case HSPTOKEN_SPEED:
	      if((tok = expectIntegerRange64(sp, tok, &pc->speed_min, &pc->speed_max, 0, LLONG_MAX)) == NULL) return NO;
	      pc->speed_set = YES;
	      break;
	    case HSPTOKEN_SAMPLING:
	      if((tok = expectInteger32(sp, tok, &pc->sampling_n, 0, HSP_MAX_SAMPLING_N)) == NULL) return NO;
	      pc->sampling_n_set = YES;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_TCP:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_TUNNEL:
	      if((tok = expectONOFF(sp, tok, &sp->tcp.tunnel)) == NULL) return NO;
	      break;
	    case HSPTOKEN_UDP:
	      if((tok = expectONOFF(sp, tok, &sp->tcp.udp)) == NULL) return NO;
	      break;
	    case HSPTOKEN_DUMP:
	      if((tok = expectONOFF(sp, tok, &sp->tcp.dump)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_CUMULUS:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_SWITCHPORT:
	      if((tok = expectRegex(sp, tok, &sp->cumulus.swp_regex)) == NULL) return NO;
	      sp->cumulus.swp_regex_str = my_strdup(tok->str);
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_DENT:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_SWITCHPORT:
	      if((tok = expectRegex(sp, tok, &sp->dent.swp_regex)) == NULL) return NO;
	      sp->dent.swp_regex_str = my_strdup(tok->str);
	      break;
	    case HSPTOKEN_SW:
	      if((tok = expectONOFF(sp, tok, &sp->dent.sw)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_OVS:
	  {
	    switch(tok->stok) {
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_JSON:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_UDPPORT:
	    case HSPTOKEN_JSONPORT:
	      if((tok = expectInteger32(sp, tok, &sp->json.port,0,65535)) == NULL) return NO;
	      break;
	    case HSPTOKEN_FIFO:
	    case HSPTOKEN_JSONFIFO:
	      // expect a file name such as "/tmp/hsflowd_json_fifo" that was created using mkfifo(1)
	      if((tok = expectFile(sp, tok, &sp->json.FIFO)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	  // OS10 is now the same as OPX internally (starting with 2.0.17)
	case HSPOBJ_OS10:
	case HSPOBJ_OPX:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_UDPPORT:
	      if((tok = expectInteger32(sp, tok, &sp->opx.port,0,65535)) == NULL) return NO;
	      break;
	    case HSPTOKEN_SWITCHPORT:
	      if((tok = expectRegex(sp, tok, &sp->opx.swp_regex)) == NULL) return NO;
	      sp->opx.swp_regex_str = my_strdup(tok->str);
	      break;
	    case HSPTOKEN_PORT:
	      if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	      newOPXPort(sp);
	      level[++depth] = HSPOBJ_PORT;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_SONIC:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_SWITCHPORT:
	      if((tok = expectRegex(sp, tok, &sp->sonic.swp_regex)) == NULL) return NO;
	      sp->sonic.swp_regex_str = my_strdup(tok->str);
	      break;
	    case HSPTOKEN_UNIXSOCK:
	      if((tok = expectONOFF(sp, tok, &sp->sonic.unixsock)) == NULL) return NO;
	      break;
	    case HSPTOKEN_DBCONFIG:
	      if((tok = expectString(sp, tok, &sp->sonic.dbconfig, "path")) == NULL) return NO;
	      break;
	    case HSPTOKEN_WAITREADY:
	      if((tok = expectInteger32(sp, tok, &sp->sonic.waitReady, 0, 0xFFFFFFFF)) == NULL) return NO;
	      break;
	    case HSPTOKEN_SUPPRESSOTHER:
	      if((tok = expectONOFF(sp, tok, &sp->sonic.suppressOther)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_PORT:
	  {
	    HSPPort *prt = NULL;
	    if(depth) {
	      if (level[depth-1] == HSPOBJ_OPX
		  || level[depth-1] == HSPOBJ_OS10)
		prt = sp->opx.ports;
	    }
	    if(prt == NULL) {
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	    }
	    switch(tok->stok) {
	    case HSPTOKEN_DEV:
	      if((tok = expectDevice(sp, tok, &prt->dev)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_NVML:
	  {
	    switch(tok->stok) {
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_DBUS:
	  {
	    switch(tok->stok) {
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_SYSTEMD:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_REFRESH_VMS:
	      if((tok = expectInteger32(sp, tok, &sp->systemd.refreshVMListSecs, 10, 3600)) == NULL) return NO;
	      break;
	    case HSPTOKEN_DROP_PRIV:
	      if((tok = expectONOFF(sp, tok, &sp->systemd.dropPriv)) == NULL) return NO;
	      break;
	    case HSPTOKEN_CGROUP_PROCS:
	      if((tok = expectString(sp, tok, &sp->systemd.cgroup_procs, "format")) == NULL) return NO;
	      break;
	    case HSPTOKEN_CGROUP_ACCT:
	      if((tok = expectString(sp, tok, &sp->systemd.cgroup_acct, "format")) == NULL) return NO;
	      break;
	    case HSPTOKEN_CGROUP_TRAFFIC:
	      if((tok = expectONOFF(sp, tok, &sp->systemd.markTraffic)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_EAPI:
	  {
	    switch(tok->stok) {
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_NLROUTE:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_LIMIT:
	      if((tok = expectInteger32(sp, tok, &sp->nlroute.limit, 0, HSP_MAX_NLROUTE_LIMIT)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	case HSPOBJ_VPP:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_IFOFFSET:
	      if((tok = expectInteger32(sp, tok, &sp->vpp.ifOffset, 0, 0xFFFFFFFF)) == NULL) return NO;
	      break;
	    default:
	      unexpectedToken(sp, tok, level[depth]);
	      return NO;
	      break;
	    }
	  }
	  break;

	default:
	  parseError(sp, tok, "unexpected state", "");
	}
    }

    // OK we consumed all the tokens, but we still need to run some sanity checks to make sure
    // we have a usable configuration...

    int parseOK = YES;

    if(sp->sFlowSettings_file == NULL) {
      myLog(LOG_ERR, "parse error in %s : sFlow {} not found", sp->configFile);
      parseOK = NO;
    }
    else {
      if(sp->sFlowSettings_file->numCollectors == 0
	 && sp->DNSSD.DNSSD == NO
	 && sp->eapi.eapi == NO
	 && sp->sonic.sonic == NO) {
	myLog(LOG_ERR, "parse error in %s : no collectors are defined", sp->configFile);
	parseOK = NO;
      }

      for(HSPCollector *coll = sp->sFlowSettings_file->collectors; coll; coll = coll->nxt) {
	//////////////////////// collector /////////////////////////
	if(coll->ipAddr.type == 0) {
	  myLog(LOG_ERR, "parse error in %s : collector  has no IP", sp->configFile);
	  parseOK = NO;
	}
      }
    }

    if(sp->ulog.probability > 0) {
      sp->ulog.samplingRate = (uint32_t)(1.0 / sp->ulog.probability);
    }
    if(sp->nflog.probability > 0) {
      sp->nflog.samplingRate = (uint32_t)(1.0 / sp->nflog.probability);
    }

    if(depth != 0) {
      // this cannot be a fatal error because we tolerated it before
      myLog(LOG_ERR, "parse error in %s: expect closing '}'", sp->configFile);
    }
    
    return parseOK;
  }


  /*_________________---------------------------__________________
    _________________  dynamic_config_line      __________________
    -----------------___________________________------------------
    may be called from different threads in parallel
  */
  static bool tokenMatch(char *str, EnumHSPSpecialToken tk) {
    return (!strcasecmp(str, HSPSpecialTokens[tk].str));
  }
  
  void dynamic_config_line(HSPSFlowSettings *st, char *line) {
    char *varval = (char *)line;
    char keyBuf[EV_MAX_EVT_DATALEN];
    char valBuf[EV_MAX_EVT_DATALEN];
    if(parseNextTok(&varval, "=", YES, '"', YES, keyBuf, EV_MAX_EVT_DATALEN)
       && parseNextTok(&varval, "=", YES, '"', YES, valBuf, EV_MAX_EVT_DATALEN)) {

      myDebug(3, "dynamic_config_line key=%s val=%s", keyBuf, valBuf);

      if(tokenMatch(keyBuf, HSPTOKEN_COLLECTOR)) {
	int valLen = my_strlen(valBuf);
	if(valLen > 3) {
	  HSPCollector *coll = newCollector(st);
	  char partBuf[EV_MAX_EVT_DATALEN];
	  uint32_t field = 0;
	  char *str = valBuf;
	  // collector=address/udpport/deviceName/namespace
	  // This assumes we never have a '/' in one of these names.
	  while(parseNextTok(&str, "/", YES, '"', YES, partBuf, EV_MAX_EVT_DATALEN)) {
	    switch(field++) {
	    case 0: // address
	      if(lookupAddress(partBuf, (struct sockaddr *)&coll->sendSocketAddr, &coll->ipAddr, 0) == NO) {
		myLog(LOG_ERR, "collector address lookup failed: %s", partBuf);
		// turn off the collector by clearing the address type
		coll->ipAddr.type = SFLADDRESSTYPE_UNDEFINED;
	      }
	      break;
	    case 1: // udpport
	      coll->udpPort = strtol(partBuf, NULL, 0);
	      if(coll->udpPort < 1 || coll->udpPort > 65535) {
		myLog(LOG_ERR, "collector bad port: %d", coll->udpPort);
		// turn off the collector by clearing the address type
		coll->ipAddr.type = SFLADDRESSTYPE_UNDEFINED;
	      }
	      break;
	    case 2: // deviceName
	      if(my_strlen(partBuf) > 0)
		coll->deviceName = my_strdup(partBuf);
	      break;
	    case 3: // namespace
	      if(my_strlen(partBuf) > 0)
		coll->namespace = my_strdup(partBuf);
	      break;
	    default:
	      myLog(LOG_ERR, "ignoring excess collector-spec fields");
	      break;
	    }
	  }
	}
      }
      else {
	// key=val (TXT record line)
	if(tokenMatch(keyBuf, HSPTOKEN_SAMPLING)) {
	  st->samplingRate = strtol(valBuf, NULL, 0);
	}
	else if(!strncasecmp(keyBuf, "sampling.", 9)) {
	  setApplicationSampling(st, keyBuf+9, strtol(valBuf, NULL, 0));
	}
	else if(!strcasecmp(keyBuf, "txtvers")) {
	}
	else if(tokenMatch(keyBuf, HSPTOKEN_POLLING)) {
	  st->pollingInterval = strtol(valBuf, NULL, 0);
	}
	else if(!strncasecmp(keyBuf, "polling.", 8)) {
	  setApplicationPolling(st, keyBuf+8, strtol(valBuf, NULL, 0));
	}
	else if(tokenMatch(keyBuf, HSPTOKEN_AGENTIP)) {
	  SFLAddress ip = { 0 };
	  if(lookupAddress(valBuf, NULL, &ip, 0) == NO)
	    myLog(LOG_ERR, "address lookup failed: agentIP=%s", valBuf);
	  else
	    st->agentIP = ip;
	}
	else if(tokenMatch(keyBuf, HSPTOKEN_AGENT)) {
	  if(st->agentDevice)
	    my_free(st->agentDevice);
	  // TODO: check device lookup?
	  st->agentDevice = my_strdup(valBuf);
	}
	else if(tokenMatch(keyBuf, HSPTOKEN_AGENTCIDR)) {
	  HSPCIDR cidr = { 0 };
	  if(SFLAddress_parseCIDR(valBuf,
				  &cidr.ipAddr,
				  &cidr.mask,
				  &cidr.maskBits)) {
	    addAgentCIDR(st, &cidr, NO);
	  }
	  else {
	    myLog(LOG_ERR, "CIDR parse error in dynamic config record <%s>=<%s>", keyBuf, valBuf);
	  }
	}
	else if(!strcasecmp(keyBuf, "dropLimit")) {
	  st->dropLimit = strtol(valBuf, NULL, 0);
	  st->dropLimit_set = YES;
	}
	else if(tokenMatch(keyBuf, HSPTOKEN_HEADERBYTES)) {
	  st->headerBytes = strtol(valBuf, NULL, 0);
	  if(st->headerBytes > HSP_MAX_HEADER_BYTES)
	    st->headerBytes = HSP_MAX_HEADER_BYTES;
	}
	// TODO: *** add datagramBytes, samplingDirection here
	// so they can be overridden dynamically by DNSSD, SONiC etc.
	else {
	  myLog(LOG_INFO, "unexpected dynamic config record <%s>=<%s>", keyBuf, valBuf);
	}
      }
    }
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
