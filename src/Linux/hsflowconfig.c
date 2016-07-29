/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

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
    HSPOBJ_ULOG,
    HSPOBJ_NFLOG,
    HSPOBJ_PCAP,
    HSPOBJ_CUMULUS,
    HSPOBJ_NVML,
    HSPOBJ_OVS,
    HSPOBJ_OS10
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
    "ulog",
    "nflog",
    "pcap",
    "cumulus",
    "nvml",
    "ovs",
    "os10"
  };

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

  static uint32_t getMultiplier(char *str)
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
    uint32_t mult = getMultiplier(str);
    *arg = (mult * strtol(str, NULL, 0));
    my_free(str);
    if(*arg < minVal || *arg > maxVal) {
      parseError(sp, tok, "range error", "");
      return NULL;
    }
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
    if(t == NULL || SFLAddress_parseCIDR(t->str, &cidr->ipAddr, &cidr->mask, &cidr->maskBits) == NO) {
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
    // enable or disable DNS server discovery
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
      // to ensure that this is a valid deviceName is now done later
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
    return col;
  }

  void clearCollectors(HSPSFlowSettings *settings) 
  {
    for(HSPCollector *coll = settings->collectors; coll; ) {
      HSPCollector *nextColl = coll->nxt;
      my_free(coll);
      coll = nextColl;
    }
    settings->collectors = NULL;
  }

  static HSPPcap *newPcap(HSP *sp) {
    HSPPcap *col = (HSPPcap *)my_calloc(sizeof(HSPPcap));
    ADD_TO_LIST(sp->pcap.pcaps, col);
    sp->pcap.numPcaps++;
    return col;
  }

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
      my_free(sFlowSettings);
    }
  }

  static void newSFlow(HSP *sp) {
    sp->sFlowSettings_file = newSFlowSettings();
    sp->subAgentId = HSP_DEFAULT_SUBAGENTID;
    sp->xen.update_dominfo = 0;
    sp->xen.dsk = 1;
    sp->xen.vbd = STRINGIFY_DEF(HSP_XEN_VBD_PATH);
  }

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
  
  static HSPApplicationSettings *getApplicationSettings(HSPSFlowSettings *settings, char *app, int create)
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
	char speedStr[51];
	if(adaptor->ifSpeed) {
	  if(printSpeed(adaptor->ifSpeed, speedStr, 50)
	     && lookupApplicationSettings(settings, NULL, speedStr, &sampling_n, NULL)) {
	    method = speedStr;
	  }
	  else {
	    // calcuate default sampling rate based on link speed.  This ensures
	    // that a network switch comes up with manageable defaults even if
	    // the config file is empty...
	    sampling_n = adaptor->ifSpeed / HSP_SPEED_SAMPLING_RATIO;
	    if(sampling_n < HSP_SPEED_SAMPLING_MIN) {
	      sampling_n = HSP_SPEED_SAMPLING_MIN;
	    }
	    method = "speed_default";
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

  void addAgentCIDR(HSPSFlowSettings *settings, HSPCIDR *cidr)
  {
    HSPCIDR *mycidr = (HSPCIDR *)my_calloc(sizeof(HSPCIDR));
    *mycidr = *cidr;
    // ordering is important here. We want them in reverse order,
    // so add this at the beginning of the list
    mycidr->nxt = settings->agentCIDRs;
    settings->agentCIDRs = mycidr;
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
    while(fgets(line, HSP_MAX_LINELEN, cfg)) {
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

    if(sp->sFlowSettings_file) {
      // allow the agent.cidr settings to boost the priority
      // of this address.  The cidrs are in reverse order.
      HSPCIDR *cidr = sp->sFlowSettings_file->agentCIDRs;
      uint32_t cidrIndex = 1;
      for(; cidr; cidrIndex++, cidr=cidr->nxt) {
	myDebug(1, "testing CIDR at index %d", cidrIndex);
	if(SFLAddress_maskEqual(addr, &cidr->mask, &cidr->ipAddr)) break;
      }
      
      if(cidr) {
	myDebug(1, "CIDR at index %d matched: boosting priority", cidrIndex);
	boosted_priority += (cidrIndex * IPSP_NUM_PRIORITIES); 
      }
    }
    else {
      myDebug(1, "agentAddressPriority: no config yet (so no CIDR boost)");
    }
      
    return boosted_priority;
  }


  /*_________________---------------------------__________________
    _________________     selectAgentAddress    __________________
    -----------------___________________________------------------
  */
  
  int selectAgentAddress(HSP *sp, int *p_changed) {

    int selected = NO;
    SFLAddress previous = sp->agentIP;

    myDebug(1, "selectAgentAddress");

    if(sp->explicitAgentIP && sp->agentIP.type) {
      // it was hard-coded in the config file
      myDebug(1, "selectAgentAddress hard-coded in config file");
      selected = YES;
    }
    else if(sp->explicitAgentDevice && sp->agentDevice) {
      // it may have been defined as agent=<device>
      SFLAdaptor *ad = adaptorByName(sp, sp->agentDevice);
      if(ad) {
	sp->agentIP = ADAPTOR_NIO(ad)->ipAddr;
	myDebug(1, "selectAgentAddress pegged to device in config file");
	selected = YES;
      }
    }
    else {
      // try to automatically choose an IP (or IPv6) address,  based on the priority ranking.
      // We already used this ranking to prioritize L3 addresses per adaptor (in the case where
      // there are more than one) so now we are applying the same ranking globally to pick
      // the best candidate to represent the whole agent:
      SFLAdaptor *selectedAdaptor = NULL;
      EnumIPSelectionPriority ipPriority = IPSP_NONE;

      SFLAdaptor *adaptor;
      UTHASH_WALK(sp->adaptorsByName, adaptor) {
	HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(adaptor);
	// take the highest priority one,  but if we have more than one with the same
	// priority then choose the one with the lowest (non-zero) ifIndex number:
	if(adaptorNIO->ipPriority > ipPriority
	   || (adaptorNIO->ipPriority == ipPriority
	       && adaptor->ifIndex
	       && selectedAdaptor
	       && (selectedAdaptor->ifIndex == 0
		   || adaptor->ifIndex < selectedAdaptor->ifIndex))) {
	  selectedAdaptor = adaptor;
	  ipPriority = adaptorNIO->ipPriority;
	}
      }
      if(selectedAdaptor) {
	// crown the winner
	HSPAdaptorNIO *adaptorNIO = ADAPTOR_NIO(selectedAdaptor);
	sp->agentIP = adaptorNIO->ipAddr;
	sp->agentDevice = my_strdup(selectedAdaptor->deviceName);
	myDebug(1, "selectAgentAddress selected agentIP with highest priority");
	selected = YES;
      }
    }

    if(p_changed) {
      if(SFLAddress_equal(&previous, &sp->agentIP)) {
	*p_changed = YES;
      }
      else {
	*p_changed = NO;
      }
    }
    
    return selected;
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
    
    for(HSPToken *tok = readTokens(sp); tok; tok = tok->nxt) {

      if(tok->stok
	 && HSPSpecialTokens[tok->stok].deprecated)
	myDebug(1, "line %u: %s now deprecated. prefer: \"%s\"",
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
	  case HSPTOKEN_PCAP:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->pcap.pcap = YES;
	    newPcap(sp);
	    level[++depth] = HSPOBJ_PCAP;
	    break;
	  case HSPTOKEN_CUMULUS:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    sp->cumulus.cumulus = YES;
	    level[++depth] = HSPOBJ_CUMULUS;
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
	    sp->os10.os10 = YES;
	    level[++depth] = HSPOBJ_OS10;
	    break;

	  case HSPTOKEN_SAMPLING:
	  case HSPTOKEN_PACKETSAMPLINGRATE:
	    if((tok = expectInteger32(sp, tok, &sp->sFlowSettings_file->samplingRate, 0, 65535)) == NULL) return NO;
	    break;
	  case HSPTOKEN_POLLING:
	  case HSPTOKEN_COUNTERPOLLINGINTERVAL:
	    if((tok = expectInteger32(sp, tok, &sp->sFlowSettings_file->pollingInterval, 0, 300)) == NULL) return NO;
	    break;
	  case HSPTOKEN_AGENTIP:
	    if((tok = expectIP(sp, tok, &sp->agentIP, NULL)) == NULL) return NO;
	    sp->explicitAgentIP = YES;
	    break;
	  case HSPTOKEN_AGENTCIDR:
	    {
	      HSPCIDR cidr = { 0 };
	      if((tok = expectCIDR(sp, tok, &cidr)) == NULL) return NO;
	      addAgentCIDR(sp->sFlowSettings_file, &cidr);
	    }
	    break;
	  case HSPTOKEN_AGENT:
	    if((tok = expectDevice(sp, tok, &sp->agentDevice)) == NULL) return NO;
	    sp->explicitAgentDevice = YES;
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
	    if((tok = expectDirection(sp, tok, &sp->sFlowSettings_file->samplingDirection)) == NULL) return NO;
	    break;
	  default:
	    // handle wildcards here - allow sampling.<app>=<n> and polling.<app>=<secs>
	    if(tok->str && strncasecmp(tok->str, "sampling.", 9) == 0) {
	      char *app = tok->str + 9;
	      uint32_t sampling_n=0;
	      if((tok = expectInteger32(sp, tok, &sampling_n, 0, 65535)) == NULL) return NO;
	      setApplicationSampling(sp->sFlowSettings_file, app, sampling_n);
	    }
	    else if(tok->str && strncasecmp(tok->str, "polling.", 8) == 0) {
	      char *app = tok->str + 8;
	      uint32_t polling_secs=0;
	      if((tok = expectInteger32(sp, tok, &polling_secs, 0, 300)) == NULL) return NO;
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
	  
	case HSPOBJ_OS10:
	  {
	    switch(tok->stok) {
	    case HSPTOKEN_UDPPORT:
	      if((tok = expectInteger32(sp, tok, &sp->os10.port,0,65535)) == NULL) return NO;
	      break;
	    case HSPTOKEN_SWITCHPORT:
	      if((tok = expectRegex(sp, tok, &sp->os10.swp_regex)) == NULL) return NO;
	      sp->os10.swp_regex_str = my_strdup(tok->str);
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
      if(sp->sFlowSettings_file->numCollectors == 0 && sp->DNSSD.DNSSD == NO) {
	myLog(LOG_ERR, "parse error in %s : DNS-SD is off and no collectors are defined", sp->configFile);
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
    
    return parseOK;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

