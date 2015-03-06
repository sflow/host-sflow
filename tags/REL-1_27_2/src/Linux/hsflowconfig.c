/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

#define HSP_MAX_LINELEN 2048
#define HSP_MAX_CONFIG_DEPTH 3
#define HSP_SEPARATORS " \t\r\n=;"

extern int debug;
  
  typedef enum { HSPTOKENTYPE_UNDEFINED=0,
		 HSPTOKENTYPE_SYNTAX,
		 HSPTOKENTYPE_OBJ,
		 HSPTOKENTYPE_ATTRIB } EnumHSPTokenType;
  
  // read the special tokens include twice,
  // first to generate the enum, then to
  // populate the special token lookup table
  typedef enum {
#define HSPTOKEN_DATA(tag, token, type) tag,
#include "hsflowtokens.h"
#undef HSPTOKEN_DATA
    HSPTOKEN_NUM_TOKENS } EnumHSPSpecialToken;
  
  typedef struct _HSPSpecialToken {
    EnumHSPSpecialToken tag;
    char *str;
    EnumHSPTokenType type;
  } HSPSpecialToken;
  
  static const HSPSpecialToken HSPSpecialTokens[] = {
#define HSPTOKEN_DATA(tag, token, type) { tag, token, type },
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
    HSPOBJ_COLLECTOR,
  } EnumHSPObject;


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

  static HSPToken *expectONOFF(HSP *sp, HSPToken *tok, int *arg)
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
    if(t && strcasecmp(t->str, "in") == 0) (*arg) = HSF_DIRN_IN;
    else if(t && strcasecmp(t->str, "out") == 0) (*arg) = HSF_DIRN_OUT;
    else if(t && strcasecmp(t->str, "both") == 0) (*arg) = HSF_DIRN_BOTH;
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
      if(sp->DNSSD_domain) my_free(sp->DNSSD_domain);
      sp->DNSSD_domain = my_strdup(t->str);
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
	parseError(sp, tok, "WARNING:", "file does not exist");
	// not a show-stopper. Let it go through.
      }
      *p_fileName = my_strdup(t->str);
      return t;
    }
    parseError(sp, tok, "expected file name", "");
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

  HSPSFlowSettings *newSFlowSettings(void) {
    HSPSFlowSettings *st = (HSPSFlowSettings *)my_calloc(sizeof(HSPSFlowSettings));
    // initialize defaults
    st->samplingRate = SFL_DEFAULT_SAMPLING_RATE;
    st->pollingInterval = SFL_DEFAULT_POLLING_INTERVAL;
    st->headerBytes = SFL_DEFAULT_HEADER_SIZE;
    st->ulogGroup = HSP_DEFAULT_ULOG_GROUP;
    st->jsonPort = HSP_DEFAULT_JSON_PORT;
    st->jsonFIFO = NULL;
    st->xen_update_dominfo = 0;
    st->xen_dsk = 1;
    st->samplingDirection = HSF_DIRN_IN;
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

  static HSPSFlow *newSFlow(HSP *sp) {
    HSPSFlow *sf = (HSPSFlow *)my_calloc(sizeof(HSPSFlow));
    sf->sFlowSettings_file = newSFlowSettings();
    sf->subAgentId = HSP_DEFAULT_SUBAGENTID;
    sp->sFlow = sf; // just one of these, not a list
    sf->myHSP = sp;
    return sf;
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
    // This falls back on the default "sampling=<n>" setting if the speed is unknown or zero
    uint32_t sampling_n = settings->samplingRate;
    char *method = "global_default";
    if(adaptor) {
      HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
      
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

      if(debug) {
	myLog(LOG_INFO, "%s (speed=%"PRIu64") using %s sampling rate = %u",
	      adaptor->deviceName,
	      adaptor->ifSpeed,
	      method,
	      sampling_n);
      }
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

    // skip separators
    r += strspn(r, HSP_SEPARATORS);

    if(*r != '\0') {
      // found token, but watch out for a contiguous '{' or '}' token.
      uint32_t len = strcspn(r, "{}" HSP_SEPARATORS);
      if(len == 0) len = 1; // started with '{' or '}'
      token = newToken(r, len);
      r += len;
    }
    // tell the caller how far we got
    *out = r;
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

    if(sp->sFlow && sp->sFlow->sFlowSettings_file) {
      // allow the agent.cidr settings to boost the priority
      // of this address.  The cidrs are in reverse order.
      HSPCIDR *cidr = sp->sFlow->sFlowSettings_file->agentCIDRs;
      uint32_t cidrIndex = 1;
      for(; cidr; cidrIndex++, cidr=cidr->nxt) {
	if(debug) myLog(LOG_INFO, "testing CIDR at index %d", cidrIndex);
	if(SFLAddress_maskEqual(addr, &cidr->mask, &cidr->ipAddr)) break;
      }
      
      if(cidr) {
	if(debug) myLog(LOG_INFO, "CIDR at index %d matched: boosting priority", cidrIndex);
	boosted_priority += (cidrIndex * IPSP_NUM_PRIORITIES); 
      }
    }
    else {
      if(debug) myLog(LOG_INFO, "agentAddressPriority: no config yet (so no CIDR boost)");
    }
      
    return boosted_priority;
  }


  /*_________________---------------------------__________________
    _________________     selectAgentAddress    __________________
    -----------------___________________________------------------
  */
  
  int selectAgentAddress(HSP *sp, int *p_changed) {

    int selected = NO;
    SFLAddress previous = sp->sFlow->agentIP;

    if(debug) myLog(LOG_INFO, "selectAgentAddress");

    if(sp->sFlow->explicitAgentIP && sp->sFlow->agentIP.type) {
      // it was hard-coded in the config file
      if(debug) myLog(LOG_INFO, "selectAgentAddress hard-coded in config file");
      selected = YES;
    }
    else if(sp->sFlow->explicitAgentDevice && sp->sFlow->agentDevice) {
      // it may have been defined as agent=<device>
      SFLAdaptor *ad = adaptorListGet(sp->adaptorList, sp->sFlow->agentDevice);
      if(ad && ad->userData) {
	HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)ad->userData;
	sp->sFlow->agentIP = adaptorNIO->ipAddr;
	if(debug) myLog(LOG_INFO, "selectAgentAddress pegged to device in config file");
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
      
      for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
	SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
	if(adaptor && adaptor->userData) {
	  HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	  if(adaptorNIO->ipPriority > ipPriority) {
	    selectedAdaptor = adaptor;
	    ipPriority = adaptorNIO->ipPriority;
	  }
	}	    
      }
      if(selectedAdaptor && selectedAdaptor->userData) {
	// crown the winner
	HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)selectedAdaptor->userData;
	sp->sFlow->agentIP = adaptorNIO->ipAddr;
	sp->sFlow->agentDevice = my_strdup(selectedAdaptor->deviceName);
	if(debug) myLog(LOG_INFO, "selectAgentAddress selected agentIP with highest priority");
	selected = YES;
      }
    }

    if(p_changed) {
      if(SFLAddress_equal(&previous, &sp->sFlow->agentIP)) {
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
	  case HSPTOKEN_LOOPBACK:
	    if((tok = expectLoopback(sp, tok)) == NULL) return NO;
	    break;
	  case HSPTOKEN_DNSSD:
	    if((tok = expectONOFF(sp, tok, &sp->DNSSD)) == NULL) return NO;
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

	  case HSPTOKEN_COLLECTOR:
	    if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	    newCollector(sp->sFlow->sFlowSettings_file);
	    level[++depth] = HSPOBJ_COLLECTOR;
	    break;
	  case HSPTOKEN_SAMPLING:
	  case HSPTOKEN_PACKETSAMPLINGRATE:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->samplingRate, 0, 65535)) == NULL) return NO;
	    break;
	  case HSPTOKEN_POLLING:
	  case HSPTOKEN_COUNTERPOLLINGINTERVAL:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->pollingInterval, 0, 300)) == NULL) return NO;
	    break;
	  case HSPTOKEN_AGENTIP:
	    if((tok = expectIP(sp, tok, &sp->sFlow->agentIP, NULL)) == NULL) return NO;
	    sp->sFlow->explicitAgentIP = YES;
	    break;
	  case HSPTOKEN_AGENTCIDR:
	    {
	      HSPCIDR cidr = { 0 };
	      if((tok = expectCIDR(sp, tok, &cidr)) == NULL) return NO;
	      addAgentCIDR(sp->sFlow->sFlowSettings_file, &cidr);
	    }
	    break;
	  case HSPTOKEN_AGENT:
	    if((tok = expectDevice(sp, tok, &sp->sFlow->agentDevice)) == NULL) return NO;
	    sp->sFlow->explicitAgentDevice = YES;
	    break;
	  case HSPTOKEN_SUBAGENTID:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->subAgentId, 0, HSP_MAX_SUBAGENTID)) == NULL) return NO;
	    break;
	  case HSPTOKEN_UUID:
	    if((tok = expectUUID(sp, tok, sp->uuid)) == NULL) return NO;
	    break;
	  case HSPTOKEN_HEADERBYTES:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->headerBytes, 0, HSP_MAX_HEADER_BYTES)) == NULL) return NO;
	    break;
	  case HSPTOKEN_DATAGRAMBYTES:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->datagramBytes, SFL_MIN_DATAGRAM_SIZE, SFL_MAX_DATAGRAM_SIZE)) == NULL) return NO;
	    break;
	  case HSPTOKEN_XEN_UPDATE_DOMINFO:
	    if((tok = expectONOFF(sp, tok, &sp->sFlow->sFlowSettings_file->xen_update_dominfo)) == NULL) return NO;
	    break;
	  case HSPTOKEN_XEN_DSK:
	    if((tok = expectONOFF(sp, tok, &sp->sFlow->sFlowSettings_file->xen_dsk)) == NULL) return NO;
	    break;
	  case HSPTOKEN_ULOGGROUP:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->ulogGroup, 1, 32)) == NULL) return NO;
	    break;
	  case HSPTOKEN_ULOGPROBABILITY:
	    if((tok = expectDouble(sp, tok, &sp->sFlow->sFlowSettings_file->ulogProbability, 0.0, 1.0)) == NULL) return NO;
	    break;
	  case HSPTOKEN_JSONPORT:
	    if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->jsonPort, 1025, 65535)) == NULL) return NO;
	    break;
	  case HSPTOKEN_JSONFIFO:
	    // expect a file name such as "/tmp/hsflowd_json_fifo" that was created using mkfifo(1)
	    if((tok = expectFile(sp, tok, &sp->sFlow->sFlowSettings_file->jsonFIFO)) == NULL) return NO;
	    break;
	  case HSPTOKEN_SAMPLINGDIRECTION:
	    if((tok = expectDirection(sp, tok, &sp->sFlow->sFlowSettings_file->samplingDirection)) == NULL) return NO;
	    break;
	  default:
	    // handle wildcards here - allow sampling.<app>=<n> and polling.<app>=<secs>
	    if(tok->str && strncasecmp(tok->str, "sampling.", 9) == 0) {
	      char *app = tok->str + 9;
	      uint32_t sampling_n=0;
	      if((tok = expectInteger32(sp, tok, &sampling_n, 0, 65535)) == NULL) return NO;
	      setApplicationSampling(sp->sFlow->sFlowSettings_file, app, sampling_n);
	    }
	    else if(tok->str && strncasecmp(tok->str, "polling.", 8) == 0) {
	      char *app = tok->str + 8;
	      uint32_t polling_secs=0;
	      if((tok = expectInteger32(sp, tok, &polling_secs, 0, 300)) == NULL) return NO;
	      setApplicationPolling(sp->sFlow->sFlowSettings_file, app, polling_secs);
	    }
	    else {
	      parseError(sp, tok, "unexpected sFlow setting", "");
	      return NO;
	    }
	    break;
	  }
	  break;
	
	case HSPOBJ_COLLECTOR:
	  {
	    HSPCollector *col = sp->sFlow->sFlowSettings_file->collectors;
	    switch(tok->stok) {
	    case HSPTOKEN_IP:
	      if((tok = expectIP(sp, tok, &col->ipAddr, (struct sockaddr *)&col->sendSocketAddr)) == NULL) return NO;
	      break;
	    case HSPTOKEN_UDPPORT:
	      if((tok = expectInteger32(sp, tok, &col->udpPort, 1, 65535)) == NULL) return NO;
	      break;
	    default:
	      parseError(sp, tok, "unexpected collector setting", "");
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

    if(sp->sFlow == NULL) {
      myLog(LOG_ERR, "parse error in %s : sFlow not found", sp->configFile);
      parseOK = NO;
    }
    else {
      if(sp->sFlow->sFlowSettings_file->numCollectors == 0 && sp->DNSSD == NO) {
	myLog(LOG_ERR, "parse error in %s : DNS-SD is off and no collectors are defined", sp->configFile);
	parseOK = NO;
      }
      
      for(HSPCollector *coll = sp->sFlow->sFlowSettings_file->collectors; coll; coll = coll->nxt) {
	//////////////////////// collector /////////////////////////
	if(coll->ipAddr.type == 0) {
	  myLog(LOG_ERR, "parse error in %s : collector  has no IP", sp->configFile);
	  parseOK = NO;
	}
      }
    }
    
    if(sp->sFlow->sFlowSettings_file->ulogProbability > 0) {
      sp->sFlow->sFlowSettings_file->ulogSamplingRate = (uint32_t)(1.0 / sp->sFlow->sFlowSettings_file->ulogProbability);
    }
    
    return parseOK;
  }
  

#if defined(__cplusplus)
} /* extern "C" */
#endif

