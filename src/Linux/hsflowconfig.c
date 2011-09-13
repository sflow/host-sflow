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

  HSPToken *expectInteger32(HSP *sp, HSPToken *tok, uint32_t *arg, uint32_t minVal, uint32_t maxVal)
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
  HSPToken *expectDouble(HSP *sp, HSPToken *tok, double *arg, double minVal, double maxVal)
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

  HSPToken *expectIP(HSP *sp, HSPToken *tok, SFLAddress *addr, struct sockaddr *sa)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || lookupAddress(t->str, sa, addr, 0) == NO) {
      parseError(sp, tok, "expected hostname or IP", "");
      return NULL;
    }
    return t;
  }

  // expectDNSSD

  static HSPToken *expectDNSSD(HSP *sp, HSPToken *tok)
  {
    HSPToken *t = tok;
    t = t->nxt;
    if(t == NULL || (strcasecmp(t->str, "on") != 0 && strcasecmp(t->str, "off") != 0)) {
      parseError(sp, tok, "expected 'on' or 'off'", "");
      return NULL;
    }
    // enable or disable DNS server discovery
    sp->DNSSD = (strcasecmp(t->str, "on") == 0);
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
      for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
	SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
	if(adaptor && adaptor->deviceName && strcmp(adaptor->deviceName, t->str) == 0) {
	  if(p_devName) *p_devName = my_strdup(adaptor->deviceName);
	  return t;
	}
      }
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

  HSPSFlowSettings *newSFlowSettings(void) {
    HSPSFlowSettings *st = (HSPSFlowSettings *)my_calloc(sizeof(HSPSFlowSettings));
    st->samplingRate = SFL_DEFAULT_SAMPLING_RATE;
    st->pollingInterval = SFL_DEFAULT_POLLING_INTERVAL;
    st->headerBytes = SFL_DEFAULT_HEADER_SIZE;
    st->ulogGroup = HSP_DEFAULT_ULOG_GROUP;
    return st;
  }

  void freeSFlowSettings(HSPSFlowSettings *sFlowSettings) {
    clearApplicationSettings(sFlowSettings);
    for(HSPCollector *coll = sFlowSettings->collectors; coll; ) {
      HSPCollector *nextColl = coll->nxt;
      my_free(coll);
      coll = nextColl;
    }
    my_free(sFlowSettings);
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
	case HSPTOKEN_LOOPBACK:
	  if((tok = expectLoopback(sp, tok)) == NULL) return NO;
	  break;
	case HSPTOKEN_DNSSD:
	  if((tok = expectDNSSD(sp, tok)) == NULL) return NO;
	  break;
	case HSPTOKEN_DNSSD_DOMAIN:
	  if((tok = expectDNSSD_domain(sp, tok)) == NULL) return NO;
	  break;
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
	  break;
	case HSPTOKEN_AGENT:
	  if((tok = expectDevice(sp, tok, &sp->sFlow->agentDevice)) == NULL) return NO;
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
	case HSPTOKEN_ULOGGROUP:
	  if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->ulogGroup, 1, 32)) == NULL) return NO;
	  break;
	case HSPTOKEN_ULOGPROBABILITY:
	  if((tok = expectDouble(sp, tok, &sp->sFlow->sFlowSettings_file->ulogProbability, 0.0, 1.0)) == NULL) return NO;
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
      //////////////////////// sFlow /////////////////////////
      if(sp->sFlow->agentIP.type == 0) {
	 // it may have been defined as agent=<device>
	if(sp->sFlow->agentDevice) {
	  SFLAdaptor *ad = adaptorListGet(sp->adaptorList, sp->sFlow->agentDevice);
	  if(ad && ad->ipAddr.addr) {
	    sp->sFlow->agentIP.type = SFLADDRESSTYPE_IP_V4;
	    sp->sFlow->agentIP.address.ip_v4 = ad->ipAddr;
	  }
	}
      }
      if(sp->sFlow->agentIP.type == 0) {
	// nae luck - try to automatically choose the first non-loopback IP address
	// only the non-loopback devices should be listed here, unless the loopback
	// flag was set specially to include them.  However we want to suppress
	// self-assigned IP addresses too, and we'd rather avoid vlan-specific
	// interfaces too if we can, so use a priority scheme...
	
	typedef enum { IPSP_NONE=0,
		       IPSP_LOOPBACK,
		       IPSP_SELFASSIGNED,
		       IPSP_VLAN,
		       IPSP_OK } EnumIPSelectionPriority;

	SFLAdaptor *selectedAdaptor = NULL;
	EnumIPSelectionPriority selectedPriority = IPSP_NONE;

	for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
	  SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
	  if(adaptor && adaptor->ipAddr.addr) {
	    HSPAdaptorNIO *adaptorNIO = (HSPAdaptorNIO *)adaptor->userData;
	    u_char *ipbytes = (u_char *)&(adaptor->ipAddr.addr);
	    EnumIPSelectionPriority ipPriority = IPSP_OK;
	    if(adaptorNIO->loopback) {
	      ipPriority = IPSP_LOOPBACK;
	    }
	    else if (ipbytes[0] == 169 &&
		     ipbytes[1] == 254) {
	      ipPriority = IPSP_SELFASSIGNED;
	    }
	    else if(adaptorNIO->vlan != HSP_VLAN_ALL) {
	      ipPriority = IPSP_VLAN;
	    }
	    if(ipPriority > selectedPriority) {
	      selectedAdaptor = adaptor;
	      selectedPriority = ipPriority;
	    }
	  }
	}
	if(selectedAdaptor) {
	  sp->sFlow->agentIP.type = SFLADDRESSTYPE_IP_V4;
	  sp->sFlow->agentIP.address.ip_v4 = selectedAdaptor->ipAddr;
	  sp->sFlow->agentDevice = my_strdup(selectedAdaptor->deviceName);
	}
      }

      if(sp->sFlow->agentIP.type == 0) {
        // still no agentIP.  That's a showstopper.
	myLog(LOG_ERR, "parse error in %s : agentIP not defined", sp->configFile);
	parseOK = NO;
      }
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

      if(sp->sFlow->sFlowSettings_file->ulogProbability > 0) {
	sp->sFlow->sFlowSettings_file->ulogSamplingRate = (uint32_t)(1.0 / sp->sFlow->sFlowSettings_file->ulogProbability);
      }

    }

    return parseOK;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

