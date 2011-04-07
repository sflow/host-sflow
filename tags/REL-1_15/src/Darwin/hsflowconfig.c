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


#define ADD_TO_LIST(linkedlist, obj) \
  do { \
    obj->nxt = linkedlist; \
    linkedlist = obj; \
  } while(0)
    
  /*________________---------------------------__________________
    ________________       lookupAddress       __________________
    ----------------___________________________------------------
  */

  int lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
  {
    struct addrinfo *info = NULL;
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM; // constrain this so we don't get lots of answers
    hints.ai_family = family; // PF_INET, PF_INET6 or 0
    int err = getaddrinfo(name, NULL, &hints, &info);
    if(err) {
      switch(err) {
      case EAI_NONAME: break;
      case EAI_NODATA: break;
      case EAI_AGAIN: break; // loop and try again?
      default: myLog(LOG_ERR, "getaddrinfo() error: %s", gai_strerror(err)); break;
      }
      return NO;
    }
  
    if(info == NULL) return NO;
  
    if(info->ai_addr) {
      // answer is now in info - a linked list of answers with sockaddr values.
      // extract the address we want from the first one.
      switch(info->ai_family) {
      case PF_INET:
	{
	  struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
	  addr->type = SFLADDRESSTYPE_IP_V4;
	  addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
	  if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      case PF_INET6:
	{
	  struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	  addr->type = SFLADDRESSTYPE_IP_V6;
	  memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
	  if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
	}
	break;
      default:
	myLog(LOG_ERR, "get addrinfo: unexpected address family: %d", info->ai_family);
	return NO;
	break;
      }
    }
    // free the dynamically allocated data before returning
    freeaddrinfo(info);
    return YES;
  }

  /*________________---------------------------__________________
    ________________       parseMAC            __________________
    ----------------___________________________------------------
  */

  static u_char hex2bin(u_char c)
  {
    return (isdigit(c) ? (c)-'0': ((toupper(c))-'A')+10)  & 0xf;
  }
  
  
  int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen)
  {
    // read from hex into bin, up to max binLen chars, return number written
    u_char *h = hex;
    u_char *b = bin;
    u_char c;
    uint32_t i = 0;
    
    while((c = *h++) != '\0') {
      if(isxdigit(c)) {
	u_char val = hex2bin(c);
	if(isxdigit(*h)) {
	  c = *h++;
	  val = (val << 4) | hex2bin(c);
	}
	*b++ = val;
	if(++i >= binLen) return i;
      }
      else if(c != '.' &&
	      c != '-' &&
	      c != ':') { // allow a variety of byte-separators
	return i;
      }
    }
    return i;
  }

  int parseMAC(char *str, uint64_t *mac)
  {
    u_char macbytes[6];
    if(hexToBinary((u_char *)str, macbytes, 6) != 6) return NO;
    // cast to 64-bit integer by simply copying in the bytes.
    // It doesn't matter whether the architecture is big endian
    // or little endian, we are just using this as a convenient
    // comparison symbol.
    memcpy(mac, macbytes, 6);
    return YES;
  }

  int parseUUID(char *str, char *uuid)
  {
    if(hexToBinary((u_char *)str, (u_char *)uuid, 16) != 16) return NO;
    return YES;
  }

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
    uint32_t len = strlen(str);
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
    char *str = strdup(t->str); // take a copy so we can modify it
    uint32_t mult = getMultiplier(str);
    *arg = (mult * strtol(str, NULL, 0));
    free(str);
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

  // expectDevice

   static HSPToken *expectDevice(HSP *sp, HSPToken *tok, SFLAdaptor **p_adaptor)
   {
      HSPToken *t = tok;
      t = t->nxt;
      if(t && t->str) {
	 for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
	    SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
	    if(adaptor && adaptor->deviceName && strcmp(adaptor->deviceName, t->str) == 0) {
	       if(p_adaptor) *p_adaptor = adaptor;
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
    HSPCollector *col = (HSPCollector *)calloc(1, sizeof(HSPCollector));
    ADD_TO_LIST(sFlowSettings->collectors, col);
    sFlowSettings->numCollectors++;
    col->udpPort = SFL_DEFAULT_COLLECTOR_PORT;
    return col;
  }

  HSPSFlowSettings *newSFlowSettings(void) {
    HSPSFlowSettings *st = (HSPSFlowSettings *)calloc(1, sizeof(HSPSFlowSettings));
    st->pollingInterval = SFL_DEFAULT_POLLING_INTERVAL;
    return st;
  }

  void freeSFlowSettings(HSPSFlowSettings *sFlowSettings) {
    for(HSPCollector *coll = sFlowSettings->collectors; coll; ) {
      HSPCollector *nextColl = coll->nxt;
      free(coll);
      coll = nextColl;
    }
    free(sFlowSettings);
  }

  static HSPSFlow *newSFlow(HSP *sp) {
    HSPSFlow *sf = (HSPSFlow *)calloc(1, sizeof(HSPSFlow));
    sf->sFlowSettings_file = newSFlowSettings();
    sf->subAgentId = HSP_DEFAULT_SUBAGENTID;
    sp->sFlow = sf; // just one of these, not a list
    sf->myHSP = sp;
    return sf;
  }

  static HSPToken *newToken(char *str, int len) {
    HSPToken *token = (HSPToken *)calloc(1, sizeof(HSPToken));
    token->str = (char *)calloc(1, len + 1);
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
      return NO;
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
	case HSPTOKEN_DNSSD:
	  if((tok = expectDNSSD(sp, tok)) == NULL) return NO;
	  break;
	case HSPTOKEN_COLLECTOR:
	  if((tok = expectToken(sp, tok, HSPTOKEN_STARTOBJ)) == NULL) return NO;
	  newCollector(sp->sFlow->sFlowSettings_file);
	  level[++depth] = HSPOBJ_COLLECTOR;
	  break;
	case HSPTOKEN_COUNTERPOLLINGINTERVAL:
	  if((tok = expectInteger32(sp, tok, &sp->sFlow->sFlowSettings_file->pollingInterval, 1, 300)) == NULL) return NO;
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
	default:
	  parseError(sp, tok, "unexpected sFlow setting", "");
	  return NO;
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
	 if(sp->sFlow->agentDevice && sp->sFlow->agentDevice->ipAddr.addr) {
	    sp->sFlow->agentIP.type = SFLADDRESSTYPE_IP_V4;
	    sp->sFlow->agentIP.address.ip_v4 = sp->sFlow->agentDevice->ipAddr;
	 }
      }
      if(sp->sFlow->agentIP.type == 0) {
	 // nae luck - try to automatically choose the first non-loopback IP address
	 for(uint32_t i = 0; i < sp->adaptorList->num_adaptors; i++) {
	    SFLAdaptor *adaptor = sp->adaptorList->adaptors[i];
	    // only the non-loopback devices should be listed here, so just take the first
	    if(adaptor && adaptor->ipAddr.addr) {
	       sp->sFlow->agentIP.type = SFLADDRESSTYPE_IP_V4;
	       sp->sFlow->agentIP.address.ip_v4 = adaptor->ipAddr;
	       break;
	    }
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
    }

    return parseOK;
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

