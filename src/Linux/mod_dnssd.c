/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include "arpa/nameser.h"
#include "resolv.h"

#define HSP_DEFAULT_DNSSD_STARTDELAY 30
#define HSP_DEFAULT_DNSSD_RETRYDELAY 300
#define HSP_DEFAULT_DNSSD_MINDELAY 10

#define HSP_MIN_DNAME 4  /* what is the shortest FQDN you can have? */
#define HSP_MIN_TXT 4  /* what is the shortest meaingful TXT record here? */

  // using DNS SRV+TXT records
#define SFLOW_DNS_SD "_sflow._udp"
#define HSP_MAX_DNS_LEN 255
  typedef void (*HSPDnsCB)(EVMod *mod, uint16_t rtype, uint32_t ttl, u_char *key, int keyLen, u_char *val, int valLen, HSPSFlowSettings *settings);

  typedef struct _HSP_mod_DNSSD {
    int countdown;
    uint32_t startDelay;
    uint32_t retryDelay;
    uint32_t ttl;
    EVBus *configBus;
    EVBus *pollBus;
    EVEvent *configStartEvent;
    EVEvent *configEvent;
    EVEvent *configEndEvent;
  } HSP_mod_DNSSD;

    
  /*________________---------------------------__________________
    ________________       dnsSD_Request       __________________
    ----------------___________________________------------------
  */

  static int dnsSD_Request(EVMod *mod, char *dname, uint16_t rtype, HSPDnsCB callback, HSPSFlowSettings *settings)
  {
    // HSP_mod_DNSSD *mdata = (HSP_mod_DNSSD *)mod->data;
    u_char buf[PACKETSZ];

    // We could have a config option to set the DNS servers that we will ask. If so
    // they should be written into this array of sockaddrs...
    // myDebug(1,"_res_nsaddr=%p", &_res.nsaddr);

    myDebug(1,"=== res_search(%s, C_IN, %u) ===", dname, rtype);
    int anslen = res_search(dname, C_IN, rtype, buf, PACKETSZ);
    if(anslen == -1) {
      if(errno == 0 && (h_errno == HOST_NOT_FOUND || h_errno == NO_DATA)) {
	// although res_search returned -1, the request did actually get an answer,
	// it's just that there was no SRV record configured,  or the response was
	// not authoritative. Interpret this the same way as answer_count==0.
	myDebug(1,"res_search(%s, C_IN, %u) came up blank (h_errno=%d)", dname, rtype, h_errno);
	return 0;
      }
      else {
	myLog(LOG_ERR,"res_search(%s, C_IN, %u) failed : %s (h_errno=%d)", dname, rtype, strerror(errno), h_errno);
	return -1;
      }
    }
    if(anslen < sizeof(HEADER)) {
      myLog(LOG_ERR,"res_search(%s) returned %d (too short)", dname, anslen);
      return -1;
    }
    HEADER *ans = (HEADER *)buf;
    if(ans->rcode != NOERROR) {
      myLog(LOG_ERR,"res_search(%s) returned response code %d", dname, ans->rcode);
      return -1;
    }

    uint32_t answer_count = (ntohs(ans->ancount));
    if(answer_count == 0) {
      myLog(LOG_INFO,"res_search(%s) returned no answer", dname);
      return 0;
    }
    myDebug(1, "dnsSD: answer_count = %d", answer_count);

    u_char *p = buf + sizeof(HEADER);
    u_char *endp = buf + anslen;

    // consume query
    int query_name_len = dn_skipname(p, endp);
    if(query_name_len == -1) {
      myLog(LOG_ERR,"dn_skipname() <query> failed");
      return -1;
    }
    myDebug(1, "dnsSD: (compressed) query_name_len = %d", query_name_len);
    p += (query_name_len);
    p += QFIXEDSZ;

    // collect array of results
    for(int entry = 0; entry < answer_count; entry++) {

      myDebug(1, "dnsSD: entry %d, bytes_left=%d", entry, (endp - p));

      // consume name (again)
      query_name_len = dn_skipname(p, endp);
      if(query_name_len == -1) {
	myLog(LOG_ERR,"dn_skipname() <ans> failed");
	return -1;
      }
      p += (query_name_len);

      // now p should be looking at:
      // [type:16][class:16][ttl:32][len:16][record]
      if((endp - p) <= 16) {
	myLog(LOG_ERR,"ans %d of %d: ran off end -- only %d bytes left",
	      entry, answer_count, (endp-p));
	return -1;
      }
      uint16_t res_typ =  (p[0] << 8)  |  p[1];
      uint16_t res_cls =  (p[2] << 8)  |  p[3];
      uint32_t res_ttl =  (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
      uint16_t res_len =  (p[8] << 8)  |  p[9];
      p += 10;
      // use another pointer to walk the payload and move p to the next answer
      u_char *x = p;
      p += res_len;
      uint16_t res_payload = res_len;

      // sanity check
      if(res_typ != rtype ||
	 res_cls != C_IN) {
	myLog(LOG_ERR,"expected t=%d,c=%d, got t=%d,c=%d", rtype, C_IN, res_typ, res_cls);
	return -1;
      }
      
      switch(rtype) {
      case T_SRV:
	{
	  // now x should see
	  // [priority:2][weight:2][port:2][FQDN:res_len-6]
	  uint16_t res_pri = (x[0] << 8)  | x[1];
	  uint16_t res_wgt = (x[2] << 8)  | x[3];
	  uint32_t res_prt = (x[4] << 8)  | x[5];
	  x += 6;
	  res_payload -= 6;
	  
	  // still got room for an FQDN?
	  if((endp - x) < HSP_MIN_DNAME) {
	    myLog(LOG_ERR,"no room for target name -- only %d bytes left", (endp - x));
	    return -1;
	  }
	  
	  char fqdn[MAXDNAME];
	  int ans_len = dn_expand(buf, endp, x, fqdn, MAXDNAME);
	  if(ans_len == -1) {
	    myLog(LOG_ERR,"dn_expand() failed");
	    return -1;
	  }
	  
	  // cross-check
	  if(ans_len != res_payload) {
	    myLog(LOG_ERR,"target name len cross-check failed");
	    return -1;
	  }
	  
	  if(ans_len < HSP_MIN_DNAME) {
	    // just ignore this one -- e.g. might just be "."
	  }
	  else {
	    // fqdn[ans_len] = '\0';
	    myDebug(1, "answer %d is <%s>:<%u> (wgt=%d; pri=%d; ttl=%d; ans_len=%d; res_len=%d)",
			    entry,
			    fqdn,
			    res_prt,
			    res_wgt,
			    res_pri,
			    res_ttl,
			    ans_len,
			    res_len);
	    if(callback) {
	      char fqdn_port[PACKETSZ];
	      sprintf(fqdn_port, "%s/%u", fqdn, res_prt);
	      // use key == NULL to indicate that the value is host:port
	      (*callback)(mod, rtype, res_ttl, NULL, 0, (u_char *)fqdn_port, strlen(fqdn_port), settings);
	    }
	  }
	}
	break;
      case T_TXT:
	{
	  // now x should see
	  // [TXT:res_len]

	  // still got room for a text record?
	  if((endp - x) < HSP_MIN_TXT) {
	    myLog(LOG_ERR,"no room for text record -- only %d bytes left", (endp - x));
	    return -1;
	  }

	  if(getDebug()) {
	    printf("dsnSD TXT Record: ");
	    for(int i = 0; i < res_len; i++) {
	      int ch = x[i];
	      if(isalnum(ch)) printf("%c", ch);
	      else printf("{%02x}", ch);
	    } 
	    printf("\n");
	  }

	  // format is [len][<key>=<val>][len][<key>=<val>]...
	  // so we can pull out the settings and give them directly
	  // to the callback fn without copying
	  u_char *txtend = x + res_len;
	  // need at least 3 chars for a var=val setting
	  while((txtend - x) >= 3) {
	    int pairlen = *x++;
	    int klen = strcspn((char *)x, "=");
	    if(klen < 0) {
	      myLog(LOG_ERR, "dsnSD TXT record not in var=val format: %s", x);
	    }
	    else {
	      if(callback) (*callback)(mod, rtype, res_ttl, x, klen, (x+klen+1), (pairlen - klen - 1), settings);
	    }
	    x += pairlen;
	  }
	}
	break;

      default:
	myLog(LOG_ERR, "unsupported query type: %u" , rtype);
	return -1;
	break;
      }
    }
    return answer_count;
  }
    
  /*________________---------------------------__________________
    ________________      dnsSD                __________________
    ----------------___________________________------------------
  */

  static int dnsSD(EVMod *mod, HSPDnsCB callback, HSPSFlowSettings *settings)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    // HSP_mod_DNSSD *mdata = (HSP_mod_DNSSD *)mod->data;
    char request[HSP_MAX_DNS_LEN];
    char *domain_override = sp->DNSSD.domain ?: "";
    snprintf(request, HSP_MAX_DNS_LEN, "%s%s", SFLOW_DNS_SD, domain_override);
    int num_servers = dnsSD_Request(mod, request, T_SRV, callback, settings);
    dnsSD_Request(mod, request, T_TXT, callback, settings);
    // it's ok even if only the SRV request succeeded
    return num_servers; //  -1 on error
  }

  /*_________________---------------------------__________________
    _________________      myDnsCB              __________________
    -----------------___________________________------------------
  */

  static void myDnsCB(EVMod *mod, uint16_t rtype, uint32_t ttl, u_char *key, int keyLen, u_char *val, int valLen, HSPSFlowSettings *st)
  {
    HSP_mod_DNSSD *mdata = (HSP_mod_DNSSD *)mod->data;
    // latch the min ttl
    if(mdata->ttl == 0 || ttl < mdata->ttl) {
      mdata->ttl = ttl;
    }

    char keyBuf[1024];
    char valBuf[1024];
    if(keyLen > 1023 || valLen > 1023) {
      myLog(LOG_ERR, "myDNSCB: string too long");
      return;
    }
    // make a null-terminated copy of key and value
    // and be careful to avoid memcpy(<target>, 0, 0) because it seems to break
    // things horribly when the gcc optimizer is on.
    if(key && keyLen) memcpy(keyBuf, (char *)key, keyLen);
    keyBuf[keyLen] = '\0';
    if(val && valLen) memcpy(valBuf, (char *)val, valLen);
    valBuf[valLen] = '\0';

    myDebug(1, "dnsSD: (rtype=%u,ttl=%u) <%s>=<%s>", rtype, ttl, keyBuf, valBuf);

    if(((keyLen ?: strlen("collector")) + valLen + 2) > EV_MAX_EVT_DATALEN) {
      myLog(LOG_ERR, "myDNSCB: config line too long");
      return;
    }

    char cfgLine[EV_MAX_EVT_DATALEN];
    snprintf(cfgLine, EV_MAX_EVT_DATALEN, "%s=%s", (keyLen ? keyBuf : "collector"), valBuf);
    
    // sending configEvent (pollBus) from here (configBus) means it will go via pipe
    EVEventTx(mod, mdata->configEvent, cfgLine, my_strlen(cfgLine));
  }

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DNSSD *mdata = (HSP_mod_DNSSD *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(--mdata->countdown <= 0) {
      // SIGSEGV on Fedora 14 if HSP_RLIMIT_MEMLOCK is non-zero, because calloc returns NULL.
      // Maybe we need to repeat some of the setrlimit() calls here in the forked thread? Or
      // maybe we are supposed to fork the DNSSD thread before dropping privileges?
      
      // we want the min ttl, so clear it here
      mdata->ttl = 0;
      // now make the requests
      EVEventTx(mod, mdata->configStartEvent, NULL, 0);
      int num_servers = dnsSD(mod, myDnsCB, sp->sFlowSettings_dnsSD); // will send config line events
      EVEventTx(mod, mdata->configEndEvent, &num_servers, sizeof(num_servers));
	
      // whatever happens we might still learn a TTL (e.g. from the TXT record query)
      mdata->countdown = mdata->ttl ?: mdata->retryDelay;
      // but make sure it's sane
      if(mdata->countdown < HSP_DEFAULT_DNSSD_MINDELAY) {
	myDebug(1, "forcing minimum DNS polling delay");
	mdata->countdown = HSP_DEFAULT_DNSSD_MINDELAY;
      }
      myDebug(1, "DNSSD polling delay set to %u seconds", mdata->countdown);
    }  
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_dnssd(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_DNSSD));
    HSP_mod_DNSSD *mdata = (HSP_mod_DNSSD *)mod->data;
    mdata->startDelay = HSP_DEFAULT_DNSSD_STARTDELAY;
    mdata->retryDelay = HSP_DEFAULT_DNSSD_RETRYDELAY;

    // make sure we don't all hammer the DNS server immediately on restart
    mdata->countdown = sfl_random(mdata->startDelay);

    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    mdata->configStartEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_START);
    mdata->configEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_LINE);
    mdata->configEndEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_END);

    mdata->configBus = EVGetBus(mod, HSPBUS_CONFIG, YES);
    EVEventRx(mod, EVGetEvent(mdata->configBus, EVEVENT_TICK), evt_tick);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif

