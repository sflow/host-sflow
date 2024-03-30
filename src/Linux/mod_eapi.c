/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

  /*
    Prerequisite:  turn on eAPI:
    
    management api http-commands
    protocol unix-socket
    no shutdown

    as described here:
    https://eos.arista.com/eapi-and-unix-domain-socket/
  */

#include "hsflowd.h"
#include "cJSON.h"

#define HSP_DEFAULT_EAPI_STARTDELAY 2
#define HSP_DEFAULT_EAPI_RETRYDELAY 20

  typedef enum {
    HSPEAPIREQ_HEADERS=0,
    HSPEAPIREQ_LENGTH,
    HSPEAPIREQ_CONTENT,
    HSPEAPIREQ_ENDCONTENT,
    HSPEAPIREQ_ERR
  } HSPEapiRequestState;

  typedef void (*HSPEapiCB)(EVMod *mod, UTStrBuf *buf, cJSON *obj);
  
  typedef struct _HSPEapiRequest {
    UTStrBuf *request;
    UTStrBuf *response;
    HSPEapiCB jsonCB;
    HSPEapiRequestState state;
    int contentLength;
    int chunkLength;
  } HSPEapiRequest;

#define HSP_EAPI_SOCK  VARFS_STR "/run/command-api.sock"
#define HSP_EAPI_HTTP "HTTP/1.0\nHost: localhost\n"
#define HSP_EAPI_CONTENT "Content-Type: application/json\nContent-Length: %u\n\n"
#define HSP_EAPI_REQ_FMT "POST / " HSP_EAPI_HTTP HSP_EAPI_CONTENT "%s"
#define HSP_CONTENT_LENGTH_REGEX "^Content-Length: ([0-9]+)$"

  typedef struct _HSP_mod_Eapi {
    int countdown;
    uint32_t retryDelay;
    EVBus *configBus;
    EVBus *pollBus;
    EVEvent *configStartEvent;
    EVEvent *configEvent;
    EVEvent *configEndEvent;
    int currentRequests;
    regex_t *contentLengthPattern;
  } HSP_mod_Eapi;


  /*_________________---------------------------__________________
    _________________    config_line            __________________
    -----------------___________________________------------------
  */
  static int send_config_line(EVMod *mod, char *fmt, ...) {
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    int ans = 0;
    va_list args;
    va_start(args, fmt);
    // vsnprintf will tell you what space it *would* need
    int needed = vsnprintf(NULL, 0, fmt, args);
    if(needed > 0) {
      char *buf = my_calloc(needed+1);
      va_start(args, fmt);
      ans = vsnprintf(buf, needed+1, fmt, args);
      myDebug(1, "send_config_line <%s>", buf);
      // will copy from config bus to poll bus via pipe
      EVEventTx(mod, mdata->configEvent, buf, my_strlen(buf));
      my_free(buf);
    }
    return ans;
  }

  /*_________________---------------------------__________________
    _________________     eapi_show_sflow       __________________
    -----------------___________________________------------------

Expecting something like:
{"jsonrpc": "2.0", "result": [{"ipv6Destinations": [], "pollingInterval": 30.0, "ipv4Destinations": [{"ipv4Address": "10.0.0.160", "vrfName": "default", "hostname": "10.0.0.160", "port": 6343}], "samplingEnabled": true, "bgpExports": [{"export": false, "vrfName": "default"}], "rewriteDscp": false, "samplePool": 0, "warnings": ["Displaying counters that may be stale"], "enabled": false, "sendingDatagrams": [{"vrfName": "default", "sending": false, "reason": "notRunning"}], "sampleRate": 1048576, "datagrams": 0, "polling": false, "hardwareSamples": 0, "hardwareSampleRate": 1048576, "softwareSamples": 0, "ipv6Sources": [{"vrfName": "default", "ipv6Address": "::", "sourceInterface": "Management1"}], "totalPackets": 0, "ipv4Sources": [{"ipv4Address": "0.0.0.0", "vrfName": "default", "sourceInterface": "Management1"}]}], "id": "hsflowd-1"}
  */

  static void eapi_show_sflow(EVMod *mod, UTStrBuf *buf, cJSON *top) {
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    myDebug(1, "eapi_show_sflow");
    cJSON *result = cJSON_GetObjectItem(top, "result");
    cJSON *sflow = cJSON_GetArrayItem(result, 0);
    cJSON *enabled = cJSON_GetObjectItem(sflow, "enabled");
    cJSON *sources_v4 = cJSON_GetObjectItem(sflow, "ipv4Sources");
    cJSON *sources_v6 = cJSON_GetObjectItem(sflow, "ipv6Sources");
    int n_sources_v4 = cJSON_GetArraySize(sources_v4);
    int n_sources_v6 = cJSON_GetArraySize(sources_v6);
    SFLAddress agent = { 0 };
    bool gotAgent = NO;
    if(n_sources_v4) {
      cJSON *source = cJSON_GetArrayItem(sources_v4, 0);
      cJSON *ip = cJSON_GetObjectItem(source, "ipv4Address");
      gotAgent = parseNumericAddress(ip->valuestring, NULL, &agent, PF_INET);
    }
    if(n_sources_v6 &&  !gotAgent) {
      cJSON *source = cJSON_GetArrayItem(sources_v6, 0);
      cJSON *ip = cJSON_GetObjectItem(source, "ipv6Address");
      gotAgent = parseNumericAddress(ip->valuestring, NULL, &agent, PF_INET6);
    }
    cJSON *dests_v4 = cJSON_GetObjectItem(sflow, "ipv4Destinations");
    cJSON *dests_v6 = cJSON_GetObjectItem(sflow, "ipv6Destinations");
    int n_dests_v4 = cJSON_GetArraySize(dests_v4);
    int n_dests_v6 = cJSON_GetArraySize(dests_v6);
    cJSON *sampling = cJSON_GetObjectItem(sflow, "samplingEnabled");
    cJSON *polling = cJSON_GetObjectItem(sflow, "polling");
    cJSON *sampling_n = cJSON_GetObjectItem(sflow, "sampleRate");
    cJSON *polling_i = cJSON_GetObjectItem(sflow, "pollingInterval");
    cJSON *datagrams_sent = cJSON_GetObjectItem(sflow, "datagrams");
    char ipbuf[51];
    char *agentIP = SFLAddress_print(&agent, ipbuf, 50);
    
    myDebug(1, "agent: %s enabled: %s sampling: %s sampling_n: %s polling: %s polling_interval: %s datagrams: %s",
	    agentIP,
	    cJSON_Print(enabled),
	    cJSON_Print(sampling),
	    cJSON_Print(sampling_n),
	    cJSON_Print(polling),
	    cJSON_Print(polling_i),
	    cJSON_Print(datagrams_sent));

    // Even if "show sflow" indicates one or more valid destinations EOS won't send
    // anything unless a valid source is configured too.  So we only send the collectors
    // below if we have a valid agent address.  Sending num_servers==0 will have the
    // effect of turning off the hsflowd monitoring.

    EVEventTx(mod, mdata->configStartEvent, NULL, 0);
    int num_servers = 0;
    if(SFLAddress_isZero(&agent)) {
      myDebug(1, "no agent IP detected, so sending num_servers==0");
    }
    else {
      send_config_line(mod, "agentIP=%s", agentIP);
      // don't set sampling because it is not needed and it would be misleading
      // anyway - would need to set sampling.<speed> for all speeds before it would
      // be correct.
      // send_config_line(mod, "sampling=%s", cJSON_Print(sampling_n));
      send_config_line(mod, "polling=%s", cJSON_Print(polling_i));
      int dd;
      for(dd = 0; dd < n_dests_v4; dd++) {
	cJSON *dest = cJSON_GetArrayItem(dests_v4, dd);
	cJSON *dest_addr = cJSON_GetObjectItem(dest, "ipv4Address");
	cJSON *dest_port = cJSON_GetObjectItem(dest, "port");
	send_config_line(mod, "collector=%s/%d", dest_addr->valuestring, dest_port->valueint);
	num_servers++;
      }
      for(dd = 0; dd < n_dests_v6; dd++) {
	cJSON *dest = cJSON_GetArrayItem(dests_v6, dd);
	cJSON *dest_addr = cJSON_GetObjectItem(dest, "ipv6Address");
	cJSON *dest_port = cJSON_GetObjectItem(dest, "port");
	send_config_line(mod, "collector=%s/%d", dest_addr->valuestring, dest_port->valueint);
	num_servers++;
      }
    }
    EVEventTx(mod, mdata->configEndEvent, &num_servers, sizeof(num_servers));
  }

  /*_________________---------------------------__________________
    _________________       logJSON             __________________
    -----------------___________________________------------------
  */

  static void logJSON(char *msg, cJSON *obj)
  {
    char *str = cJSON_Print(obj);
    myLog(LOG_INFO, "%s json=<%s>", msg, str);
    my_free(str); // TODO: get this fn from cJSON hooks
  }

  /*_________________---------------------------__________________
    _________________    processEapiJSON        __________________
    -----------------___________________________------------------
  */

  static void processEapiJSON(EVMod *mod, HSPEapiRequest *req, UTStrBuf *buf) {
    myDebug(3, "processEapiJSON");
    cJSON *top = cJSON_Parse(UTSTRBUF_STR(buf));
    if(top) {
      if(EVDebug(mod, 1, NULL))
	logJSON("processEapiJSON:", top);
      (*req->jsonCB)(mod, buf, top);
      cJSON_Delete(top);
    }
  }

  /*_________________---------------------------__________________
    _________________   processEapiResponse     __________________
    -----------------___________________________------------------
  */
  // Assume headers include:
  // Content-Type: Application/JSON
  // Transfer-Encoding: chunked
  //
  // Assume that the chunks of JSON content do not have CR or LF characters within them
  // (if they ever do then we can add another "within chunk" state and append lines to
  // the response result there).
  static void processEapiResponse(EVMod *mod, EVSocket *sock, HSPEapiRequest *req) {
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    char *line = UTSTRBUF_STR(sock->ioline);
    myDebug(2, "EAPI got answer: <%s> state=%d", line, req->state);

    // handle missing length
    if(req->state == HSPEAPIREQ_LENGTH
       && line[0] == '{') {
      myDebug(2, "EAPI got content when expecting length");
      req->state = HSPEAPIREQ_CONTENT;
      req->contentLength = UTSTRBUF_LEN(sock->ioline);
    }

    switch(req->state) {
      
    case HSPEAPIREQ_HEADERS:
      UTStrBuf_chomp(sock->ioline);
      if(UTRegexExtractInt(mdata->contentLengthPattern, line, 1, &req->contentLength, NULL, NULL)) {
	myDebug(1, "got contentLength=%d", req->contentLength);
      }
      else if(UTSTRBUF_LEN(sock->ioline) == 0) {
	req->state = req->contentLength
	  ? HSPEAPIREQ_CONTENT
	  : HSPEAPIREQ_LENGTH;
      }
      break;

    case HSPEAPIREQ_ENDCONTENT:
      UTStrBuf_chomp(sock->ioline);
      if(UTSTRBUF_LEN(sock->ioline) == 0)
	req->state = HSPEAPIREQ_LENGTH;
      break;
      
    case HSPEAPIREQ_LENGTH: {
      UTStrBuf_chomp(sock->ioline);
      char *endp = NULL;
      req->chunkLength = strtol(line, &endp, 16); // hex
      if(*endp != '\0') {
	// failed to consume the whole string - must be an error.
	myDebug(1, "EAPI error: <%s> for request: <%s>",
		line, UTSTRBUF_STR(req->request));
	req->state = HSPEAPIREQ_ERR;
      }
      else {
	req->state = req->chunkLength
	  ? HSPEAPIREQ_CONTENT
	  : HSPEAPIREQ_ENDCONTENT;
      }
      break;
    }

    case HSPEAPIREQ_CONTENT: {
      int clen = req->chunkLength ?: req->contentLength;
      assert(clen == UTSTRBUF_LEN(sock->ioline)); // assume no newlines in chunk
      if(req->response == NULL)
	req->response = UTStrBuf_new();
      UTStrBuf_append_n(req->response, line, UTSTRBUF_LEN(sock->ioline));
      req->state = HSPEAPIREQ_ENDCONTENT;
      break;
    }
      
    case HSPEAPIREQ_ERR:
      // TODO: just wait for EOF, or should we force the socket to close?
      break;
    }
  }

  /*________________---------------------------__________________
    ________________      eapiRequest New/Free __________________
    ----------------___________________________------------------
  */

  static HSPEapiRequest *eapiRequestNew(EVMod *mod, HSPEapiCB jsonCB) {
    HSPEapiRequest *req = (HSPEapiRequest *)my_calloc(sizeof(HSPEapiRequest));
    req->request = UTStrBuf_new();
    req->jsonCB = jsonCB;
    return req;
  }

  static void  eapiRequestFree(EVMod *mod, HSPEapiRequest *req) {
    myDebug(3, "eapiRequestFree");
    UTStrBuf_free(req->request);
    if(req->response) UTStrBuf_free(req->response);
    my_free(req);
  }

  /*________________---------------------------__________________
    ________________    readEapiCB             __________________
    ----------------___________________________------------------
  */
  
  static void readEapiCB(EVMod *mod, EVSocket *sock, EnumEVSocketReadStatus status, void *magic) {
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    HSPEapiRequest *req = (HSPEapiRequest *)magic;
    myDebug(3, "readEapiCB: status=%d", status);
    switch(status) {
    case EVSOCKETREAD_AGAIN:
      break;
    case EVSOCKETREAD_STR:
      processEapiResponse(mod, sock, req);
      UTStrBuf_reset(sock->ioline);
      break;
    case EVSOCKETREAD_EOF:
      if(req->response)
	processEapiJSON(mod, req, req->response);
      // fall through
    case EVSOCKETREAD_BADF:
    case EVSOCKETREAD_ERR:
      // clean up
      assert(mdata->currentRequests > 0);
      --mdata->currentRequests;
      eapiRequestFree(mod, req);
      req = NULL;
    }
  }

  static void readEapi(EVMod *mod, EVSocket *sock, void *magic) {
    EVSocketReadLines(mod, sock, readEapiCB, NO, magic);
  }

  static void eapiRequest(EVMod *mod, HSPEapiRequest *req) {
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    char *cmd = UTSTRBUF_STR(req->request);
    ssize_t len = UTSTRBUF_LEN(req->request);
    int fd = UTUnixDomainSocket(HSP_EAPI_SOCK);
    myDebug(1, "eapiRequest(%s) fd==%d", cmd, fd);
    if(fd < 0)  {
      myLog(LOG_ERR, "eapiRequest - cannot open unixsocket: %s", HSP_EAPI_SOCK);
    }
    else {
      EVBusAddSocket(mod, mdata->configBus, fd, readEapi, req);
      int cc;
      while((cc = write(fd, cmd, len)) != len && errno == EINTR);
      if(cc == len) {
	myDebug(3, "eapiRequest: request sent");
	mdata->currentRequests++;
      }
      else {
	myLog(LOG_ERR, "eapiRequest - write(%s) returned %d != %u: %s",
	      cmd, cc, len, strerror(errno));
      }
    }
  }

  /*________________---------------------------__________________
    ________________      eapi                 __________________
    ----------------___________________________------------------
  */

  static void eapi(EVMod *mod)
  {
    cJSON *root = cJSON_CreateObject(), *params, *cmds;
    cJSON_AddItemToObject(root, "jsonrpc", cJSON_CreateString("2.0"));
    cJSON_AddItemToObject(root, "method", cJSON_CreateString("runCmds"));
    cJSON_AddItemToObject(root, "params", params = cJSON_CreateObject());
    cJSON_AddNumberToObject(params, "version", 1);
    cJSON_AddItemToObject(params, "cmds", cmds = cJSON_CreateArray());
    cJSON_AddItemToArray(cmds, cJSON_CreateString("show sflow"));
    cJSON_AddItemToObject(params, "format", cJSON_CreateString("json"));
    cJSON_AddItemToObject(params, "timestamps", cJSON_CreateBool(NO));
    cJSON_AddItemToObject(root, "id", cJSON_CreateString("hsflowd-1"));
    HSPEapiRequest *req = eapiRequestNew(mod, eapi_show_sflow);
    char *msg = cJSON_Print(root);
    UTStrBuf_printf(req->request, HSP_EAPI_REQ_FMT, my_strlen(msg), msg);
    cJSON_Delete(root);
    eapiRequest(mod, req);
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    myDebug(3, "EAPI tick: countdown=%d", mdata->countdown);
    if(--mdata->countdown <= 0) {
      mdata->countdown = mdata->retryDelay;
      eapi(mod); // will send config line events
    }
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_eapi(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_Eapi));
    HSP_mod_Eapi *mdata = (HSP_mod_Eapi *)mod->data;
    mdata->retryDelay = HSP_DEFAULT_EAPI_RETRYDELAY;
    mdata->countdown = HSP_DEFAULT_EAPI_STARTDELAY;
    mdata->contentLengthPattern = UTRegexCompile(HSP_CONTENT_LENGTH_REGEX);

    // register call-backs
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    mdata->configStartEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_START);
    mdata->configEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_LINE);
    mdata->configEndEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_END);
    
    // not sure if we need a different bus here - only necessary if
    // we think we might block the thread for more than about 200mS
    mdata->configBus = EVGetBus(mod, HSPBUS_CONFIG, YES);
    EVEventRx(mod, EVGetEvent(mdata->configBus, EVEVENT_TICK), evt_tick);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
