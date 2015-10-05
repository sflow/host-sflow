/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  extern int debug;

#ifdef HSF_JSON


#ifdef HSF_RTMETRIC
  
  typedef enum {
    RTMetricType_string = 0,
    RTMetricType_counter32,
    RTMetricType_counter64,
    RTMetricType_gauge32,
    RTMetricType_gauge64,
    RTMetricType_gaugeFloat,
    RTMetricType_gaugeDouble
  } EnumRTMetricType;

  typedef enum {
    RTFlowType_string = 0,
    RTFlowType_mac,
    RTFlowType_ip,
    RTFlowType_ip6,
    RTFlowType_int32,
    RTFlowType_int64,
    RTFlowType_float,
    RTFlowType_double
  } EnumRTFlowType;
  
#define HSP_MAX_RTMETRIC_KEY_LEN 64
#define HSP_MAX_RTMETRIC_VAL_LEN 255

#define TAG_RTMETRIC ((4300 << 12) + 1002)
#define TAG_RTFLOW ((4300 << 12) + 1003)

#endif /* HSF_RTMETRIC */

  /*_________________---------------------------__________________
    _________________  int counters and gauges  __________________
    -----------------___________________________------------------
    Avoid cJSON->valueint, because it is limited to INT_MAX in the
    cJSON library, which is only 2^31 on Linux,  even on 64-bit architectures.
  */
  static uint16_t json_uint16(cJSON *cj, const char *fieldName) {
    cJSON *field = cJSON_GetObjectItem(cj, fieldName);
    return field ? (uint16_t)field->valuedouble : 0;
  }
  static uint32_t json_uint32(cJSON *cj, const char *fieldName) {
    cJSON *field = cJSON_GetObjectItem(cj, fieldName);
    return field ? (uint32_t)field->valuedouble : 0;
  }
  static uint64_t json_uint64(cJSON *cj, const char *fieldName) {
    cJSON *field = cJSON_GetObjectItem(cj, fieldName);
    return field ? (uint64_t)field->valuedouble : 0;
  }
  static uint32_t json_gauge32(cJSON *cj, const char *fieldName) {
    return json_uint32(cj, fieldName);
  }
  static uint64_t json_gauge64(cJSON *cj, const char *fieldName) {
    return json_uint64(cj, fieldName);
  }
  static uint32_t json_counter32(cJSON *cj, const char *fieldName) {
    cJSON *field = cJSON_GetObjectItem(cj, fieldName);
    return field ? (uint32_t)field->valuedouble : (uint32_t)-1;
  }

  /*_________________---------------------------__________________
    _________________    agentCB_getCounters    __________________
    -----------------___________________________------------------
  */
  
  static void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    HSP *sp = (HSP *)magic;

    // we stashed a pointer to the application in the userData field
    HSPApplication *application = (HSPApplication *)poller->userData;

    // are we receiving counter updates via JSON messages?
    int json_ctrs = ((sp->clk - application->last_json_counters) < HSP_COUNTER_SYNTH_TIMEOUT);

    if(json_ctrs != application->json_counters) {
      // state transition - reset seq no
      sfl_poller_resetCountersSeqNo(application->poller);
      application->json_counters = json_ctrs;
    }
    
    if(!json_ctrs) {
      // The application is not sending counters, so send the synthesized
      // app_operations counter block that we have been maintaining.
      SFLADD_ELEMENT(cs, &application->counters);
      sfl_poller_writeCountersSample(poller, cs);
      // and any rtcount metrics that we have been collecting
    }
  }

  /*_________________---------------------------__________________
    _________________      addApplication       __________________
    -----------------___________________________------------------
  */
  
  static uint32_t nextApplicationDSIndex = 0;
  static uint32_t service_port_clash = 0;
#define HSP_SERVICE_PORT_CLASH_WARNINGS 3

  static HSPApplication *addApplication(HSP *sp, char *application, uint16_t servicePort)
  {
    // assigning dsIndex:
    // 1: $$$ need to make it persistent on a restart - perhaps using hsflowd.c:assignVM_dsIndex()
    // 2: $$$ circle back and find a free one if we reach end of range
    uint32_t dsIndex = servicePort ? servicePort : (HSP_DEFAULT_APP_DSINDEX_START + nextApplicationDSIndex++);
    SFLDataSource_instance dsi;
    SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, dsIndex, 0);

    // before we allocate anything, make sure there isn't a clash on servicePort
    if(servicePort && sfl_agent_getPoller(sp->sFlow->agent, &dsi)) {
      service_port_clash++;
      if(debug || service_port_clash < HSP_SERVICE_PORT_CLASH_WARNINGS) {
	myLog(LOG_ERR, "addApplication(%s) service port %d already allocated for another application",
	      application,
	      servicePort);
	return NULL;
      }
    }

    // OK,  create the application
    HSPApplication *aa = (HSPApplication *)my_calloc(sizeof(HSPApplication));
    aa->application = my_strdup(application);
    aa->dsIndex = dsIndex;
    aa->servicePort = servicePort;
    uint32_t sampling_n = 0;
    uint32_t polling_secs = 0;
    aa->settings_revisionNo = sp->sFlow->revisionNo;
    lookupApplicationSettings(sp->sFlow->sFlowSettings, "app", application, &sampling_n, &polling_secs);
    // poller
    aa->poller = sfl_agent_addPoller(sp->sFlow->agent, &dsi, sp, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(aa->poller, polling_secs);
    sfl_poller_set_sFlowCpReceiver(aa->poller, HSP_SFLOW_RECEIVER_INDEX); 
    // point to the application with the userData ptr
    aa->poller->userData = aa;
    // more counter-block initialization
    aa->counters.tag = SFLCOUNTERS_APP;
    aa->counters.counterBlock.app.application.str = aa->application; // just point
    aa->counters.counterBlock.app.application.len = my_strlen(aa->application);
    // start off assuming that the application is going to send it's own counters
    aa->json_counters = YES;
    aa->last_json_counters = sp->clk;
    // sampler
    aa->sampler = sfl_agent_addSampler(sp->sFlow->agent, &dsi);
    sfl_sampler_set_sFlowFsPacketSamplingRate(aa->sampler, sampling_n);
    sfl_sampler_set_sFlowFsReceiver(aa->sampler, HSP_SFLOW_RECEIVER_INDEX);
    
    return aa;
  }

  /*_________________-----------------------------__________________
    _________________     getApplication          __________________
    -----------------_____________________________------------------
  */

  static HSPApplication *getApplication(HSP *sp, char *application, uint16_t servicePort)
  {
    HSPApplication *aa = NULL;
    if(sp->applicationHT_size == 0) {
      // first time: initialize the hash table
      sp->applicationHT_size = HSP_INITIAL_JSON_APP_HT_SIZE;
      sp->applicationHT = (HSPApplication **)my_calloc(sp->applicationHT_size * sizeof(HSPApplication *));
      sp->applicationHT_entries = 0;
    }

    uint32_t hash = my_strhash(application);
    uint32_t hashBkt = hash & (sp->applicationHT_size - 1);
    aa = sp->applicationHT[hashBkt];
    for(; aa; aa = aa->ht_nxt) {
      if(hash == aa->hash && my_strequal(application, aa->application)) break;
    }
    if(aa == NULL) {
      // create new application
      if(debug) myLog(LOG_INFO, "adding new application: %s", application);
      aa = addApplication(sp, application, servicePort);
      if(aa) {
	// add to HT
	aa->hash = hash;
	aa->ht_nxt = sp->applicationHT[hashBkt];
	sp->applicationHT[hashBkt] = aa;
	if(++sp->applicationHT_entries > sp->applicationHT_size) {
	  /* grow the HT */
	  uint32_t newSize = sp->applicationHT_size * 2;
	  HSPApplication **newTable = (HSPApplication **)my_calloc(newSize * sizeof(HSPApplication *));
	  for(uint32_t bkt = 0; bkt < sp->applicationHT_size; bkt++) {
	    for(HSPApplication *aa = sp->applicationHT[bkt]; aa; ) {
	      HSPApplication *next_aa = aa->ht_nxt;
	      uint32_t newHashBkt = aa->hash & (newSize - 1);
	      aa->ht_nxt = newTable[newHashBkt];
	      newTable[newHashBkt] = aa;
	      aa = next_aa;
	    }
	  }
	  my_free(sp->applicationHT);
	  sp->applicationHT = newTable;
	  sp->applicationHT_size = newSize;
	}
      }
    }

    // make sure the application wasn't already instantiated with another servicePort (or with no servicePort)
    // This is just a warning,  though.  After all, things do change sometimes.
    if(servicePort != aa->servicePort) {
      if(debug || aa->service_port_clash < HSP_SERVICE_PORT_CLASH_WARNINGS) {
	myLog(LOG_ERR, "Warning: conflicting servicePort for application %s (current=%d, offered=%d)",
	      application,
	      aa->servicePort,
	      servicePort);
      }
    }

    // check in case the configuration changed since the last time we looked
    // could move this to agentCB_getCounters(), but the test is not expensive
    // so doing it for every sample seems OK.
    if(aa->settings_revisionNo != sp->sFlow->revisionNo) {
      uint32_t sampling_n = 0;
      uint32_t polling_secs = 0;
      aa->settings_revisionNo = sp->sFlow->revisionNo;
      lookupApplicationSettings(sp->sFlow->sFlowSettings, "app", application, &sampling_n, &polling_secs);
      sfl_poller_set_sFlowCpInterval(aa->poller, polling_secs);
      sfl_sampler_set_sFlowFsPacketSamplingRate(aa->sampler, sampling_n);
    }

    return aa;
  }      


  /*_________________---------------------------__________________
    _________________   json_app_timeout_check  __________________
    -----------------___________________________------------------
    Check to see if we should free an idle application that has stopped sending.
    This allows applications to be fairly numerous and transient without causing
    this program to grow too large.
  */

  void json_app_timeout_check(HSP *sp)
  {
    if(sp->applicationHT_entries) {
      for(uint32_t bkt = 0; bkt < sp->applicationHT_size; bkt++) {
	for(HSPApplication *prev = NULL, *aa = sp->applicationHT[bkt]; aa; ) {
	  HSPApplication *next_aa = aa->ht_nxt;
	  if((sp->clk - aa->last_json) > HSP_JSON_APP_TIMEOUT) {
	    if(debug) myLog(LOG_INFO, "removing idle application: %s\n", aa->application);
	    // unlink
	    if(prev) prev->ht_nxt = next_aa;
	    else sp->applicationHT[bkt] = next_aa;
	    // remove sampler and poller
	    sfl_agent_removeSampler(sp->sFlow->agent, &aa->sampler->dsi);
	    sfl_agent_removePoller(sp->sFlow->agent, &aa->poller->dsi);
	    // free
	    my_free(aa->application);
	    my_free(aa);
	    // update the count
	    sp->applicationHT_entries--;
	  }
	  else prev = aa;
	  aa = next_aa;
	}
      }
    }
  }
  

  /*_________________---------------------------__________________
    _________________       logJSON             __________________
    -----------------___________________________------------------
  */

  static void logJSON(cJSON *obj, char *msg)
  {
    char *str = cJSON_Print(obj);
    myLog(LOG_INFO, "%s json=<%s>", msg, str);
    my_free(str);
  }


  /*_________________---------------------------__________________
    _________________     sendAppSample         __________________
    -----------------___________________________------------------
  */

  static void sendAppSample(HSP *sp, HSPApplication *app, uint32_t sampling_n, int as_client, char *operation, char *attributes, char *status_descr, EnumSFLAPPStatus status, uint64_t req_bytes, uint64_t resp_bytes, uint32_t duration_uS, char *parent_app, char *parent_operation, char *parent_attributes, char *actor_init, char *actor_tgt, SFLExtended_socket_ipv4 *soc4,  SFLExtended_socket_ipv6 *soc6)
  {

    // encode an sFlow transaction sample
    SFL_FLOW_SAMPLE_TYPE fs = { 0 };
    // client/server info in encoded into the input/output field
    // according to this sFlow convention:
    if(as_client) {
      fs.input = SFL_INTERNAL_INTERFACE;
    }
    else {
      fs.output = SFL_INTERNAL_INTERFACE;
    }
    
    SFLFlow_sample_element appElem = { 0 };
    appElem.tag = SFLFLOW_APP;
    appElem.flowType.app.context.application.str = app->application;
    appElem.flowType.app.context.application.len = my_strnlen(app->application, SFLAPP_MAX_APPLICATION_LEN);
    appElem.flowType.app.context.operation.str = operation;
    appElem.flowType.app.context.operation.len = my_strnlen(operation, SFLAPP_MAX_OPERATION_LEN);
    appElem.flowType.app.context.attributes.str = attributes;
    appElem.flowType.app.context.attributes.len = my_strnlen(attributes, SFLAPP_MAX_ATTRIBUTES_LEN);
    appElem.flowType.app.status_descr.str = status_descr;
    appElem.flowType.app.status_descr.len = my_strnlen(status_descr, SFLAPP_MAX_STATUS_LEN);
    appElem.flowType.app.status = (EnumSFLAPPStatus)status;
    appElem.flowType.app.req_bytes = req_bytes;
    appElem.flowType.app.resp_bytes = resp_bytes;
    appElem.flowType.app.duration_uS = duration_uS;
    SFLADD_ELEMENT(&fs, &appElem);

    SFLFlow_sample_element parentContextElem = { 0 };
    if(parent_app) {
      parentContextElem.tag = SFLFLOW_APP_CTXT;
      parentContextElem.flowType.context.application.str = parent_app;
      parentContextElem.flowType.context.application.len = my_strlen(parent_app);
      parentContextElem.flowType.context.operation.str = parent_operation;
      parentContextElem.flowType.context.operation.len = my_strlen(parent_operation);
      parentContextElem.flowType.context.attributes.str = parent_attributes;
      parentContextElem.flowType.context.attributes.len = my_strlen(parent_attributes);
      SFLADD_ELEMENT(&fs, &parentContextElem);
    }

    SFLFlow_sample_element initiatorElem = { 0 };
    if(actor_init) {
      initiatorElem.tag = SFLFLOW_APP_ACTOR_INIT;
      initiatorElem.flowType.actor.actor.str = actor_init;
      initiatorElem.flowType.actor.actor.len = my_strnlen(actor_init, SFLAPP_MAX_ACTOR_LEN);
      SFLADD_ELEMENT(&fs, &initiatorElem);
    }

    SFLFlow_sample_element targetElem = { 0 };
    if(actor_tgt) {
      targetElem.tag = SFLFLOW_APP_ACTOR_TGT;
      targetElem.flowType.actor.actor.str = actor_tgt;
      targetElem.flowType.actor.actor.len = my_strnlen(actor_tgt, SFLAPP_MAX_ACTOR_LEN);
      SFLADD_ELEMENT(&fs, &targetElem);
    }
      
    SFLFlow_sample_element ssockElem4 = { 0 };
    if(soc4) {
      ssockElem4.tag = SFLFLOW_EX_SOCKET4;
      ssockElem4.flowType.socket4 = *soc4;
      SFLADD_ELEMENT(&fs, &ssockElem4);
    }
      
    SFLFlow_sample_element ssockElem6 = { 0 };
    if(soc6) {
      ssockElem6.tag = SFLFLOW_EX_SOCKET6;
      ssockElem6.flowType.socket6 = *soc6;
      SFLADD_ELEMENT(&fs, &ssockElem6);
    }


    // sample_pool
    app->sampler->samplePool += sampling_n;
    // override the sampler's sampling_rate by filling it in here:
    fs.sampling_rate = sampling_n;
    if(debug > 1) {
      myLog(LOG_INFO, "sendAppSample (sampling_n=%d)", sampling_n);
    }
    // and send it out
    sfl_sampler_writeFlowSample(app->sampler, &fs);
  }


  /*_________________---------------------------__________________
    _________________      readJSON_flowSample  __________________
    -----------------___________________________------------------
  */

static void readJSON_flowSample(HSP *sp, cJSON *fs)
  {
    if(debug > 1) logJSON(fs, "got flow sample");
    cJSON *app = cJSON_GetObjectItem(fs, "app_name");
    uint16_t service_port = json_uint16(fs, "service_port");
    cJSON *as_client = cJSON_GetObjectItem(fs, "client");
    uint32_t sampling_n = json_uint32(fs, "sampling_rate");
    if(sampling_n == 0) sampling_n = 1;
    
    if(app) {
      HSPApplication *application = getApplication(sp, app->valuestring, service_port);
      if(application) {
	// remember that we heard from this application
	application->last_json = sp->clk;

	cJSON *opn = cJSON_GetObjectItem(fs, "app_operation");
	if(opn) {
	  EnumSFLAPPStatus status = SFLAPP_SUCCESS;
	  cJSON *sts = cJSON_GetObjectItem(opn, "status");
	  if(sts) {
	    status = (EnumSFLAPPStatus)json_uint32(opn, "status");
	    if((u_int)status > (u_int)SFLAPP_UNAUTHORIZED) {
	      status = SFLAPP_OTHER;
	    }
	  }
	
	  // update my version of the counters - even if we are not going to send them
	  // because the application is sending them anyway.  It will be a good cross-check
	  int ii = (uint)status;
	  uint32_t *errorCounterArray = &application->counters.counterBlock.app.status_OK;
	  errorCounterArray[ii] += sampling_n;
	
	  // decide if we are going to sample this transaction, based
	  // on the ratio of sampling_n to the configured sampling rate
	  // in the sampler.
	  uint32_t config_sampling_n = sfl_sampler_get_sFlowFsPacketSamplingRate(application->sampler);
	  uint32_t sub_sampling_n = config_sampling_n / sampling_n;
	  if(sub_sampling_n == 0) sub_sampling_n = 1;
	  uint32_t effective_sampling_n = sampling_n * sub_sampling_n;
	  if(sub_sampling_n == 1
	     || sfl_random(sub_sampling_n * 16) <= 16) {
	    // sample this one

	    // extract operation fields
	    cJSON *operation = cJSON_GetObjectItem(opn, "operation");
	    cJSON *attributes = cJSON_GetObjectItem(opn, "attributes");
	    cJSON *status_descr = cJSON_GetObjectItem(opn, "status_descr");

	    uint64_t req_bytes = json_gauge64(opn, "req_bytes");
	    uint64_t resp_bytes = json_gauge64(opn, "resp_bytes");
	    uint32_t uS = json_gauge32(opn, "uS");

	    // optional fields: parent context
	    char *parent_app = NULL;
	    char *parent_operation = NULL;
	    char *parent_attributes = NULL;
	    cJSON *parent_context = cJSON_GetObjectItem(fs, "app_parent_context");
	    if(parent_context) {
	      cJSON *p_app = cJSON_GetObjectItem(parent_context, "application");
	      if(p_app) parent_app = p_app->valuestring;
	      cJSON *p_op = cJSON_GetObjectItem(parent_context, "operation");
	      if(p_op) parent_operation = p_op->valuestring;
	      cJSON *p_attrib = cJSON_GetObjectItem(parent_context, "attributes");
	      if(p_attrib) parent_attributes = p_attrib->valuestring;
	    }
	  
	    // optional fields: actors
	    char *actor_initiator = NULL;
	    char *actor_target = NULL;
	    cJSON *app_initiator = cJSON_GetObjectItem(fs, "app_initiator");
	    if(app_initiator) {
	      cJSON *ai = cJSON_GetObjectItem(app_initiator, "actor");
	      if(ai) actor_initiator = ai->valuestring;
	    }
	    cJSON *app_target = cJSON_GetObjectItem(fs, "app_target");
	    if(app_target) {
	      cJSON *at = cJSON_GetObjectItem(app_target, "actor");
	      if(at) actor_target = at->valuestring;
	    }

	    // optional fields: sockets
	    SFLExtended_socket_ipv4 soc4 = {  0 };
	    cJSON *extended_socket_ipv4 = cJSON_GetObjectItem(fs, "extended_socket_ipv4");
	    if(extended_socket_ipv4) {
	      soc4.protocol = json_uint32(extended_socket_ipv4, "protocol");
	      soc4.local_port = json_uint32(extended_socket_ipv4, "local_port");
	      soc4.remote_port = json_uint32(extended_socket_ipv4, "remote_port");
	      cJSON *local_ip = cJSON_GetObjectItem(extended_socket_ipv4, "local_ip");
	      if(local_ip && my_strlen(local_ip->valuestring)) {
		SFLAddress addr = { 0 };
		if(parseNumericAddress(local_ip->valuestring, NULL, &addr, PF_INET)) {
		  soc4.local_ip = addr.address.ip_v4;
		}
	      }
	      cJSON *remote_ip = cJSON_GetObjectItem(extended_socket_ipv4, "remote_ip");
	      if(remote_ip && my_strlen(remote_ip->valuestring)) {
		SFLAddress addr = { 0 };
		if(parseNumericAddress(remote_ip->valuestring, NULL, &addr, PF_INET)) {
		  soc4.remote_ip = addr.address.ip_v4;
		}
	      }
	    }

	    SFLExtended_socket_ipv6 soc6 = {  0 };
	    cJSON *extended_socket_ipv6 = cJSON_GetObjectItem(fs, "extended_socket_ipv6");
	    if(extended_socket_ipv6) {
	      soc6.protocol = json_uint32(extended_socket_ipv6, "protocol");
	      soc6.local_port = json_uint32(extended_socket_ipv6, "local_port");
	      soc6.remote_port = json_uint32(extended_socket_ipv6, "remote_port");
	      cJSON *local_ip = cJSON_GetObjectItem(extended_socket_ipv6, "local_ip");
	      if(local_ip && my_strlen(local_ip->valuestring)) {
		SFLAddress addr = { 0 };
		if(parseNumericAddress(local_ip->valuestring, NULL, &addr, PF_INET6)) {
		  soc6.local_ip = addr.address.ip_v6;
		}
	      }
	      cJSON *remote_ip = cJSON_GetObjectItem(extended_socket_ipv6, "remote_ip");
	      if(remote_ip && my_strlen(remote_ip->valuestring)) {
		SFLAddress addr = { 0 };
		if(parseNumericAddress(remote_ip->valuestring, NULL, &addr, PF_INET6)) {
		  soc6.remote_ip = addr.address.ip_v6;
		}
	      }
	    }

	    // submit the flow sample
	    sendAppSample(sp,
			  application,
			  effective_sampling_n,
			  as_client ? (as_client->type == cJSON_True) : NO,
			  operation ? operation->valuestring : NULL,
			  attributes ? attributes->valuestring : NULL,
			  status_descr ? status_descr->valuestring : NULL,
			  status,
			  req_bytes,
			  resp_bytes,
			  uS,
			  parent_app,       // any of the following may be NULL
			  parent_operation,
			  parent_attributes,
			  actor_initiator,
			  actor_target,
			  extended_socket_ipv4 ? &soc4 : NULL,
			  extended_socket_ipv6 ? &soc6 : NULL);
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________  readJSON_counterSample   __________________
    -----------------___________________________------------------
  */

static void readJSON_counterSample(HSP *sp, cJSON *cs)
  {
    if(debug > 1) logJSON(cs, "got counter sample");
    cJSON *app_name = cJSON_GetObjectItem(cs, "app_name");
    uint16_t service_port = json_uint16(cs, "service_port");
    if(app_name) {
      HSPApplication *application = getApplication(sp, app_name->valuestring, service_port);
      if(application) {
	// remember that we heard from this application
	application->last_json = sp->clk;
	// and remember that the application sent these counters
	application->last_json_counters = sp->clk;

	SFL_COUNTERS_SAMPLE_TYPE csample = { 0 };
	// app_operations
	SFLCounters_sample_element c_ops = { 0 };
	cJSON *ops = cJSON_GetObjectItem(cs, "app_operations");
	int json_ops = (ops != NULL);
	if(json_ops != application->json_ops_counters) {
	  // policy transisition - reset seq nos
	  sfl_poller_resetCountersSeqNo(application->poller);
	  application->json_ops_counters = json_ops;
	}
	  
	if(json_ops) {
	  c_ops.tag = SFLCOUNTERS_APP;
	  c_ops.counterBlock.app.application.str = app_name->valuestring;
	  c_ops.counterBlock.app.application.len = my_strnlen(app_name->valuestring, SFLAPP_MAX_APPLICATION_LEN);
	  c_ops.counterBlock.app.status_OK = json_counter32(ops, "success");
	  c_ops.counterBlock.app.errors_OTHER = json_counter32(ops, "other");
	  c_ops.counterBlock.app.errors_TIMEOUT = json_counter32(ops, "timeout");
	  c_ops.counterBlock.app.errors_INTERNAL_ERROR = json_counter32(ops, "internal_error");
	  c_ops.counterBlock.app.errors_BAD_REQUEST = json_counter32(ops, "bad_request");
	  c_ops.counterBlock.app.errors_FORBIDDEN = json_counter32(ops, "forbidden");
	  c_ops.counterBlock.app.errors_TOO_LARGE = json_counter32(ops, "too_large");
	  c_ops.counterBlock.app.errors_NOT_IMPLEMENTED = json_counter32(ops, "not_implemented");
	  c_ops.counterBlock.app.errors_NOT_FOUND = json_counter32(ops, "not_found");
	  c_ops.counterBlock.app.errors_UNAVAILABLE = json_counter32(ops, "unavailable");
	  c_ops.counterBlock.app.errors_UNAUTHORIZED = json_counter32(ops, "unauthorized");
	  SFLADD_ELEMENT(&csample, &c_ops);
	}
	else {
	  // the synthesized ones
	  SFLADD_ELEMENT(&csample, &application->counters);
	}

	// app_resources
	SFLCounters_sample_element c_res = { 0 };
	cJSON *res = cJSON_GetObjectItem(cs, "app_resources");
	if(res) {
	  c_res.tag = SFLCOUNTERS_APP_RESOURCES;
	  c_res.counterBlock.appResources.user_time = json_gauge32(res, "user_time");
	  c_res.counterBlock.appResources.system_time = json_gauge32(res, "system_time");
	  c_res.counterBlock.appResources.mem_used = json_gauge64(res, "mem_used");
	  c_res.counterBlock.appResources.mem_max = json_gauge64(res, "mem_max");
	  c_res.counterBlock.appResources.fd_open = json_gauge32(res, "fd_open");
	  c_res.counterBlock.appResources.fd_max = json_gauge32(res, "fd_max");
	  c_res.counterBlock.appResources.conn_open = json_gauge32(res, "conn_open");
	  c_res.counterBlock.appResources.conn_max = json_gauge32(res, "conn_max");
	  SFLADD_ELEMENT(&csample, &c_res);
	}

	// app_workers
	SFLCounters_sample_element c_wrk = { 0 };
	cJSON *wrk = cJSON_GetObjectItem(cs, "app_workers");
	if(wrk) {
	  c_wrk.tag = SFLCOUNTERS_APP_WORKERS;
	  c_wrk.counterBlock.appWorkers.workers_active = json_gauge32(wrk, "workers_active");
	  c_wrk.counterBlock.appWorkers.workers_idle = json_gauge32(wrk, "workers_idle");
	  c_wrk.counterBlock.appWorkers.workers_max = json_gauge32(wrk, "workers_max");
	  c_wrk.counterBlock.appWorkers.req_delayed = json_counter32(wrk, "req_delayed");
	  c_wrk.counterBlock.appWorkers.req_dropped = json_counter32(wrk, "req_dropped");
	  SFLADD_ELEMENT(&csample, &c_wrk);
	}

	// always include the "parent" structure too
	SFLCounters_sample_element c_par = { 0 };
        c_par.tag = SFLCOUNTERS_HOST_PAR;
        c_par.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
        c_par.counterBlock.host_par.dsIndex = HSP_DEFAULT_PHYSICAL_DSINDEX;
        SFLADD_ELEMENT(&csample, &c_par);

	// submit the counter sample
	sfl_poller_writeCountersSample(application->poller, &csample);
      }
    }
  }

#ifdef HSF_RTMETRIC

  /*_________________---------------------------__________________
    _________________     XDR encoding          __________________
    -----------------___________________________------------------
  */

  typedef struct {
    int cursor;
    uint32_t xdr[SFL_MAX_DATAGRAM_SIZE >> 2];
  } XDRBuf;


  static void xdr_init(XDRBuf *buf) {
    buf->cursor = 0;
  }

  static uint32_t *xdr_ptr(XDRBuf *buf) {
    return (buf->xdr + buf->cursor);
  }

  static void xdr_enc_int32(XDRBuf *buf, uint32_t val32) {
    buf->xdr[buf->cursor++] = htonl(val32);
  }

  static void xdr_enc_int64(XDRBuf *buf, uint64_t val64) {
    uint32_t hi = (val64 >> 32);
    uint32_t lo = val64;
    xdr_enc_int32(buf, hi);
    xdr_enc_int32(buf, lo);
  }

  static void xdr_enc_float(XDRBuf *buf, float valf) {
    uint32_t val;
    memcpy(&val, &valf, 4);
    xdr_enc_int32(buf, val);
  }

  static void xdr_enc_dbl(XDRBuf *buf, double vald) {
    uint64_t val64;
    memcpy(&val64, &vald, 8);
    xdr_enc_int64(buf, val64);
  }

  static void xdr_enc_bytes(XDRBuf *buf, u_char *data, uint32_t len) {
    uint32_t quads = (len + 3) >> 2;
    u_char *ptr = (u_char *)xdr_ptr(buf);
    memset(ptr, 0, (quads << 2));
    memcpy(ptr, data, len);
    buf->cursor += quads;
  }

  static void xdr_enc_str(XDRBuf *buf, char *str, uint32_t len) {
    xdr_enc_int32(buf, len);
    xdr_enc_bytes(buf, (u_char *)str, len);
  }

  /*_________________---------------------------__________________
    _________________    rtmetric types         __________________
    -----------------___________________________------------------
  */

  static int rtmetric_type(char *str) {
    if(my_strequal(str, "string")) return (int)RTMetricType_string;
    if(my_strequal(str, "counter32")) return (int)RTMetricType_counter32;
    if(my_strequal(str, "counter64")) return (int)RTMetricType_counter64;
    if(my_strequal(str, "gauge32")) return (int)RTMetricType_gauge32;
    if(my_strequal(str, "gauge64")) return (int)RTMetricType_gauge64;
    if(my_strequal(str, "gaugeFloat")) return (int)RTMetricType_gaugeFloat;
    if(my_strequal(str, "gaugeDouble")) return (int)RTMetricType_gaugeDouble;
    return -1;
  }

  static void xdr_enc_metric(XDRBuf *buf, char *mname, uint32_t mname_len, int mtype, cJSON *field, uint32_t field_len)
  {
    xdr_enc_str(buf, mname, mname_len);
    xdr_enc_int32(buf, mtype);

    if(field->type == cJSON_String) {
      // string input
      uint32_t val32;
      uint64_t val64;
      float valf;
      double vald;
      char *instr = field->valuestring;
      // string input
      switch(mtype) {
      case RTMetricType_counter32:
      case RTMetricType_gauge32:
	val32 = strtoul(instr, NULL, 0);
	xdr_enc_int32(buf, val32);
	break;
      case RTMetricType_counter64:
      case RTMetricType_gauge64:
	val64 = strtoull(instr, NULL, 0);
	xdr_enc_int64(buf, val64);
	break;
      case RTMetricType_gaugeFloat:
	valf = strtof(instr, NULL);
	xdr_enc_float(buf, valf);
	break;
      case RTMetricType_gaugeDouble:
	vald = strtod(instr, NULL);
	xdr_enc_dbl(buf, vald);
      break;
      case RTMetricType_string:
	xdr_enc_str(buf, instr, field_len);
      break;
      }
    }
    else if(field->type == cJSON_Number) {
      // numeric input - only certain types expressible
      // because JSON only offers number as type==double
      double indbl = field->valuedouble;
      switch(mtype) {
      case RTMetricType_counter32:
      case RTMetricType_gauge32:
	xdr_enc_int32(buf, (uint32_t)indbl);
	break;
      case RTMetricType_counter64: // this may go wrong (premature counter wrap?)
      case RTMetricType_gauge64:
	xdr_enc_int64(buf, (uint64_t)indbl);
	break;
      case RTMetricType_gaugeFloat:
	xdr_enc_float(buf, (float)indbl);
	break;
      case RTMetricType_gaugeDouble:
	xdr_enc_dbl(buf, indbl);
      break;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________  rtmetric_len_ok          __________________
    -----------------___________________________------------------
   combine the length-test of the key with a test for validity
  */

  static uint32_t rtmetric_len_ok(char *str) {
    uint32_t len = 0;
    int ch;
    while((ch = str[len]) != '\0') {
      if(ch != '-' &&
	 ch != '_' &&
	 !isalnum(ch)) {
	// illegal character
	return 0;
      }
      if(++len > HSP_MAX_RTMETRIC_KEY_LEN) {
	// too long
	return 0;
      }
    }
    return len;
  }

  /*_________________---------------------------__________________
    _________________    dsname_len_ok          __________________
    -----------------___________________________------------------
   The dsname has the additional requirement that it cannot start
   with a digit (to distinguish it from numeric sFlow datasources).
  */

  static uint32_t dsname_len_ok(char *str) {
    if(isdigit(str[0]))
      return 0;
    return rtmetric_len_ok(str);
  }

  /*_________________---------------------------__________________
    _________________  readJSON_rtmetric        __________________
    -----------------___________________________------------------

    {
       "rtmetric": {
         "datasource": "web1",
         "metric1": { "type": "counter32",   "value": 777          },
         "metric2": { "type": "string",      "value": "helloworld" },
         "metric3": { "type": "gaugedouble", "value": 1.234        },
       }
    }
  */

  static void readJSON_rtmetric(HSP *sp, cJSON *rtmetric)
  {
    if(debug > 1) logJSON(rtmetric, "got rtmetric");

    SFLReceiver *receiver = sp->sFlow->agent->receivers;
    if(receiver == NULL)
      return;

    XDRBuf buf;
    xdr_init(&buf);
    uint32_t num_fields = 0;
    char *dsname = NULL;
    uint32_t dsname_len = 0;

    // iterate to pull out datasource name first
    for(cJSON *rtm = rtmetric->child; rtm; rtm = rtm->next) {
      if(!rtm->string) {
	if(debug) logJSON(rtm, "expected named field");
	continue;
      }
      // pick up optional datasource
      if(rtm->type == cJSON_String &&
	 my_strequal(rtm->string, "datasource")) {
	dsname = rtm->valuestring;
	dsname_len = dsname_len_ok(dsname);
	if(dsname_len == 0) {
	  if(debug) myLog(LOG_ERR, "invalid datasource name: %s", dsname);
	  return; // bail completely on bad dsname
	}
	continue;
      }
    }

    xdr_enc_int32(&buf, TAG_RTMETRIC);
    uint32_t *mstart = xdr_ptr(&buf);
    xdr_enc_int32(&buf, 0); // will be rtmetric len
    xdr_enc_str(&buf, dsname, dsname_len);
    uint32_t *fstart = xdr_ptr(&buf);
    xdr_enc_int32(&buf, 0); // will be num fields
    
    for(cJSON *rtm = rtmetric->child; rtm; rtm = rtm->next) {
      // only want named objects now
      if(rtm->string == NULL ||
	 rtm->type != cJSON_Object) {
	continue;
      }
      
      uint32_t mname_len = rtmetric_len_ok(rtm->string);
      if(mname_len == 0) {
	if(debug) {
	  myLog(LOG_ERR, "invalid rtmetric key: <%s>", rtm->string);
	}
	return; // bail on bad key
      }

      cJSON *field = cJSON_GetObjectItem(rtm, "value");
      uint32_t field_len = sizeof(double);

      if(field == NULL) {
	if(debug) myLog(LOG_ERR, "rtmetric missing \"value\"");
	return; // bail on missing value
      }
      if(field->type == cJSON_String) {
	field_len = my_strlen(field->valuestring);
	if(field_len > HSP_MAX_RTMETRIC_VAL_LEN) {
	  if(debug) {
	    myLog(LOG_ERR, "rtmetric field %s len(%u) > max(%u)",
		  rtm->string,
		  field_len,
		  HSP_MAX_RTMETRIC_VAL_LEN);
	  }
	  return; // bail on field len error
	}
      }

      cJSON *field_type = cJSON_GetObjectItem(rtm, "type");
      if(field_type == NULL) {
	if(debug) myLog(LOG_ERR, "rtflow missing \"type\"");
	return; // bail on missing type
      }

      int rtmType = rtmetric_type(field_type->valuestring);
      if(rtmType == -1) {
	if(debug) myLog(LOG_ERR, "rtmetric bad type");
	return; // bail on bad/missing type
      }

      num_fields++;
      xdr_enc_metric(&buf, rtm->string, mname_len, rtmType, field, field_len);
    }

    if(num_fields) {
      uint32_t len = (char *)xdr_ptr(&buf) - (char *)mstart - 4;
      mstart[0] = htonl(len);
      fstart[0] = htonl(num_fields);
      sfl_receiver_writeEncoded(receiver,
				1,
				buf.xdr,
				(buf.cursor << 2));
    }
    // don't flush: allow them to accumulate in the datagram
    // sfl_receiver_flush(receiver);
  }

  /*_________________---------------------------__________________
    _________________      rtflow types         __________________
    -----------------___________________________------------------
  */

  static int rtflow_type(char *str) {
    if(my_strequal(str, "string")) return (int)RTFlowType_string;
    if(my_strequal(str, "mac")) return (int)RTFlowType_mac;
    if(my_strequal(str, "ip")) return (int)RTFlowType_ip;
    if(my_strequal(str, "ip6")) return (int)RTFlowType_ip6;
    if(my_strequal(str, "int32")) return (int)RTFlowType_int32;
    if(my_strequal(str, "int64")) return (int)RTFlowType_int64;
    if(my_strequal(str, "float")) return (int)RTFlowType_float;
    if(my_strequal(str, "double")) return (int)RTFlowType_double;
    return -1;
  }

  static void xdr_enc_flow_field(XDRBuf *buf, char *mname, uint32_t mname_len, int mtype, cJSON *field, uint32_t field_len)
  {
    xdr_enc_str(buf, mname, mname_len);
    xdr_enc_int32(buf, mtype);

    if(field->type == cJSON_String) {
      // string input
      uint32_t val32;
      uint64_t val64;
      float valf;
      double vald;
      u_char mac[6];
      SFLAddress addr;
      char *instr = field->valuestring;
      // string input
      switch(mtype) {
      case RTFlowType_string:
	xdr_enc_str(buf, instr, field_len);
      break;
      case RTFlowType_mac:
	if(hexToBinary((u_char *)instr, mac, 6) == 6) {
	  xdr_enc_bytes(buf, mac, 6);
	}
	else {
	  if(debug) logJSON(field, "failed to parse MAC address");
	}
	break;
      case RTFlowType_ip:
	if(parseNumericAddress(instr, NULL, &addr, AF_INET)) {
	  xdr_enc_bytes(buf, (u_char *)&addr.address.ip_v4.addr, 4);
	}
	else {
	  if(debug) logJSON(field, "failed to parse IP address");
	}
	break;
      case RTFlowType_ip6:
	if(parseNumericAddress(instr, NULL, &addr, AF_INET6)) {
	  xdr_enc_bytes(buf, (u_char *)&addr.address.ip_v6.addr, 16);
	}
	else {
	  if(debug) logJSON(field, "failed to parse IP address");
	}
	break;
      case RTFlowType_int32:
	val32 = strtoul(instr, NULL, 0);
	xdr_enc_int32(buf, val32);
	break;
      case RTFlowType_int64:
	val64 = strtoull(instr, NULL, 0);
	xdr_enc_int64(buf, val64);
	break;
      case RTFlowType_float:
	valf = strtof(instr, NULL);
	xdr_enc_float(buf, valf);
	break;
      case RTFlowType_double:
	vald = strtod(instr, NULL);
	xdr_enc_dbl(buf, vald);
      break;
      }
    }
    else if(field->type == cJSON_Number) {
      // numeric input - only certain types expressible
      double indbl = field->valuedouble;
      switch(mtype) {
      case RTFlowType_int32:
	xdr_enc_int32(buf, (uint32_t)indbl);
	break;
      case RTFlowType_int64:
	xdr_enc_int64(buf, (uint64_t)indbl);
	break;
      case RTFlowType_float:
	xdr_enc_float(buf, (float)indbl);
	break;
      case RTFlowType_double:
	xdr_enc_dbl(buf, indbl);
      break;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________  readJSON_rtflow          __________________
    -----------------___________________________------------------

    rtflow messages can have multiple key/value fields, and an
    optional sampling_rate=<integer> field.
    {
      "rtflow": {
        "datasource": "web1",
        "sampling_rate": 1,
	"field1": { "type": "int32",  "value": 777            },
	"field2": { "type": "string", "value": "helloworld"   },
	"field3": { "type": "mac",    "value": "020304050607" }
      }
    }
  */
  
  static void readJSON_rtflow(HSP *sp, cJSON *rtflow) {
    if(debug > 1) logJSON(rtflow, "got rtflow");
    SFLReceiver *receiver = sp->sFlow->agent->receivers;
    if(receiver == NULL)
      return;
    
    XDRBuf buf;
    xdr_init(&buf);
    uint32_t sampling_rate = 1;
    uint32_t num_fields = 0;
    char *dsname = NULL;
    uint32_t dsname_len = 0;

    // iterate to pull out sampling_rate and datasource name first
    for(cJSON *rtf = rtflow->child; rtf; rtf = rtf->next) {
      if(!rtf->string) {
	if(debug) logJSON(rtf, "expected named field");
	continue;
      }
      // pick up optional sampling_rate setting
      if(rtf->type == cJSON_Number &&
	 my_strequal(rtf->string, "sampling_rate")) {
	sampling_rate = (uint32_t)rtf->valuedouble;
	if(sampling_rate == 0) sampling_rate = 1;
	continue;
      }
      // pick up optional datasource
      if(rtf->type == cJSON_String &&
	 my_strequal(rtf->string, "datasource")) {
	dsname = rtf->valuestring;
	dsname_len = dsname_len_ok(dsname);
	if(dsname_len == 0) {
	  if(debug) myLog(LOG_ERR, "invalid datasource name: %s", dsname);
	  return; // bail completely on bad dsname
	}
	continue;
      }
      // all other fields must be objects
      if(rtf->type != cJSON_Object) {
	if(debug) logJSON(rtf, "expected object field");
	continue;
      }
    }

    xdr_enc_int32(&buf, TAG_RTFLOW);
    uint32_t *mstart = xdr_ptr(&buf);
    xdr_enc_int32(&buf, 0); // will be rtflow len
    xdr_enc_str(&buf, dsname, dsname_len);
    xdr_enc_int32(&buf, sampling_rate); // sampling_rate
    xdr_enc_int32(&buf, 0); // reserved (e.g. for sample_pool)
    uint32_t *fstart = xdr_ptr(&buf);
    xdr_enc_int32(&buf, 0); // will be num fields

    for(cJSON *rtf = rtflow->child; rtf; rtf = rtf->next) {
      // only want named objects now
      if(rtf->string == NULL ||
	 rtf->type != cJSON_Object) {
	continue;
      }
      
      uint32_t fname_len = rtmetric_len_ok(rtf->string);
      if(fname_len == 0) {
	if(debug) {
	  myLog(LOG_ERR, "invalid rtflow key: <%s>", rtf->string);
	}
	return; // bail on bad key
      }

      cJSON *field = cJSON_GetObjectItem(rtf, "value");
      uint32_t field_len = sizeof(double);

      if(field == NULL) {
	if(debug) myLog(LOG_ERR, "rtflow missing \"value\"");
	return; // bail on missing value
      }

      if(field->type == cJSON_String) {
	field_len = my_strlen(field->valuestring);
	if(field_len > HSP_MAX_RTMETRIC_VAL_LEN) {
	  if(debug) {
	    myLog(LOG_ERR, "rtflow field %s len(%u) > max(%u)",
		  rtf->string,
		  field_len,
		  HSP_MAX_RTMETRIC_VAL_LEN);
	  }
	  return; // bail on field len error
	}
      }

      cJSON *field_type = cJSON_GetObjectItem(rtf, "type");
      if(field_type == NULL) {
	if(debug) myLog(LOG_ERR, "rtflow missing \"type\"");
	return; // bail on missing type
      }

      int rtfType = rtflow_type(field_type->valuestring);
      if(rtfType == -1) {
	if(debug) myLog(LOG_ERR, "rtflow field bad type <%s>", field_type->valuestring);
	return; // bail on bad/missing type
      }

      num_fields++;
      xdr_enc_flow_field(&buf, rtf->string, fname_len, rtfType, field, field_len);
    }

    if(num_fields) {
      uint32_t len = (char *)xdr_ptr(&buf) - (char *)mstart - 4;
      mstart[0] = htonl(len);
      fstart[0] = htonl(num_fields);
      sfl_receiver_writeEncoded(receiver,
				1,
				buf.xdr,
				(buf.cursor << 2));
    }
    // don't flush: allow them to accumulate in the datagram
    // sfl_receiver_flush(receiver);
  }

#endif /* HSF_RTMETRIC */
  
  /*_________________---------------------------__________________
    _________________      readJSON             __________________
    -----------------___________________________------------------
  */

  int readJSON(HSP *sp, int soc)
  {
    if(sp->sFlow->sFlowSettings == NULL) {
      // config was turned off
      return 0;
    }
    int batch = 0;
    if(soc) {
      for( ; batch < HSP_READJSON_BATCH; batch++) {
	char buf[HSP_MAX_JSON_MSG_BYTES];
	// use read() so that it works for both UDP and FIFO inputs
	int len = read(soc, buf, HSP_MAX_JSON_MSG_BYTES);
	if(len <= 0) break;
	if(debug > 1) myLog(LOG_INFO, "got JSON msg: %u bytes", len);
	cJSON *top = cJSON_Parse(buf);
	if(top) {
	  if(debug > 1) logJSON(top, "got JSON message");
	  cJSON *fs = cJSON_GetObjectItem(top, "flow_sample");
	  if(fs) readJSON_flowSample(sp, fs);
	  cJSON *cs = cJSON_GetObjectItem(top, "counter_sample");
	  if(cs) readJSON_counterSample(sp, cs);
#ifdef HSF_RTMETRIC
	  cJSON *rtmetric = cJSON_GetObjectItem(top, "rtmetric");
	  if(rtmetric) readJSON_rtmetric(sp, rtmetric);
	  cJSON *rtflow = cJSON_GetObjectItem(top, "rtflow");
	  if(rtflow) readJSON_rtflow(sp, rtflow);
#endif /* HSF_RTMETRIC */
	  cJSON_Delete(top);
	}
      }
    }
    return batch;
  }

#endif /* HSF_JSON */
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

