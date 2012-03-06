/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */


#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"

  extern int debug;

#ifdef HSF_JSON


  /*_________________---------------------------__________________
    _________________    agentCB_getCounters    __________________
    -----------------___________________________------------------
  */
  
  static void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    // we stashed a pointer to the right counters for this datasource in the userData field
    SFLCounters_sample_element *ctrs = (SFLCounters_sample_element *)poller->userData;
    SFLADD_ELEMENT(cs, ctrs);
    sfl_poller_writeCountersSample(poller, cs);
  }

  /*_________________---------------------------__________________
    _________________      addApplication       __________________
    -----------------___________________________------------------
  */
  
  static uint32_t nextApplicationDSIndex = 0;
  
  static HSPApplication *addApplication(HSP *sp, char *application, uint16_t servicePort)
  {
    // assigning dsIndex:
    // 1: need to make it persistent on a restart - perhaps using hsflowd.c:assignVM_dsIndex()
    // 2: $$$ circle back and find a free one if we reach end of range
    uint32_t dsIndex = servicePort ? servicePort : (HSP_DEFAULT_APP_DSINDEX_START + nextApplicationDSIndex++);
    SFLDataSource_instance dsi;
    SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, dsIndex, 0);

    // before we allocate anything, make sure there isn't a clash on servicePort
    if(servicePort && sfl_agent_getPoller(sp->sFlow->agent, &dsi)) {
      if(debug) myLog(LOG_ERR, "addApplication(%s) service port %d already allocated for another application",
		      application,
		      servicePort);
      return NULL;
    }

    // OK,  create the application
    HSPApplication *aa = (HSPApplication *)my_calloc(sizeof(HSPApplication));
    aa->application = my_strdup(application);
    aa->dsIndex = dsIndex;
    aa->servicePort = servicePort;
    // poller
    aa->poller = sfl_agent_addPoller(sp->sFlow->agent, &dsi, aa, agentCB_getCounters);
    sfl_poller_set_sFlowCpInterval(aa->poller, sp->sFlow->sFlowSettings->pollingInterval); // look up polling interval by app name
    sfl_poller_set_sFlowCpReceiver(aa->poller, HSP_SFLOW_RECEIVER_INDEX); 
    // point to the counter block with the userData ptr
    aa->poller->userData = &aa->counters;
    // more counter-block initialization
    aa->counters.tag = SFLCOUNTERS_APP;
    aa->counters.counterBlock.app.application.str = application; // just point
    aa->counters.counterBlock.app.application.len = strlen(application);
    // sampler
    aa->sampler = sfl_agent_addSampler(sp->sFlow->agent, &dsi);
    sfl_sampler_set_sFlowFsPacketSamplingRate(aa->sampler, sp->sFlow->sFlowSettings->samplingRate); // $$$ look up sampling rate by app name
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
    if(servicePort != aa->servicePort) {
      if(debug) myLog(LOG_ERR, "conflicting servicePort for application %s (current=%d, offered=%d)",
		      application,
		      aa->servicePort,
		      servicePort);
      return NULL;
    }
    return aa;
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

  static void sendAppSample(HSP *sp, HSPApplication *app, char *operation, char *attributes, char *status_descr, EnumSFLAPPStatus status, uint64_t req_bytes, uint64_t resp_bytes, uint32_t duration_uS, char *actor_init, char *actor_tgt, SFLExtended_socket_ipv4 *soc4)
  {

    // encode an sFlow transaction sample
    SFL_FLOW_SAMPLE_TYPE fs = { 0 };
    // client/server info in encoded into the input/output field
    // according to this sFlow convention:
    //if(t->client_socket) fs.input = SFL_INTERNAL_INTERFACE;
    // else fs.output = SFL_INTERNAL_INTERFACE;
    
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
      
    SFLFlow_sample_element ssockElem = { 0 };
    if(soc4) {
      ssockElem.tag = SFLFLOW_EX_SOCKET4;
      ssockElem.flowType.socket4 = *soc4;
      SFLADD_ELEMENT(&fs, &ssockElem);
    }

    sfl_sampler_writeFlowSample(app->sampler, &fs);
  }

  /*_________________---------------------------__________________
    _________________      readJSON             __________________
    -----------------___________________________------------------
  */

  int readJSON(HSP *sp)
  {
    int batch = 0;
    if(sp->json_soc) {
      for( ; batch < HSP_READJSON_BATCH; batch++) {
	char buf[HSP_MAX_MSG_BYTES];
	socklen_t peerlen = sizeof(sp->json_peer);
	int len = recvfrom(sp->json_soc,
			   buf,
			   HSP_MAX_MSG_BYTES,
			   0,
			   (struct sockaddr *)&sp->json_peer,
			   &peerlen);
	if(len <= 0) break;
	if(debug > 1) myLog(LOG_INFO, "got JSON msg: %u bytes", len);
	cJSON *top = cJSON_Parse(buf);
	if(top) {
	  if(debug > 1) logJSON(top, "got JSON message");
	  cJSON *fs = cJSON_GetObjectItem(top, "flow_sample");
	  if(fs) {
	    if(debug > 1) logJSON(fs, "got flow sample");
	    cJSON *app = cJSON_GetObjectItem(fs, "app_name");
	    cJSON *service_port = cJSON_GetObjectItem(fs, "service_port");
	    cJSON *smp = cJSON_GetObjectItem(fs, "sampling_rate");
	    uint32_t sampling_rate = smp ? smp->valueint : 1;

	    if(app) {
	      HSPApplication *application = getApplication(sp,
							   app->valuestring,
							   (uint16_t)(service_port ? service_port->valueint : 0));
	      cJSON *opn = cJSON_GetObjectItem(fs, "app_operation");
	      if(opn) {
		cJSON *sts = cJSON_GetObjectItem(opn, "status");

		// update my version of the counters
		EnumSFLAPPStatus status = sts ? (EnumSFLAPPStatus)sts->valueint : SFLAPP_SUCCESS;
		if((u_int)status > (u_int)SFLAPP_UNAUTHORIZED) {
		  status = SFLAPP_OTHER;
		}
		int ii = (uint)status;
		uint32_t *errorCounterArray = &application->counters.counterBlock.app.status_OK;
		errorCounterArray[ii] += sampling_rate;

		// $$$ decide if we are going to sample this transaction, based
		// on the ratio of sampling_rate to the configured sampling rate
		// in the sampler.

		// extract operation fields
		cJSON *operation = cJSON_GetObjectItem(opn, "operation");
		cJSON *attributes = cJSON_GetObjectItem(opn, "attributes");
		cJSON *status_descr = cJSON_GetObjectItem(opn, "status_descr");
		cJSON *req_bytes = cJSON_GetObjectItem(opn, "req_bytes");
		cJSON *resp_bytes = cJSON_GetObjectItem(opn, "resp_bytes");
		cJSON *uS = cJSON_GetObjectItem(opn, "uS");

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
		  cJSON *protocol = cJSON_GetObjectItem(extended_socket_ipv4, "protocol");
		  if(protocol) {
		    soc4.protocol = protocol->valueint;
		  }
		  cJSON *local_ip = cJSON_GetObjectItem(extended_socket_ipv4, "local_ip");
		  if(local_ip) {
		    SFLAddress addr = { 0 };
		    if(lookupAddress(local_ip->valuestring, NULL, &addr, PF_INET)) {
		      soc4.local_ip = addr.address.ip_v4;
		    }
		  }
		  cJSON *remote_ip = cJSON_GetObjectItem(extended_socket_ipv4, "remote_ip");
		  if(remote_ip) {
		    SFLAddress addr = { 0 };
		    if(lookupAddress(remote_ip->valuestring, NULL, &addr, PF_INET)) {
		      soc4.remote_ip = addr.address.ip_v4;
		    }
		  }
		  cJSON *local_port = cJSON_GetObjectItem(extended_socket_ipv4, "local_port");
		  if(local_port) {
		    soc4.local_port = local_port->valueint;
		  }
		  cJSON *remote_port = cJSON_GetObjectItem(extended_socket_ipv4, "remote_port");
		  if(remote_port) {
		    soc4.remote_port = remote_port->valueint;
		  }
		}

		// submit the flow sample
		sendAppSample(sp,
			      application,
			      operation->valuestring,
			      attributes->valuestring,
			      status_descr->valuestring,
			      status,
			      req_bytes->valueint, // valuedouble?
			      resp_bytes->valueint, // valuedouble?
			      uS->valueint,
			      actor_initiator,  // may be NULL
			      actor_target,     // may be NULL
			      &soc4);           // may be NULL
	      }
	    }
	  }
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

