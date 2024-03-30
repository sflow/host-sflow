/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "sflow_api.h"

static void * sflAlloc(SFLAgent *agent, size_t bytes);
static void sflFree(SFLAgent *agent, void *obj);
static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler);
static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler);

/*________________--------------------------__________________
  ________________  SFDG datagram callbacks __________________
  ----------------__________________________------------------
*/

static void *sfdgCB_alloc(void *magic, size_t bytes)  {
  SFLReceiver *receiver = (SFLReceiver *)magic;
  return sflAlloc(receiver->agent, bytes);
}

static void sfdgCB_free(void *magic, void *obj)  {
  SFLReceiver *receiver = (SFLReceiver *)magic;
  sflFree(receiver->agent, obj);
}

static void sfdgCB_error(void *magic, char *msg)  {
  SFLReceiver *receiver = (SFLReceiver *)magic;
  sfl_agent_error(receiver->agent, "SFDG", msg);
}

static uint64_t sfdgCB_now_mS(void *magic)  {
  SFLReceiver *receiver = (SFLReceiver *)magic;
  return sfl_agent_uptime_mS(receiver->agent);
}

static void sfdgCB_send(void *magic, struct iovec *iov, int iovcnt)  {
  /* If we get here it's because we were not given a vector-io send function,
     so this is where we match the old API by combining the buffers. */
  SFLReceiver *receiver = (SFLReceiver *)magic;
  SFLAgent *agent = receiver->agent;
  u_char pkt[SFL_MAX_DATAGRAM_SIZE];
  uint32_t len = 0;
  for(uint32_t ii = 0; ii < iovcnt; ii++) {
    size_t seglen = iov[ii].iov_len;
    if ((len + seglen) > SFL_MAX_DATAGRAM_SIZE) {
      sfl_agent_error(agent, "SFDG", "backwards compatibility send error");
      return;
    }
    memcpy(pkt + len, iov[ii].iov_base, seglen);
    len += seglen;
  }
  agent->sendFn(agent->magic, agent, agent->receivers, pkt, len);
}
  
/*________________--------------------------__________________
  ________________    sfl_agent_init        __________________
  ----------------__________________________------------------
*/

void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent in net byte order */
		    uint32_t subId,  /* agent_sub_id */
		    time_t bootTime,  /* agent boot time */
		    time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn)
{
  /* first clear everything */
  memset(agent, 0, sizeof(*agent));
  /* now copy in the parameters */
  agent->myIP = *myIP; /* structure copy */
  agent->subId = subId;
  agent->bootTime = bootTime;
  agent->now = now;
  agent->magic = magic;
  agent->allocFn = allocFn;
  agent->freeFn = freeFn;
  agent->errorFn = errorFn;
  agent->sendFn = sendFn;
  /* by default the callbacks from the SFDG datagram-builder come back through the agent */
  agent->sfdg.allocFn = sfdgCB_alloc;
  agent->sfdg.freeFn = sfdgCB_free;
  agent->sfdg.errFn = sfdgCB_error;
  agent->sfdg.sendFn = sfdgCB_send;
  agent->sfdg.nowFn = sfdgCB_now_mS;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_init_sfdg_*   __________________
  -----------------___________________________------------------
Some datagram-builder callbacks can be overridden at init time for performance.
*/

static void reset_receiver_sfdgs(SFLAgent *agent) {
  for(SFLReceiver *rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
    sfl_receiver_init_sfdg(rcv);
}
    
void sfl_agent_init_sfdg_sendFn(SFLAgent *agent, f_send_t sendFn) {
  agent->sfdg.sendFn = sendFn;
  reset_receiver_sfdgs(agent);
}

void sfl_agent_init_sfdg_nowFn(SFLAgent *agent, f_now_mS_t nowFn) {
  agent->sfdg.nowFn = nowFn;
  reset_receiver_sfdgs(agent);
} 

void sfl_agent_init_sfdg_hookFn(SFLAgent *agent, f_hook_t hookFn) {
  agent->sfdg.hookFn = hookFn;
  reset_receiver_sfdgs(agent);
} 

/*_________________---------------------------__________________
  _________________   sfl_agent_release       __________________
  -----------------___________________________------------------
*/

void sfl_agent_release(SFLAgent *agent)
{
 
  SFLSampler *sm;
  SFLPoller *pl;
  SFLNotifier *nf;
  SFLReceiver *rcv;
   /* release and free the samplers */
  for(sm = agent->samplers; sm != NULL; ) {
    SFLSampler *nextSm = sm->nxt;
    sflFree(agent, sm);
    sm = nextSm;
  }
  agent->samplers = NULL;

  /* release and free the pollers */
  for( pl= agent->pollers; pl != NULL; ) {
    SFLPoller *nextPl = pl->nxt;
    sflFree(agent, pl);
    pl = nextPl;
  }
  agent->pollers = NULL;

  /* release and free the notifiers */
  for( nf = agent->notifiers; nf != NULL; ) {
    SFLNotifier *nextNf = nf->nxt;
    sflFree(agent, nf);
    nf = nextNf;
  }
  agent->notifiers = NULL;

  /* release and free the receivers */
  for( rcv = agent->receivers; rcv != NULL; ) {
    SFLReceiver *nextRcv = rcv->nxt;
    sflFree(agent, rcv);
    rcv = nextRcv;
  }
  agent->receivers = NULL;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_tick          __________________
  -----------------___________________________------------------
*/

void sfl_agent_tick(SFLAgent *agent, time_t now)
{
  SFLReceiver *rcv;
  SFLSampler *sm;
  SFLPoller *pl;
  SFLNotifier *nf;

  agent->now = now;
  /* pollers use ticks to decide when to ask for counters */
  for( pl = agent->pollers; pl != NULL; pl = pl->nxt) sfl_poller_tick(pl, now);
  /* receivers use ticks to flush send data */
  for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt) sfl_receiver_tick(rcv, now);
  /* samplers use ticks to decide when they are sampling too fast */
  for( sm = agent->samplers; sm != NULL; sm = sm->nxt) sfl_sampler_tick(sm, now);
  /* notifiers use ticks to set leaky-bucket quota */
  for( nf = agent->notifiers; nf != NULL; nf = nf->nxt) sfl_notifier_tick(nf, now);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_set_now       __________________
  -----------------___________________________------------------
Used to set a higher-precision "now" timestamp.
*/

void sfl_agent_set_now(SFLAgent *agent, time_t now, time_t now_nS)
{
  agent->now = now;
  agent->now_nS = now_nS;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_get_address    __________________
  -----------------___________________________------------------
*/

SFLAddress *sfl_agent_get_address(SFLAgent *agent)
{
  return &agent->myIP;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_set_address    __________________
  -----------------___________________________------------------
*/

void sfl_agent_set_address(SFLAgent *agent, SFLAddress *ip)
{
  SFLReceiver *rcv;

  for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
    sfl_receiver_flush(rcv);

  agent->myIP = (*ip);
  
  for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
    sfl_receiver_init_sfdg(rcv);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_uptime_mS     __________________
  -----------------___________________________------------------
*/

uint32_t sfl_agent_uptime_mS(SFLAgent *agent)
{
  return ((agent->now - agent->bootTime) * 1000) + (agent->now_nS / 1000000);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addReceiver   __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent)
{
  SFLReceiver *rcv, *r, *prev;

  prev = NULL;
  rcv = (SFLReceiver *)sflAlloc(agent, sizeof(SFLReceiver));
  sfl_receiver_init(rcv, agent);
  sfl_receiver_init_sfdg(rcv);

  // add to end of list - to preserve the receiver index numbers for existing receivers
 
  for(r = agent->receivers; r != NULL; prev = r, r = r->nxt);
  if(prev) prev->nxt = rcv;
  else agent->receivers = rcv;
  rcv->nxt = NULL;
  return rcv;
}

/*_________________---------------------------__________________
  _________________     sfl_dsi_compare       __________________
  -----------------___________________________------------------

  Note that if there is a mixture of ds_classes for this agent, then
  the simple numeric comparison may not be correct - the sort order (for
  the purposes of the SNMP MIB) should really be determined by the OID
  that these numeric ds_class numbers are a shorthand for.  For example,
  ds_class == 0 means ifIndex, which is the oid "1.3.6.1.2.1.2.2.1"
*/

static int sfl_dsi_compare(SFLDataSource_instance *pdsi1, SFLDataSource_instance *pdsi2) {
  // could have used just memcmp(),  but not sure if that would
  // give the right answer on little-endian platforms. Safer to be explicit...
  int cmp = pdsi2->ds_class - pdsi1->ds_class;
  if(cmp == 0) cmp = pdsi2->ds_index - pdsi1->ds_index;
  if(cmp == 0) cmp = pdsi2->ds_instance - pdsi1->ds_instance;
  return cmp;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addSampler    __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLSampler *newsm, *prev, *sm, *test;

  prev = NULL;
  sm = agent->samplers;
  // keep the list sorted
  for(; sm != NULL; prev = sm, sm = sm->nxt) {
    int64_t cmp = sfl_dsi_compare(pdsi, &sm->dsi);
    if(cmp == 0) return sm;  // found - return existing one
    if(cmp < 0) break;       // insert here
  }
  // either we found the insert point, or reached the end of the list...
  newsm = (SFLSampler *)sflAlloc(agent, sizeof(SFLSampler));
  sfl_sampler_init(newsm, agent, pdsi);
  if(prev) prev->nxt = newsm;
  else agent->samplers = newsm;
  newsm->nxt = sm;

  // see if we should go in the ifIndex jumpTable
  if(SFL_DS_CLASS(newsm->dsi) == 0) {
    test = sfl_agent_getSamplerByIfIndex(agent, SFL_DS_INDEX(newsm->dsi));
    if(test && (SFL_DS_INSTANCE(newsm->dsi) < SFL_DS_INSTANCE(test->dsi))) {
      // replace with this new one because it has a lower ds_instance number
      sfl_agent_jumpTableRemove(agent, test);
      test = NULL;
    }
    if(test == NULL) sfl_agent_jumpTableAdd(agent, newsm);
  }
  return newsm;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addPoller     __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic,         /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn)
{
  SFLPoller *newpl;

  // keep the list sorted
  SFLPoller *prev = NULL, *pl = agent->pollers;
  for(; pl != NULL; prev = pl, pl = pl->nxt) {
    int64_t cmp = sfl_dsi_compare(pdsi, &pl->dsi);
    if(cmp == 0) return pl;  // found - return existing one
    if(cmp < 0) break;       // insert here
  }
  // either we found the insert point, or reached the end of the list...
  newpl = (SFLPoller *)sflAlloc(agent, sizeof(SFLPoller));
  sfl_poller_init(newpl, agent, pdsi, magic, getCountersFn);
  if(prev) prev->nxt = newpl;
  else agent->pollers = newpl;
  newpl->nxt = pl;
  return newpl;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addNotifier   __________________
  -----------------___________________________------------------
*/

SFLNotifier *sfl_agent_addNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLNotifier *newnf;

  // keep the list sorted
  SFLNotifier *prev = NULL, *nf = agent->notifiers;
  for(; nf != NULL; prev = nf, nf = nf->nxt) {
    int64_t cmp = sfl_dsi_compare(pdsi, &nf->dsi);
    if(cmp == 0) return nf;  // found - return existing one
    if(cmp < 0) break;       // insert here
  }
  // either we found the insert point, or reached the end of the list...
  newnf = (SFLNotifier *)sflAlloc(agent, sizeof(SFLNotifier));
  sfl_notifier_init(newnf, agent, pdsi);
  if(prev) prev->nxt = newnf;
  else agent->notifiers = newnf;
  newnf->nxt = nf;
  return newnf;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removeSampler  __________________
  -----------------___________________________------------------
*/

int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLSampler *prev, *sm;

  /* find it, unlink it and free it */
  for(prev = NULL, sm = agent->samplers; sm != NULL; prev = sm, sm = sm->nxt) {
    if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) {
      if(prev == NULL) agent->samplers = sm->nxt;
      else prev->nxt = sm->nxt;
      sfl_agent_jumpTableRemove(agent, sm);
      sflFree(agent, sm);
      return 1;
    }
  }
  /* not found */
  return 0;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removePoller   __________________
  -----------------___________________________------------------
*/

int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLPoller *prev, *pl;
  /* find it, unlink it and free it */
  for(prev = NULL, pl = agent->pollers; pl != NULL; prev = pl, pl = pl->nxt) {
    if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) {
      if(prev == NULL) agent->pollers = pl->nxt;
      else prev->nxt = pl->nxt;
      sflFree(agent, pl);
      return 1;
    }
  }
  /* not found */
  return 0;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removeNotifier __________________
  -----------------___________________________------------------
*/

int sfl_agent_removeNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLNotifier *prev, *nf;
  /* find it, unlink it and free it */
  for(prev = NULL, nf = agent->notifiers; nf != NULL; prev = nf, nf = nf->nxt) {
    if(sfl_dsi_compare(pdsi, &nf->dsi) == 0) {
      if(prev == NULL) agent->notifiers = nf->nxt;
      else prev->nxt = nf->nxt;
      sflFree(agent, nf);
      return 1;
    }
  }
  /* not found */
  return 0;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableAdd        __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler)
{
  uint32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
  sampler->hash_nxt = agent->jumpTable[hashIndex];
  agent->jumpTable[hashIndex] = sampler;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableRemove     __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler)
{
  uint32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
  SFLSampler *search = agent->jumpTable[hashIndex], *prev = NULL;
  for( ; search != NULL; prev = search, search = search->hash_nxt) if(search == sampler) break;
  if(search) {
    // found - unlink
    if(prev) prev->hash_nxt = search->hash_nxt;
    else agent->jumpTable[hashIndex] = search->hash_nxt;
    search->hash_nxt = NULL;
  }
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_getSamplerByIfIndex __________________
  -----------------________________________________------------------
  fast lookup (pointers cached in hash table).  If there are multiple
  sampler instances for a given ifIndex, then this fn will return
  the one with the lowest instance number.  Since the samplers
  list is sorted, this means the other instances will be accesible
  by following the sampler->nxt pointer (until the ds_class
  or ds_index changes).  This is helpful if you need to offer
  the same flowSample to multiple samplers.
*/

SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, uint32_t ifIndex)
{
  SFLSampler *search = agent->jumpTable[ifIndex % SFL_HASHTABLE_SIZ];
  for( ; search != NULL; search = search->hash_nxt) if(SFL_DS_INDEX(search->dsi) == ifIndex) break;
  return search;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getSampler     __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLSampler *sm;

  /* find it and return it */
  for( sm = agent->samplers; sm != NULL; sm = sm->nxt)
    if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) return sm;
  /* not found */
  return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getPoller      __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLPoller *pl;

  /* find it and return it */
  for( pl = agent->pollers; pl != NULL; pl = pl->nxt)
    if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) return pl;
  /* not found */
  return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getNotifier    __________________
  -----------------___________________________------------------
*/

SFLNotifier *sfl_agent_getNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  SFLNotifier *nf;

  /* find it and return it */
  for( nf = agent->notifiers; nf != NULL; nf = nf->nxt)
    if(sfl_dsi_compare(pdsi, &nf->dsi) == 0) return nf;
  /* not found */
  return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getReceiver    __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, uint32_t receiverIndex)
{
  SFLReceiver *rcv;

  uint32_t rcvIdx = 0;
  for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
    if(receiverIndex == ++rcvIdx) return rcv;

  /* not found - ran off the end of the table */
  return NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextSampler  __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* return the one lexograpically just after it - assume they are sorted
     correctly according to the lexographical ordering of the object ids */
  SFLSampler *sm = sfl_agent_getSampler(agent, pdsi);
  return sm ? sm->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextPoller   __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* return the one lexograpically just after it - assume they are sorted
     correctly according to the lexographical ordering of the object ids */
  SFLPoller *pl = sfl_agent_getPoller(agent, pdsi);
  return pl ? pl->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextNotifier __________________
  -----------------___________________________------------------
*/

SFLNotifier *sfl_agent_getNextNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* return the one lexograpically just after it - assume they are sorted
     correctly according to the lexographical ordering of the object ids */
  SFLNotifier *nf = sfl_agent_getNotifier(agent, pdsi);
  return nf ? nf->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextReceiver __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, uint32_t receiverIndex)
{
  return sfl_agent_getReceiver(agent, receiverIndex + 1);
}


/*_________________---------------------------__________________
  _________________ sfl_agent_resetReceiver   __________________
  -----------------___________________________------------------
*/

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver)
{
  SFLReceiver *rcv;
  SFLSampler *sm;
  SFLPoller *pl;
  SFLNotifier *nf;
  
  /* tell samplers, pollers and notifiers to stop sending to this receiver */
  /* first get his receiverIndex */
  uint32_t rcvIdx = 0;
  for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt) {
    rcvIdx++; // thanks to Diego Valverde for pointing out this bugfix
    if(rcv == receiver) {
      /* now tell anyone that is using it to stop */
      for( sm = agent->samplers; sm != NULL; sm = sm->nxt)
	if(sfl_sampler_get_sFlowFsReceiver(sm) == rcvIdx)
	  sfl_sampler_set_sFlowFsReceiver(sm, 0);
      
      for( pl = agent->pollers; pl != NULL; pl = pl->nxt)
	if(sfl_poller_get_sFlowCpReceiver(pl) == rcvIdx)
	  sfl_poller_set_sFlowCpReceiver(pl, 0);

      for( nf = agent->notifiers; nf != NULL; nf = nf->nxt)
	if(sfl_notifier_get_sFlowEsReceiver(nf) == rcvIdx)
	  sfl_notifier_set_sFlowEsReceiver(nf, 0);

      break;
    }
  }
}
  
/*_________________---------------------------__________________
  _________________     sfl_agent_error       __________________
  -----------------___________________________------------------
*/
#define MAX_ERRMSG_LEN 1000

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg)
{
  char errm[MAX_ERRMSG_LEN];
  sprintf(errm, "sfl_agent_error: %s: %s\n", modName, msg);
  if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
  else {
    fprintf(stderr, "%s\n", errm);
    fflush(stderr);
  }
}

/*_________________---------------------------__________________
  _________________     sfl_agent_sysError    __________________
  -----------------___________________________------------------
*/

void sfl_agent_sysError(SFLAgent *agent, char *modName, char *msg)
{
  char errm[MAX_ERRMSG_LEN];
  sprintf(errm, "sfl_agent_sysError: %s: %s (errno = %d - %s)\n", modName, msg, errno, strerror(errno));
  if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
  else {
    fprintf(stderr, "%s\n", errm);
    fflush(stderr);
  }
}


/*_________________---------------------------__________________
  _________________       alloc and free      __________________
  -----------------___________________________------------------
*/

static void * sflAlloc(SFLAgent *agent, size_t bytes)
{
  if(agent->allocFn) return (*agent->allocFn)(agent->magic, agent, bytes);
  else return SFL_ALLOC(bytes);
}

static void sflFree(SFLAgent *agent, void *obj)
{
  if(agent->freeFn) (*agent->freeFn)(agent->magic, agent, obj);
  else SFL_FREE(obj);
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
