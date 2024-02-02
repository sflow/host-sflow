/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "sflow_api.h"

/*_________________--------------------------__________________
  _________________    sfl_poller_init       __________________
  -----------------__________________________------------------
*/

void sfl_poller_init(SFLPoller *poller,
		     SFLAgent *agent,
		     SFLDataSource_instance *pdsi,
		     void *magic,         /* ptr to pass back in getCountersFn() */
		     getCountersFn_t getCountersFn)
{
  /* copy the dsi in case it points to poller->dsi, which we are about to clear */
  SFLDataSource_instance dsi = *pdsi;

  /* preserve the *nxt pointer too, in case we are resetting this poller and it is
     already part of the agent's linked list (thanks to Matt Woodly for pointing this out) */
  SFLPoller *nxtPtr = poller->nxt;

  /* clear everything */
  memset(poller, 0, sizeof(*poller));
  
  /* restore the linked list ptr */
  poller->nxt = nxtPtr;
  
  /* now copy in the parameters */
  poller->agent = agent;
  poller->dsi = dsi; /* structure copy */
  poller->magic = magic;
  poller->getCountersFn = getCountersFn;
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

static void reset(SFLPoller *poller)
{
  SFLDataSource_instance dsi = poller->dsi;
  sfl_poller_init(poller, poller->agent, &dsi, poller->magic, poller->getCountersFn);
}

/*_________________---------------------------__________________
  _________________      MIB access           __________________
  -----------------___________________________------------------
*/
uint32_t sfl_poller_get_sFlowCpReceiver(SFLPoller *poller) {
  return poller->sFlowCpReceiver;
}

void sfl_poller_set_sFlowCpReceiver(SFLPoller *poller, uint32_t sFlowCpReceiver) {
  poller->sFlowCpReceiver = sFlowCpReceiver;
  if(sFlowCpReceiver == 0) reset(poller);
  else {
    /* retrieve and cache a direct pointer to my receiver */
    poller->myReceiver = sfl_agent_getReceiver(poller->agent, poller->sFlowCpReceiver);
  }
}

uint32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller) {
  return (uint32_t)poller->sFlowCpInterval;
}

void sfl_poller_set_sFlowCpInterval(SFLPoller *poller, uint32_t sFlowCpInterval) {
  poller->sFlowCpInterval = sFlowCpInterval;
  /* Set the countersCountdown to be a randomly selected value between 1 and
     sFlowCpInterval. That way the counter polling would be desynchronised
     (on a 200-port switch, polling all the counters in one second could be harmful). */
  poller->countersCountdown = sFlowCpInterval ? sfl_random(sFlowCpInterval) : 0;
}

void sfl_poller_synchronize_polling(SFLPoller *poller, SFLPoller *master) {
  /* This can be used if there is a reason to make pollers report at about the same
     time,  such as if they are in a LAG relationship */
  if(master->countersCountdown) {
    poller->countersCountdown = master->countersCountdown;
  }
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
Used to indicate a counter discontinuity
so that the sflow collector will know to ignore the next delta.
*/
void sfl_poller_resetCountersSeqNo(SFLPoller *poller) {  poller->countersSampleSeqNo = 0; }

/*_________________---------------------------------__________________
  _________________   datasource alias              __________________
  -----------------_________________________________------------------
Used where we want to export a remapped namespace for datasource index
*/
void sfl_poller_set_dsAlias(SFLPoller *poller, uint32_t ds_alias) { poller->ds_alias = ds_alias; }

/*_________________---------------------------__________________
  _________________    sfl_poller_tick        __________________
  -----------------___________________________------------------
*/

void sfl_poller_tick(SFLPoller *poller, time_t now)
{
  if(poller->countersCountdown == 0) return; /* counters retrieval was not enabled */
  if(poller->sFlowCpReceiver == 0) return;

  if(--poller->countersCountdown == 0) {
    if(poller->getCountersFn != NULL) {
      /* call out for counters */
      SFL_COUNTERS_SAMPLE_TYPE cs;
      memset(&cs, 0, sizeof(cs));
      poller->getCountersFn(poller->magic, poller, &cs);
      // this countersFn is expected to fill in some counter block elements
      // and then call sfl_poller_writeCountersSample(poller, &cs);
    }
    /* reset the countdown */
    poller->countersCountdown = poller->sFlowCpInterval;
  }
}

/*_________________---------------------------------__________________
  _________________ sfl_poller_writeCountersSample  __________________
  -----------------_________________________________------------------
*/

void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
  /* fill in the rest of the header fields, and send to the receiver */
  cs->sequence_number = ++poller->countersSampleSeqNo;
  uint32_t ds_class = SFL_DS_CLASS(poller->dsi);
  uint32_t ds_index = poller->ds_alias ? poller->ds_alias : SFL_DS_INDEX(poller->dsi);
#ifdef SFL_USE_32BIT_INDEX
  cs->ds_class = ds_class;
  cs->ds_index = ds_index;
#else
  cs->source_id = SFL_DS_SOURCEID(ds_class, ds_index);
#endif
  /* sent to my receiver */
  if(poller->myReceiver) sfl_receiver_writeCountersSample(poller->myReceiver, cs);
}


#if defined(__cplusplus)
} /* extern "C" */
#endif
