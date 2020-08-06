/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "sflow_api.h"


/*_________________--------------------------__________________
  _________________   sfl_notifier_init      __________________
  -----------------__________________________------------------
*/

void sfl_notifier_init(SFLNotifier *notifier, SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* copy the dsi in case it points to notifier->dsi, which we are about to clear. */
  SFLDataSource_instance dsi = *pdsi;

  /* clear everything, but preserve *nxt pointer */
  SFLNotifier *nxtPtr = notifier->nxt;
  memset(notifier, 0, sizeof(*notifier));
  notifier->nxt = nxtPtr;
  
  /* now copy in the parameters */
  notifier->agent = agent;
  notifier->dsi = dsi;
  
  /* set defaults */
  notifier->sFlowEsMaximumHeaderSize = SFL_DEFAULT_HEADER_SIZE;
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

static void reset(SFLNotifier *notifier)
{
  SFLDataSource_instance dsi = notifier->dsi;
  sfl_notifier_init(notifier, notifier->agent, &dsi);
}

/*_________________---------------------------__________________
  _________________    parameter access       __________________
  -----------------___________________________------------------
*/

  uint32_t sfl_notifier_get_sFlowEsReceiver(SFLNotifier *notifier) {
  return notifier->sFlowEsReceiver;
}

void sfl_notifier_set_sFlowEsReceiver(SFLNotifier *notifier, uint32_t sFlowEsReceiver) {
  notifier->sFlowEsReceiver = sFlowEsReceiver;
  if(sFlowEsReceiver == 0) reset(notifier);
  else {
    /* retrieve and cache a direct pointer to my receiver */
    notifier->myReceiver = sfl_agent_getReceiver(notifier->agent, notifier->sFlowEsReceiver);
  }
}

uint32_t sfl_notifier_get_sFlowEsMaximumHeaderSize(SFLNotifier *notifier) {
  return notifier->sFlowEsMaximumHeaderSize;
}

void sfl_notifier_set_sFlowEsMaximumHeaderSize(SFLNotifier *notifier, uint32_t sFlowEsMaximumHeaderSize) {
  // TODO: apply this
  notifier->sFlowEsMaximumHeaderSize = sFlowEsMaximumHeaderSize;
}

uint32_t sfl_notifier_get_nLastTick(SFLNotifier *notifier) {
  return notifier->nLastTick;
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
Used by the agent to indicate a samplePool discontinuity
so that the sflow collector will know to ignore the next delta.
*/
void sfl_notifier_resetSeqNo(SFLNotifier *notifier) { notifier->seqNo = 0; }

/*_________________---------------------------------__________________
  _________________   datasource alias              __________________
  -----------------_________________________________------------------
Used where we want to export a remapped namespace for datasource index
*/
void sfl_notifier_set_dsAlias(SFLNotifier *notifier, uint32_t ds_alias) { notifier->ds_alias = ds_alias; }

/*_________________---------------------------__________________
  _________________    sfl_notifier_tick       __________________
  -----------------___________________________------------------
*/

void sfl_notifier_tick(SFLNotifier *notifier, time_t now)
{
  notifier->nLastTick = notifier->nThisTick;
  notifier->nThisTick = 0;
}

/*_________________-------------------------------__________________
  _________________ sfl_notifier_writeEventSample __________________
  -----------------_______________________________------------------
*/

void sfl_notifier_writeEventSample(SFLNotifier *notifier, SFLEvent_discarded_packet *es)
{
  if(es == NULL) return;
  notifier->nThisTick++;
  /* increment the sequence number */
  es->sequence_number = ++notifier->seqNo;
  /* copy the other header fields in - event samples always use expanded form */
  es->ds_class = SFL_DS_CLASS(notifier->dsi);
  es->ds_index = notifier->ds_alias ?: SFL_DS_INDEX(notifier->dsi);
  /* send to my receiver */
  if(notifier->myReceiver)
    sfl_receiver_writeEventSample(notifier->myReceiver, es);
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
