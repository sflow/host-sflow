/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "sflow_api.h"


/*_________________--------------------------__________________
  _________________   sfl_sampler_init       __________________
  -----------------__________________________------------------
*/

void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi)
{
  /* copy the dsi in case it points to sampler->dsi, which we are about to clear.
     (Thanks to Jagjit Choudray of Force 10 Networks for pointing out this bug) */
  SFLDataSource_instance dsi = *pdsi;

  /* preserve the *nxt pointer too, in case we are resetting this poller and it is
     already part of the agent's linked list (thanks to Matt Woodly for pointing this out) */
  SFLSampler *nxtPtr = sampler->nxt;
  
  /* clear everything */
  memset(sampler, 0, sizeof(*sampler));
  
  /* restore the linked list ptr */
  sampler->nxt = nxtPtr;
  
  /* now copy in the parameters */
  sampler->agent = agent;
  sampler->dsi = dsi;
  
  /* set defaults */
  sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, SFL_DEFAULT_HEADER_SIZE);
  sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, SFL_DEFAULT_SAMPLING_RATE);
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

static void reset(SFLSampler *sampler)
{
  SFLDataSource_instance dsi = sampler->dsi;
  sfl_sampler_init(sampler, sampler->agent, &dsi);
}

/*_________________---------------------------__________________
  _________________      MIB access           __________________
  -----------------___________________________------------------
*/
uint32_t sfl_sampler_get_sFlowFsReceiver(SFLSampler *sampler) {
  return sampler->sFlowFsReceiver;
}

void sfl_sampler_set_sFlowFsReceiver(SFLSampler *sampler, uint32_t sFlowFsReceiver) {
  sampler->sFlowFsReceiver = sFlowFsReceiver;
  if(sFlowFsReceiver == 0) reset(sampler);
  else {
    /* retrieve and cache a direct pointer to my receiver */
    sampler->myReceiver = sfl_agent_getReceiver(sampler->agent, sampler->sFlowFsReceiver);
  }
}

uint32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler) {
  return sampler->sFlowFsPacketSamplingRate;
}

void sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, uint32_t sFlowFsPacketSamplingRate) {
  sampler->sFlowFsPacketSamplingRate = sFlowFsPacketSamplingRate;
  // initialize the skip count too
  sampler->skip = sfl_random(sFlowFsPacketSamplingRate);
}

uint32_t sfl_sampler_get_sFlowFsMaximumHeaderSize(SFLSampler *sampler) {
  return sampler->sFlowFsMaximumHeaderSize;
}

void sfl_sampler_set_sFlowFsMaximumHeaderSize(SFLSampler *sampler, uint32_t sFlowFsMaximumHeaderSize) {
  sampler->sFlowFsMaximumHeaderSize = sFlowFsMaximumHeaderSize;
}

/* call this to set a maximum samples-per-second threshold. If the sampler reaches this
   threshold it will automatically back off the sampling rate. A value of 0 disables the
   mechanism */

void sfl_sampler_set_backoffThreshold(SFLSampler *sampler, uint32_t samplesPerSecond) {
  sampler->backoffThreshold = samplesPerSecond;
}

uint32_t sfl_sampler_get_backoffThreshold(SFLSampler *sampler) {
  return sampler->backoffThreshold;
}

uint32_t sfl_sampler_get_samplesLastTick(SFLSampler *sampler) {
  return sampler->samplesLastTick;
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
Used by the agent to indicate a samplePool discontinuity
so that the sflow collector will know to ignore the next delta.
*/
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler) { sampler->flowSampleSeqNo = 0; }

/*_________________---------------------------------__________________
  _________________   datasource alias              __________________
  -----------------_________________________________------------------
Used where we want to export a remapped namespace for datasource index
*/
void sfl_sampler_set_dsAlias(SFLSampler *sampler, uint32_t ds_alias) { sampler->ds_alias = ds_alias; }

/*_________________---------------------------__________________
  _________________    sfl_sampler_tick       __________________
  -----------------___________________________------------------
*/

void sfl_sampler_tick(SFLSampler *sampler, time_t now)
{
  if(sampler->backoffThreshold && sampler->samplesThisTick > sampler->backoffThreshold) {
    // automatic backoff.  If using hardware sampling then this is where you have to
    // call out to change the sampling rate and make sure that any other registers/variables
    // that hold this value are updated.
    sampler->sFlowFsPacketSamplingRate *= 2;
  }
  sampler->samplesLastTick = sampler->samplesThisTick;
  sampler->samplesThisTick = 0;
}



/*_________________------------------------------__________________
  _________________ sfl_sampler_writeFlowSample  __________________
  -----------------______________________________------------------
*/

void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs)
{
  if(fs == NULL) return;
  sampler->samplesThisTick++;
  /* increment the sequence number */
  fs->sequence_number = ++sampler->flowSampleSeqNo;
  /* copy the other header fields in */
  uint32_t ds_class = SFL_DS_CLASS(sampler->dsi);
  uint32_t ds_index = sampler->ds_alias ? sampler->ds_alias : SFL_DS_INDEX(sampler->dsi);
#ifdef SFL_USE_32BIT_INDEX
  fs->ds_class = ds_class;
  fs->ds_index = ds_index;
#else
  fs->source_id = SFL_DS_SOURCEID(ds_class, ds_index);
#endif
  /* the sampling rate may have been set already. */
  if(fs->sampling_rate == 0) fs->sampling_rate = sampler->sFlowFsPacketSamplingRate;
  /* the samplePool may be maintained upstream too. */
  if( fs->sample_pool == 0) fs->sample_pool = sampler->samplePool;
  /* sent to my receiver */
  if(sampler->myReceiver) sfl_receiver_writeFlowSample(sampler->myReceiver, fs);
}

/*_________________---------------------------__________________
  _________________     sfl_random            __________________
  -----------------___________________________------------------
  Gerhard's generator
*/

static uint32_t SFLRandom = 1;

uint32_t sfl_random(uint32_t lim) {
  SFLRandom = ((SFLRandom * 32719) + 3) % 32749;
  return ((SFLRandom % lim) + 1);
} 

void sfl_random_init(uint32_t seed) {
  SFLRandom = seed;
} 

/*_________________---------------------------__________________
  _________________  sfl_sampler_takeSample   __________________
  -----------------___________________________------------------
*/

int sfl_sampler_takeSample(SFLSampler *sampler)
{
  // increment the samplePool
  sampler->samplePool++;

  if(--sampler->skip == 0) {
    /* reached zero. Set the next skip and return true. */
    sampler->skip = sfl_random((2 * sampler->sFlowFsPacketSamplingRate) - 1);
    return 1;
  }
  return 0;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
