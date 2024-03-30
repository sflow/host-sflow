/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

/////////////////////////////////////////////////////////////////////////////////
/////////////////////// sFlow Sampling Agent API ////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

#ifndef SFLOW_API_H
#define SFLOW_API_H 1

#if defined(__cplusplus)
extern "C" {
#endif

/* define SFLOW_DO_SOCKET to 1 if you want the agent
   to send the packets itself, otherwise set the sendFn
   callback in sfl_agent_init.*/
/* #define SFLOW_DO_SOCKET */

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#endif //_WIN32
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "sflow.h"
#include "sflow_xdr.h"
  
/*
  uncomment this preprocessor flag  (or compile with -DSFL_USE_32BIT_INDEX)
  if your ds_index numbers can ever be >= 2^30-1 (i.e. >= 0x3FFFFFFF)
*/
/* #define SFL_USE_32BIT_INDEX */


/* Used to combine ds_class, ds_index and instance into
   a single 64-bit number like this:
    __________________________________
   | cls|  index     |   instance     |
    ----------------------------------
 
   but now is opened up to a 12-byte struct to ensure
   that ds_index has a full 32-bit field, and to make
   accessing the components simpler. The macros have
   the same behavior as before, so this change should
   be transparent.  The only difference is that these
   objects are now passed around by reference instead
   of by value, and the comparison is done using a fn.
*/

typedef struct _SFLDataSource_instance {
  uint32_t ds_class;
  uint32_t ds_index;
  uint32_t ds_instance;
} SFLDataSource_instance;

#ifdef SFL_USE_32BIT_INDEX
#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample_expanded
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample_expanded
#else
#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample
  /* if index numbers are not going to use all 32 bits, then we can use
     the more compact encoding, with the dataSource class and index merged */
#define SFL_DS_SOURCEID(cls,idx) ((cls) << 24) + (idx)
#endif

#define SFL_DS_INSTANCE(dsi) (dsi).ds_instance
#define SFL_DS_CLASS(dsi) (dsi).ds_class
#define SFL_DS_INDEX(dsi) (dsi).ds_index
#define SFL_DS_SET(dsi,clss,indx,inst) \
 do {                        \
 (dsi).ds_class = (clss);    \
 (dsi).ds_index = (indx);    \
 (dsi).ds_instance = (inst); \
 } while(0)

struct _SFLAgent;  /* forward decl */

typedef struct _SFLReceiver {
  struct _SFLReceiver *nxt;
  /* MIB fields */
  char *sFlowRcvrOwner;
  time_t sFlowRcvrTimeout;
  uint32_t sFlowRcvrMaximumDatagramSize;
  SFLAddress sFlowRcvrAddress;
  uint32_t sFlowRcvrPort;
  uint32_t sFlowRcvrDatagramVersion;
  /* public fields */
  struct _SFLAgent *agent;    /* pointer to my agent */
  /* private fields */
  SFDDgram *sfdg;
} SFLReceiver;

typedef struct _SFLSampler {
  /* for linked list */
  struct _SFLSampler *nxt;
  /* for hash lookup table */
  struct _SFLSampler *hash_nxt;
  /* MIB fields */
  SFLDataSource_instance dsi;
  uint32_t sFlowFsReceiver;
  uint32_t sFlowFsPacketSamplingRate;
  uint32_t sFlowFsMaximumHeaderSize;
  /* public fields */
  struct _SFLAgent *agent; /* pointer to my agent */
  void *userData;          /* can be useful to hang something else here */
  /* private fields */
  SFLReceiver *myReceiver;
  uint32_t skip;
  uint32_t samplePool;
  uint32_t flowSampleSeqNo;
  /* rate checking */
  uint32_t samplesThisTick;
  uint32_t samplesLastTick;
  uint32_t backoffThreshold;
  /* optional alias datasource index */
  uint32_t ds_alias;
} SFLSampler;

/* declare */
struct _SFLPoller;

typedef void (*getCountersFn_t)(void *magic,                   /* callback to get counters */
				struct _SFLPoller *sampler,    /* called with self */
				SFL_COUNTERS_SAMPLE_TYPE *cs); /* struct to fill in */

typedef struct _SFLPoller {
  /* for linked list */
  struct _SFLPoller *nxt;
  /* MIB fields */
  SFLDataSource_instance dsi;
  uint32_t sFlowCpReceiver;
  time_t sFlowCpInterval;
  /* public fields */
  struct _SFLAgent *agent; /* pointer to my agent */
  void *magic;             /* ptr to pass back in getCountersFn() */
  void *userData;          /* can be useful to hang something else here */
  getCountersFn_t getCountersFn;
  /* private fields */
  SFLReceiver *myReceiver;
  time_t countersCountdown;
  uint32_t countersSampleSeqNo;
  /* optional alias datasource index */
  uint32_t ds_alias;
} SFLPoller;

typedef void *(*allocFn_t)(void *magic,               /* callback to allocate space on heap */
			   struct _SFLAgent *agent,   /* called with self */
			   size_t bytes);             /* bytes requested */

typedef int (*freeFn_t)(void *magic,                  /* callback to free space on heap */
			struct _SFLAgent *agent,      /* called with self */
			void *obj);                   /* obj to free */

typedef void (*errorFn_t)(void *magic,                /* callback to log error message */
			  struct _SFLAgent *agent,    /* called with self */
			  char *msg);                 /* error message */

typedef void (*sendFn_t)(void *magic,                 /* optional override fn to send packet */
			 struct _SFLAgent *agent,
			 SFLReceiver *receiver,
			 u_char *pkt,
			 uint32_t pktLen);


typedef struct _SFLNotifier {
  /* for linked list */
  struct _SFLNotifier *nxt;
  /* MIB fields */
  SFLDataSource_instance dsi;
  uint32_t sFlowEsReceiver;
  uint32_t sFlowEsMaximumHeaderSize;
  /* public fields */
  struct _SFLAgent *agent; /* pointer to my agent */
  void *userData;          /* can be useful to hang something else here */
  /* private fields */
  SFLReceiver *myReceiver;
  uint32_t seqNo;
  uint32_t nLastTick;
  uint32_t nThisTick;
  /* optional alias datasource index */
  uint32_t ds_alias;
} SFLNotifier;

/* prime numbers are good for hash tables */
#define SFL_HASHTABLE_SIZ 199

typedef struct _SFLAgent {
  SFLSampler *jumpTable[SFL_HASHTABLE_SIZ]; /* fast lookup table for samplers (by ifIndex) */
  SFLSampler *samplers;   /* the list of samplers */
  SFLPoller  *pollers;    /* the list of samplers */
  SFLNotifier *notifiers; /* the list of notifiers */
  SFLReceiver *receivers; /* the array of receivers */
  time_t bootTime;        /* time when we booted or started */
  time_t now;             /* time now - seconds */
  time_t now_nS;          /* time now - nanoseconds 0-1000000000 */
  SFLAddress myIP;        /* IP address of this node */
  uint32_t subId;         /* sub_agent_id */
  void *magic;            /* ptr to pass back in logging and alloc fns */
  allocFn_t allocFn;
  freeFn_t freeFn;
  errorFn_t errorFn;
  sendFn_t sendFn;
  struct {
    f_alloc_t allocFn;
    f_free_t freeFn;
    f_err_t errFn;
    f_now_mS_t nowFn;
    f_send_t sendFn;
    f_hook_t hookFn;
  } sfdg;
} SFLAgent;

/* call this at the start with a newly created agent */
void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent */
		    uint32_t subId,  /* agent_sub_id */
		    time_t bootTime,  /* agent boot time */
		    time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn);

/* call this to override the default datagram-builder send callback */
void sfl_agent_init_sfdg_sendFn(SFLAgent *agent, f_send_t sendFn);
/* call this to override the default datagram-builder now_mS callback */
void sfl_agent_init_sfdg_nowFn(SFLAgent *agent, f_now_mS_t nowFn);
/* call this to install a sample-hook datagram-builder callback */
void sfl_agent_init_sfdg_hookFn(SFLAgent *agent, f_hook_t hookFn);

/* call this to create samplers */
SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to create pollers */
SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic, /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn);

/* call this to create notifiers */
SFLNotifier *sfl_agent_addNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to create receivers */
SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent);

/* call this to remove samplers */
int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to remove pollers */
int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to remove nofifiers */
int sfl_agent_removeNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* note: receivers should not be removed. Typically the receivers
   list will be created at init time and never changed */

/* call these fns to retrieve sampler, poller, notifier or receiver (e.g. for SNMP GET or GETNEXT operation) */
SFLSampler  *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLSampler  *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLPoller   *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLPoller   *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLNotifier *sfl_agent_getNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLNotifier  *sfl_agent_getNextNotifier(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, uint32_t receiverIndex);
SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, uint32_t receiverIndex);

/* jump table access - for performance */
SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, uint32_t ifIndex);

/* random number generator - used by sampler and poller */
uint32_t sfl_random(uint32_t mean);
void sfl_random_init(uint32_t seed);

/* call these functions to GET and SET MIB values */

/* receiver */
char *      sfl_receiver_get_sFlowRcvrOwner(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrOwner(SFLReceiver *receiver, char *sFlowRcvrOwner);
time_t      sfl_receiver_get_sFlowRcvrTimeout(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrTimeout(SFLReceiver *receiver, time_t sFlowRcvrTimeout);
uint32_t    sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, uint32_t sFlowRcvrMaximumDatagramSize);
SFLAddress *sfl_receiver_get_sFlowRcvrAddress(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrAddress(SFLReceiver *receiver, SFLAddress *sFlowRcvrAddress);
uint32_t    sfl_receiver_get_sFlowRcvrPort(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrPort(SFLReceiver *receiver, uint32_t sFlowRcvrPort);
/* sampler */
uint32_t sfl_sampler_get_sFlowFsReceiver(SFLSampler *sampler);
void     sfl_sampler_set_sFlowFsReceiver(SFLSampler *sampler, uint32_t sFlowFsReceiver);
uint32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler);
void     sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, uint32_t sFlowFsPacketSamplingRate);
uint32_t sfl_sampler_get_sFlowFsMaximumHeaderSize(SFLSampler *sampler);
void     sfl_sampler_set_sFlowFsMaximumHeaderSize(SFLSampler *sampler, uint32_t sFlowFsMaximumHeaderSize);
/* poller */
uint32_t sfl_poller_get_sFlowCpReceiver(SFLPoller *poller);
void     sfl_poller_set_sFlowCpReceiver(SFLPoller *poller, uint32_t sFlowCpReceiver);
uint32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller);
void     sfl_poller_set_sFlowCpInterval(SFLPoller *poller, uint32_t sFlowCpInterval);
void     sfl_poller_synchronize_polling(SFLPoller *poller, SFLPoller *master);
/* notifier */
uint32_t sfl_notifier_get_sFlowEsReceiver(SFLNotifier *notifier);
void sfl_notifier_set_sFlowEsReceiver(SFLNotifier *notifier, uint32_t sFlowEsReceiver);
uint32_t sfl_notifier_get_sFlowEsMaximumHeaderSize(SFLNotifier *notifier);
void sfl_notifier_set_sFlowEsMaximumHeaderSize(SFLNotifier *notifier, uint32_t sFlowEsMaximumHeaderSize);
uint32_t sfl_notifier_get_nLastTick(SFLNotifier *notifier);

/* call this to indicate a discontinuity with a counter like samplePool so that the
   sflow collector will ignore the next delta */
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler);

/* call this to indicate a discontinuity with one or more of the counters so that the
   sflow collector will ignore the next delta */
void sfl_poller_resetCountersSeqNo(SFLPoller *poller);

/* call this to indicate a discontinuity with the stream of notifications */
void sfl_notifier_resetSeqNo(SFLNotifier *notifier);
  
/* software sampling: call this with every packet - returns non-zero if the packet
   should be sampled (in which case you then call sfl_sampler_writeFlowSample()) */
int sfl_sampler_takeSample(SFLSampler *sampler);

/* call this to set a maximum samples-per-second threshold. If the sampler reaches this
   threshold it will automatically back off the sampling rate. A value of 0 disables the
   mechanism */
void sfl_sampler_set_backoffThreshold(SFLSampler *sampler, uint32_t samplesPerSecond);
uint32_t sfl_sampler_get_backoffThreshold(SFLSampler *sampler);

/* call this once per second (N.B. not on interrupt stack i.e. not hard real-time) */
void sfl_agent_tick(SFLAgent *agent, time_t now);

/* call this to set more accurate "now" - e.g. to influence datagram timestamp */
void sfl_agent_set_now(SFLAgent *agent, time_t now_S, time_t now_nS);

/* call this to change the designated sflow-agent-address */  
SFLAddress *sfl_agent_get_address(SFLAgent *agent);
void sfl_agent_set_address(SFLAgent *agent, SFLAddress *ip);

/* use this to remap datasource index numbers on export */
void sfl_sampler_set_dsAlias(SFLSampler *sampler, uint32_t ds_alias);
void sfl_poller_set_dsAlias(SFLPoller *poller, uint32_t ds_alias);
void sfl_notifier_set_dsAlias(SFLNotifier *notifier, uint32_t ds_alias);

/* convert stored "now" to mS since bootTime */
uint32_t sfl_agent_uptime_mS(SFLAgent *agent);

/* call this with each flow sample */
void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs);

/* call this to push counters samples (usually done in the getCountersFn callback) */
void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);

/* call this to send a notification */
void sfl_notifier_writeEventSample(SFLNotifier *notifier, SFLEvent_discarded_packet *es);

/* call this to deallocate resources */
void sfl_agent_release(SFLAgent *agent);

/* internal fns */

void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent);
void sfl_receiver_init_sfdg(SFLReceiver *receiver);
void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi);
void sfl_poller_init(SFLPoller *poller, SFLAgent *agent, SFLDataSource_instance *pdsi, void *magic, getCountersFn_t getCountersFn);
void sfl_notifier_init(SFLNotifier *notifier, SFLAgent *agent, SFLDataSource_instance *pdsi);

void sfl_receiver_tick(SFLReceiver *receiver, time_t now);
void sfl_poller_tick(SFLPoller *poller, time_t now);
void sfl_sampler_tick(SFLSampler *sampler, time_t now);
void sfl_notifier_tick(SFLNotifier *notifier, time_t now);

int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs);
int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs);
int sfl_receiver_writeEventSample(SFLReceiver *receiver, SFLEvent_discarded_packet *es);
int sfl_receiver_writeEncoded(SFLReceiver *receiver, uint32_t samples, uint32_t *data, int packedSize);
SFDBuf *sfl_receiver_get_SFDBuf(SFLReceiver *receiver);
int sfl_receiver_free_SFDBuf(SFLReceiver *receiver, SFDBuf *dbuf);
int sfl_receiver_write_SFDBuf(SFLReceiver *receiver, SFDBuf *dbuf);
void sfl_receiver_flush(SFLReceiver *receiver);

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver);

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg);
void sfl_agent_sysError(SFLAgent *agent, char *modName, char *msg);

uint32_t sfl_receiver_samplePacketsSent(SFLReceiver *receiver);

#define SFL_ALLOC malloc
#define SFL_FREE free

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_API_H */


