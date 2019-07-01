/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "hsflowd.h"
#include "regex.h"

#define HSP_DEFAULT_SWITCHPORT_REGEX "^Ethernet[0-9]+$"
#define HSP_DEFAULT_REDIS_HOST "127.0.0.1"
#define HSP_DEFAULT_REDIS_PORT 6379

#define HSP_SONIC_DB_COUNTERS 2
#define HSP_SONIC_DB_STATE 4

#define HSP_SONIC_FIELD_IFINDEX "index"
#define HSP_SONIC_FIELD_IFSPEED "speed"
#define HSP_SONIC_FIELD_IFSPEED_UNITS 1000000LL
#define HSP_SONIC_FIELD_IFALIAS "alias"
#define HSP_SONIC_FIELD_IFADMINSTATUS "admin_status"

#define HSP_SONIC_FIELD_IFIN_UCASTS "SAI_PORT_STAT_IF_IN_UCAST_PKTS"
#define HSP_SONIC_FIELD_IFIN_MCASTS "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS"
#define HSP_SONIC_FIELD_IFIN_BCASTS "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS"
#define HSP_SONIC_FIELD_IFIN_OCTETS "SAI_PORT_STAT_IF_IN_OCTETS"
#define HSP_SONIC_FIELD_IFIN_ERRORS "SAI_PORT_STAT_IF_IN_ERRORS"
#define HSP_SONIC_FIELD_IFIN_UNKNOWNS "SAI_PORT_STAT_IF_IN_UNKNOWN_PROTOS"
#define HSP_SONIC_FIELD_IFIN_DISCARDS "SAI_PORT_STAT_IF_IN_DISCARDS"

#define HSP_SONIC_FIELD_IFOUT_UCASTS "SAI_PORT_STAT_IF_OUT_UCAST"
#define HSP_SONIC_FIELD_IFOUT_MCASTS "SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS"
#define HSP_SONIC_FIELD_IFOUT_BCASTS "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS"
#define HSP_SONIC_FIELD_IFOUT_OCTETS "SAI_PORT_STAT_IF_OUT_OCTETS"
#define HSP_SONIC_FIELD_IFOUT_ERRORS "SAI_PORT_STAT_IF_OUT_ERRORS"
#define HSP_SONIC_FIELD_IFOUT_DISCARDS "SAI_PORT_STAT_IF_OUT_DISCARDS"

#define HSP_SONIC_MIN_POLLING_INTERVAL 5

#define HSP_MAX_EXEC_LINELEN 1024

  typedef enum {
    HSP_SONIC_STATE_INIT=0,
    HSP_SONIC_STATE_CONNECT,
    HSP_SONIC_STATE_DISCOVER,
    HSP_SONIC_STATE_RUN } EnumSonicState;

  typedef struct _HSPSonicPort {
    char *portName;
    char *oid;
    bool mark:1;
    bool operUp:1;
    bool adminUp:1;
    uint32_t ifIndex;
    uint64_t ifSpeed;
    char *ifAlias;
    SFLHost_nio_counters ctrs;
    HSP_ethtool_counters et_ctrs;
  } HSPSonicPort;

  typedef struct _HSP_mod_SONIC {
    EnumSonicState state;
    EVBus *pollBus;
    redisAsyncContext *db;
    int dbNo;
    UTHash *portsByName;
    UTArray *newPorts;
    bool changedSwitchPorts:1;
    UTStrBuf *replyBuf;
  } HSP_mod_SONIC;

  static void discoverNewPorts(EVMod *mod);

  /*_________________---------------------------__________________
    _________________      db_replyStr          __________________
    -----------------___________________________------------------
  */
  static char *db_replyStr(redisReply *reply, UTStrBuf *sbuf) {
    switch (reply->type) {
    case REDIS_REPLY_STRING:
      UTStrBuf_printf(sbuf, "string(%d)=\"%s\"", reply->len, reply->str);
      break;
    case REDIS_REPLY_ARRAY:
      UTStrBuf_printf(sbuf, "array(%d)", reply->elements);
      break;
    case REDIS_REPLY_INTEGER:
      UTStrBuf_printf(sbuf, "integer(%lld)", reply->integer);
      break;
    case REDIS_REPLY_NIL:
      UTStrBuf_printf(sbuf, "nil");
      break;
    case REDIS_REPLY_STATUS:
      UTStrBuf_printf(sbuf, "status(%lld)=\"%s\"", reply->integer, reply->str ?: "");
      break;
    case REDIS_REPLY_ERROR:
      UTStrBuf_printf(sbuf, "error(%lld)=\"%s\"", reply->integer, reply->str ?: "");
      break;
    default:
      UTStrBuf_printf(sbuf, "unknown(%d)", reply->type);
      break;
    }
    return UTSTRBUF_STR(sbuf);
  }

#if 0
  /*_________________---------------------------__________________
    _________________      db_errorType         __________________
    -----------------___________________________------------------
  */
  static char *db_errorType(int err) {
    switch (err) {
    case REDIS_ERR_IO: return "IO";
    case REDIS_ERR_EOF: return "EOF";
    case REDIS_ERR_PROTOCOL: return "PROTOCOL";
    case REDIS_ERR_OOM: return "OOM";
    case REDIS_ERR_OTHER: return "OTHER";
    }
    return "<unknown error type>";
  }
#endif

  /*_________________---------------------------__________________
    _________________      db_getU32            __________________
    -----------------___________________________------------------
  */
  static uint32_t db_getU32(redisReply *reply) {
    uint32_t ans32 = 0;
    switch (reply->type) {
    case REDIS_REPLY_STRING:
      ans32 = strtoul(reply->str, NULL, 0);
      break;
    case REDIS_REPLY_INTEGER:
      ans32 = (uint32_t)reply->integer;
      break;
    }
    return ans32;
  }

  /*_________________---------------------------__________________
    _________________      db_getU64            __________________
    -----------------___________________________------------------
  */
  static uint32_t db_getU64(redisReply *reply) {
    uint64_t ans64 = 0;
    switch (reply->type) {
    case REDIS_REPLY_STRING:
      ans64 = strtoull(reply->str, NULL, 0);
      break;
    case REDIS_REPLY_INTEGER:
      ans64 = (uint64_t)reply->integer;
      break;
    }
    return ans64;
  }
      
  /*_________________---------------------------__________________
    _________________    mark and sweep         __________________
    -----------------___________________________------------------
  */

  static void markPorts(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt;
    UTHASH_WALK(mdata->portsByName, prt)
      prt->mark = YES;
  }

  static void deleteMarkedPorts(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt;
    UTHASH_WALK(mdata->portsByName, prt) {
      if(prt->mark) {
	myDebug(1, "sonic port removed %s", prt->portName);
	// TODO: other places to remove?
	UTHashDel(mdata->portsByName, prt);
	my_free(prt->portName);
	my_free(prt->oid);
	my_free(prt->ifAlias);
	my_free(prt);
      }
    }
  }


  /*_________________---------------------------__________________
    _________________    redis event adaptor    __________________
    -----------------___________________________------------------
  */

  static void db_disconnectCB(const redisAsyncContext *ctx, int status) {
    EVMod *mod = (EVMod *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "db_disconnectCB: status= %d", status);
    // try to reconnect on tick
    // TODO: test - take redis down and up again
    mdata->state = HSP_SONIC_STATE_CONNECT;
  }

  static void db_readCB(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "sonic db_readCB");
    redisAsyncHandleRead(mdata->db);
  }

  static void db_addReadCB(void *magic) {
    myDebug(1, "sonic db_addReadCB");
    // nothing to do - we are always ready to read
  }

  static void db_delReadCB(void *magic) {
    myDebug(1, "sonic db_delReadCB");
  }

  static void db_addWriteCB(void *magic) {
    EVMod *mod = (EVMod *)magic;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "sonic db_addWriteCB");
    // TODO: tell evbus to look for write flag?
    // or just short-circuit it even if we might block?
    // We could set the file descriptor to non-blocking
    // mode with fcntl so that we get an EWOULDBLOCK
    // error if there is some problem.
    redisAsyncHandleWrite(mdata->db);
  }

  static void db_delWriteCB(void *magic) {
    myDebug(1, "sonic db_delWriteCB");
    // TODO: tell evbus to stop looking for write flag?
  }

  static void db_cleanupCB(void *magic) {
    myDebug(1, "sonic db_cleanupCB");
  }

  /*_________________---------------------------__________________
    _________________      db_connect           __________________
    -----------------___________________________------------------
  */

  static void db_infoCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    EVMod *mod = (EVMod *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    UTStrBuf_reset(mdata->replyBuf);
    myDebug(1, "sonic info: reply=%s", db_replyStr(reply, mdata->replyBuf));
    //redisReader *reader = redisReaderCreate();
    //redisReaderFeed(reader, reply->str, reply->len);
    //redisReply *reply2 = NULL;
    //redisReaderGetReply(reader, (void **)&reply2);
    mdata->state =  HSP_SONIC_STATE_DISCOVER;
  }


  static void db_connect(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "sonic redis connect");
    mdata->db = redisAsyncConnect(HSP_DEFAULT_REDIS_HOST, HSP_DEFAULT_REDIS_PORT);
    // TODO: check mdata->redisCtx->err;
    redisAsyncSetDisconnectCallback(mdata->db, db_disconnectCB);
    // mdata->redisCtx->onDisconnect = db_disconnectCB;
    int fd = mdata->db->c.fd;
    if(fd > 0) {
      myDebug(1, "sonic redis fd == %d", fd);
      EVBusAddSocket(mod, mdata->pollBus, fd, db_readCB, NULL /* magic */);
      mdata->db->ev.addRead = db_addReadCB;
      mdata->db->ev.delRead = db_delReadCB;
      mdata->db->ev.addWrite = db_addWriteCB;
      mdata->db->ev.delWrite = db_delWriteCB;
      mdata->db->ev.cleanup = db_cleanupCB;
      mdata->db->ev.data = mod;
      
      myDebug(1, "sonic sending command: INFO");
      int status = redisAsyncCommand(mdata->db, db_infoCB, NULL /*privData*/, "INFO");
      myDebug(1, "sonic redisAsyncCommand returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________    db_select              __________________
    -----------------___________________________------------------
  */

  static void db_selectCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    EVMod *mod = (EVMod *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    UTStrBuf_reset(mdata->replyBuf);
    myDebug(1, "sonic select: reply=%s", db_replyStr(reply, mdata->replyBuf));
  }

  static void db_select(EVMod *mod, int dbNo) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    if(dbNo != mdata->dbNo) {
      myDebug(1, "sonic sending command to select DB %u", dbNo);
      int status = redisAsyncCommand(mdata->db, db_selectCB, NULL /*privData*/, "select %u", dbNo);
      myDebug(1, "sonic redisAsyncCommand returned %d", status);
      mdata->dbNo = dbNo;
    }
  }

  /*_________________---------------------------__________________
    _________________      db_getPortNames      __________________
    -----------------___________________________------------------
  */

#define ISEVEN(i) (((i) & 1) == 0)

  static void signalCounterDiscontinuity(EVMod *mod, HSPSonicPort *prt) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);
    if(adaptor) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      if(nio
	 && nio->poller)
	sfl_poller_resetCountersSeqNo(nio->poller);
    }
  }

  static void db_portNamesCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    EVMod *mod = (EVMod *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    markPorts(mod);
    UTStrBuf_reset(mdata->replyBuf);
    myDebug(1, "sonic portNames: reply=%s", db_replyStr(reply, mdata->replyBuf));
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *p_name = reply->element[ii];
	redisReply *p_oid = reply->element[ii + 1];
	if(p_name->type == REDIS_REPLY_STRING
	   && p_oid->type == REDIS_REPLY_STRING) {
	  HSPSonicPort search = { .portName = p_name->str };
	  HSPSonicPort *prt = UTHashGet(mdata->portsByName, &search);
	  if(prt == NULL) {
	    prt = (HSPSonicPort *)my_calloc(sizeof(HSPSonicPort));
	    prt->portName = my_strdup(p_name->str);
	    prt->oid = my_strdup(p_oid->str);
	    UTHashAdd(mdata->portsByName, prt);
	    UTArrayPush(mdata->newPorts, prt);
	    myDebug(1, "sonic portNames: new port %s -> %s", prt->portName, prt->oid);
	  }
	  else if(!my_strequal(prt->oid, p_oid->str)) {
	    // OID changed under our feet
	    my_free(prt->oid);
	    prt->oid = my_strdup(p_oid->str);
	    signalCounterDiscontinuity(mod, prt);
	  }
	  prt->mark = NO;
	}
      }
    }
    deleteMarkedPorts(mod);
    mdata->state = HSP_SONIC_STATE_RUN;
  }

  static void db_getPortNames(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    db_select(mod, HSP_SONIC_DB_COUNTERS);
    myDebug(1, "sonic sending command to get port name map");
    int status = redisAsyncCommand(mdata->db, db_portNamesCB, NULL, "HGETALL COUNTERS_PORT_NAME_MAP");
    myDebug(1, "sonic redisAsyncCommand returned %d", status);
  }


  /*_________________---------------------------__________________
    _________________      db_getPortState      __________________
    -----------------___________________________------------------
  */

  static void db_portStateCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    EVMod *mod = (EVMod *)ctx->ev.data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;
    UTStrBuf_reset(mdata->replyBuf);
    myDebug(1, "sonic portState: reply=%s", db_replyStr(reply, mdata->replyBuf));
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  UTStrBuf_reset(mdata->replyBuf);
	  myDebug(1, "sonic portState: %s=%s", c_name->str, db_replyStr(c_val, mdata->replyBuf));
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFINDEX))
	    prt->ifIndex = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFSPEED))
	    prt->ifSpeed = db_getU64(c_val) * HSP_SONIC_FIELD_IFSPEED_UNITS;
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFALIAS))
	    prt->ifAlias = my_strdup(c_val->str);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFADMINSTATUS)) {
	    prt->adminUp = my_strequal(c_val->str, "up");
	    prt->operUp = prt->adminUp; // TODO: where should we get oper_status?
	  }
	}
      }
      SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);
      
#ifdef HSP_SONIC_TEST_REDISONLY
      // Adaptor missing in test-case with redis db dump. Add it here:
      if(adaptor == NULL) {
	adaptor = nioAdaptorNew(prt->portName, NULL, prt->ifIndex);
	adaptorAddOrReplace(sp->adaptorsByName, adaptor);
	adaptorAddOrReplace(sp->adaptorsByIndex, adaptor);
      }
#endif
      if(adaptor) {
	// TODO: check that ifIndex matches!
	// TODO: readVlans
	// TODO: read bond state (may need the nio->bond flag right away)
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	if(nio) {
	  nio->up = prt->operUp;
	  nio->switchPort = YES;
	  mdata->changedSwitchPorts = YES;
	}
	setAdaptorSpeed(sp, adaptor, prt->ifSpeed, "MOD_SONIC");
      }
    }
    // we may still have a batch of new ports to discover
    discoverNewPorts(mod);
  }

  static void db_getPortState(EVMod *mod, HSPSonicPort *prt) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    db_select(mod, HSP_SONIC_DB_STATE);
    int status = redisAsyncCommand(mdata->db, db_portStateCB, prt, "HGETALL PORT|%s", prt->portName);
    myDebug(1, "sonic redisAsyncCommand returned %d", status);
  }

  static void discoverNewPorts(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // kick off just one - starts a chain reaction if there are more.
    // Gets the state (index, speed etc.) so we can add it as an adaptor.
    HSPSonicPort *prt = UTArrayPop(mdata->newPorts);
    if(prt)
      db_getPortState(mod, prt);
  }


  /*_________________---------------------------__________________
    _________________      db_getPortCounters   __________________
    -----------------___________________________------------------
  */

  static void db_portCountersCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    EVMod *mod = (EVMod *)ctx->ev.data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;

    UTStrBuf_reset(mdata->replyBuf);
    myDebug(1, "sonic portCounters: reply=%s", db_replyStr(reply, mdata->replyBuf));
    memset(&prt->ctrs, 0, sizeof(prt->ctrs));
    memset(&prt->et_ctrs, 0, sizeof(prt->et_ctrs));
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  UTStrBuf_reset(mdata->replyBuf);
	  myDebug(1, "sonic portCounters: %s=%s", c_name->str, db_replyStr(c_val, mdata->replyBuf));
	  
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_UCASTS))
	    prt->ctrs.pkts_in = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_ERRORS))
	    prt->ctrs.errs_in = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_DISCARDS))
	    prt->ctrs.drops_in = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_OCTETS))
	    prt->ctrs.bytes_in = db_getU64(c_val);

	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOUT_UCASTS))
	    prt->ctrs.pkts_out = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOUT_ERRORS))
	    prt->ctrs.errs_out = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOUT_DISCARDS))
	    prt->ctrs.drops_out = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOUT_OCTETS))
	    prt->ctrs.bytes_out = db_getU64(c_val);

	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_MCASTS))
	    prt->et_ctrs.mcasts_in = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_BCASTS))
	    prt->et_ctrs.bcasts_in = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFIN_UNKNOWNS))
	    prt->et_ctrs.unknown_in = db_getU32(c_val);

	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOUT_MCASTS))
	    prt->et_ctrs.mcasts_out = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOUT_BCASTS))
	    prt->et_ctrs.bcasts_out = db_getU32(c_val);

	  // TODO: ifAdminStatus, ifOperStatus - should they be polled here?
	  // or do we poll the state often enough?
	  prt->et_ctrs.operStatus = prt->operUp;
	  prt->et_ctrs.adminStatus = prt->adminUp;
	}
      }
    }
    // sumbit counters for deltas to be accumulated
    SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);
    if(adaptor) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      if(nio) {
	nio->et_found = HSP_ETCTR_MC_IN
	  | HSP_ETCTR_MC_OUT
	  | HSP_ETCTR_BC_IN
	  | HSP_ETCTR_BC_OUT
	  | HSP_ETCTR_UNKN
	  // | HSP_ETCTR_OPER
	  | HSP_ETCTR_ADMIN;
	accumulateNioCounters(sp, adaptor, &prt->ctrs, &prt->et_ctrs);
	nio->last_update = sp->pollBus->now.tv_sec;
      }
    }
  }

  static void db_getPortCounters(EVMod *mod, HSPSonicPort *prt) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    db_select(mod, HSP_SONIC_DB_COUNTERS);
    myDebug(1, "request: HGETALL COUNTERS:%s", prt->oid);
    // TODO: consider getting only the counters we want
    int status = redisAsyncCommand(mdata->db, db_portCountersCB, prt, "HGETALL COUNTERS:%s", prt->oid);
    myDebug(1, "sonic redisAsyncCommand returned %d", status);
  }

  /*_________________---------------------------__________________
    _________________    syncSwitchPorts        __________________
    -----------------___________________________------------------
  */

  static void syncSwitchPorts(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(mdata->changedSwitchPorts) {
      // announce switch ports, so that individual pollers will be created and LAGs will be checked
      configSwitchPorts(sp);
      EVEventTxAll(sp->rootModule, HSPEVENT_INTFS_CHANGED, NULL, 0);
      mdata->changedSwitchPorts = NO;
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_poll_config_first  __________________
    -----------------___________________________------------------
  */

  static void evt_poll_config_first(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    // only get here if we have a valid config
    // TODO: set a state that will be picked up on tick()? So we can keep trying if it doesn't work?
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    mdata->state =  HSP_SONIC_STATE_CONNECT;
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_poll_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    // TODO: not sure there is anything we need to do here
  }

  /*_________________---------------------------__________________
    _________________      evt_intf_read        __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);

    myDebug(1, "evt_poll_intf_read(%s)", adaptor->deviceName);

    // TODO: this might be the right place to look up in portsByMame, set the ifSpeed
    // and mark it as a switch-port.  Except that maybe the redis walk has not been
    // completed yet.  So we might need to use the switchport regex after all?

    // turn off the use of ethtool_GSET so it doesn't get the wrong speed
    // and turn off other ethtool requests because they won't add to the picture
    // TODO: what about eth0 (software interface). It won't be a switch-port but
    // sure it can be usefully queried with ethtool?
    nio->ethtool_GSET = NO;
    nio->ethtool_GLINKSETTINGS = NO;
    nio->ethtool_GSTATS = NO;
    nio->ethtool_GDRVINFO = NO;
    // the /proc/net/dev counters are invalid too
    nio->procNetDev = NO;
  }

  /*_________________---------------------------__________________
    _________________      evt_intfs_changed    __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // need to refresh oid-mapping
    if(mdata->state == HSP_SONIC_STATE_RUN)
      mdata->state = HSP_SONIC_STATE_DISCOVER;
  }

  /*_________________---------------------------__________________
    _________________     evt_poll_update_nio   __________________
    -----------------___________________________------------------
  */

  static void evt_poll_update_nio(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    // We only need to override behavior for a port-specific request
    // so ignore the general updates with adaptor == NULL.  They are
    // for refreshing the host-adaptor counters (eth0 etc.)
    if(adaptor == NULL)
      return;

    myDebug(1, "pollCounters(adaptor=%s)", adaptor->deviceName);

    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    
    if(nio->loopback
       || nio->bond_master) {
      // bond counters will be synthesized - don't try to poll them here
      return;
    }
    HSPSonicPort search = { .portName = adaptor->deviceName };
    HSPSonicPort *prt = UTHashGet(mdata->portsByName, &search);
    if(prt) {
      // OK to queue 4 requests on the TCP connection, and ordering
      // is preserved, so can just ask for state-refresh and counters
      // together:
      db_getPortState(mod, prt);
      db_getPortCounters(mod, prt);
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    
    switch(mdata->state) {
    case HSP_SONIC_STATE_INIT:
      // waiting for evt_config_changed
      break;
    case HSP_SONIC_STATE_CONNECT:
      // got config - try to connect
      db_connect(mod);
      break;
    case HSP_SONIC_STATE_DISCOVER:
      db_getPortNames(mod); // TODO do this periodically
      break;
    case HSP_SONIC_STATE_RUN:
      // check for new ports
      discoverNewPorts(mod);
      syncSwitchPorts(mod);
      break;
    }

  }

  /*_________________---------------------------__________________
    _________________        evt_final          __________________
    -----------------___________________________------------------
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sFlowSettings == NULL)
      return;
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_sonic(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    mod->data = my_calloc(sizeof(HSP_mod_SONIC));
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    mdata->portsByName = UTHASH_NEW(HSPSonicPort, portName, UTHASH_SKEY);
    mdata->newPorts = UTArrayNew(UTARRAY_DFLT);
    mdata->replyBuf = UTStrBuf_new();
    // retainRootRequest(mod, "Needed to call out to OPX scripts (PYTHONPATH)");

    // ask that bond counters be accumuated from their components
    setSynthesizeBondCounters(mod, YES);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_READ), evt_poll_intf_read);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_poll_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_UPDATE_NIO), evt_poll_update_nio);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_FIRST), evt_poll_config_first);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_CHANGED), evt_poll_config_changed);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_FINAL), evt_final);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_TICK), evt_tick);

    // we know there are no 32-bit counters
    sp->nio_polling_secs = 0;

    // set a minimum polling interval
    if(sp->minPollingInterval < HSP_SONIC_MIN_POLLING_INTERVAL) {
      sp->minPollingInterval = HSP_SONIC_MIN_POLLING_INTERVAL;
    }
    // ask for polling to be sync'd so that clusters of interfaces are polled together.
    if(sp->syncPollingInterval < HSP_SONIC_MIN_POLLING_INTERVAL) {
      sp->syncPollingInterval = HSP_SONIC_MIN_POLLING_INTERVAL;
    }

  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
