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
#include "cJSON.h"

#define HSP_SONIC_DB_JSON "/var/run/redis/sonic-db/database_config.json"
#define HSP_SONIC_DB_APPL_NAME "APPL_DB"
#define HSP_SONIC_DB_COUNTERS_NAME "COUNTERS_DB"
#define HSP_SONIC_DB_CONFIG_NAME "CONFIG_DB"
#define HSP_SONIC_DB_STATE_NAME "STATE_DB"
#define HSP_SONIC_DB_EVENT_SUFFIX "_HSFLOWD_EVENTS"

#define HSP_SONIC_FIELD_MAC "mac"
#define HSP_SONIC_FIELD_LOCALAS "bgp_asn"
#define HSP_SONIC_FIELD_IFINDEX "index"
#define HSP_SONIC_FIELD_IFINDEX_OS "ifindex"
#define HSP_SONIC_IFINDEX_UNDEFINED 0xFFFFFFFF
#define HSP_SONIC_FIELD_IFSPEED "speed"
#define HSP_SONIC_FIELD_IFSPEED_UNITS 1000000LL
#define HSP_SONIC_FIELD_IFALIAS "alias"
#define HSP_SONIC_FIELD_IFOPERSTATUS "oper_status"
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

#define HSP_SONIC_FIELD_SFLOW_ADMIN_STATE "admin_state"
#define HSP_SONIC_FIELD_SFLOW_POLLING "polling_interval"
#define HSP_SONIC_FIELD_SFLOW_AGENT "agent_id"
#define HSP_SONIC_FIELD_SFLOW_DROP_MONITOR_LIMIT "drop_monitor_limit" // *proposed*
#define HSP_SONIC_FIELD_SFLOW_SAMPLE_DIRECTION "sample_direction" // *proposed*
#define HSP_SONIC_FIELD_SFLOW_HEADER_BYTES "max_header_size" // *proposed*

#define HSP_SONIC_FIELD_COLLECTOR_IP "collector_ip"
#define HSP_SONIC_FIELD_COLLECTOR_PORT "collector_port"
#define HSP_SONIC_FIELD_COLLECTOR_VRF "collector_vrf"
#define HSP_SONIC_VRF_DEFAULT "default"

#define HSP_SONIC_FIELD_SYSTEMREADY_STATUS "Status"

#define HSP_SONIC_DEFAULT_POLLING_INTERVAL 20
#define HSP_SONIC_MIN_POLLING_INTERVAL 5

#define HSP_SONIC_MAX_PORTNAME_LEN 512

#define HSP_SONIC_DEFAULT_PORTCHANNEL_BASEINDEX 1000
#define HSP_SONIC_PORTCHANNEL_BASEINDEX_ENVVAR "SONIC_PORTCHANNEL_BASEINDEX"
#define HSP_SONIC_PORTCHANNEL_RE "^PortChannel([0-9]+)$"

#define ISEVEN(i) (((i) & 1) == 0)

  typedef enum {
    HSP_SONIC_STATE_INIT=0,
    HSP_SONIC_STATE_CONNECT,
    HSP_SONIC_STATE_WAIT_READY,
    HSP_SONIC_STATE_CONNECTED,
    HSP_SONIC_STATE_SFLOWGLOBAL,
    HSP_SONIC_STATE_COLLECTORS,
    HSP_SONIC_STATE_DISCOVER,
    HSP_SONIC_STATE_DISCOVER_MAPPING,
    HSP_SONIC_STATE_DISCOVER_LAGS,
    HSP_SONIC_STATE_SYNC_CONFIG,
    HSP_SONIC_STATE_RUN
  } EnumSonicState;

  static const char *SonicStateNames[] = {
    "INIT",
    "CONNECT",
    "WAIT_READY",
    "CONNECTED",
    "SFLOWGLOBAL",
    "COLLECTORS",
    "DISCOVER",
    "DISCOVER_MAPPING",
    "DISCOVER_LAGS",
    "SYNC_CONFIG",
    "RUN"
  };
  
  typedef struct _HSPSonicCollector {
    char *collectorName;
    bool mark:1;
    bool parseOK:1;
    bool newCollector:1;
    char *ipStr;
    uint32_t port;
    char *deviceName;
  } HSPSonicCollector;

  typedef struct _HSPSonicPort {
    char *portName;
    char *oid;
    bool mark:1;
    bool operUp:1;
    bool adminUp:1;
    bool oidChanged:1; // used to signal discontinuity (oid is key for counters)
    uint64_t ifSpeed;
    char *ifAlias;
    SFLHost_nio_counters ctrs;
    HSP_ethtool_counters et_ctrs;
  } HSPSonicPort;

  typedef struct _HSPSonicLAG {
    char *lagName;
    bool mark:1;
    uint32_t ifIndex;
    uint32_t osIndex;
    uint64_t ifSpeed;
    UTStringArray *components;
  } HSPSonicLAG;

  typedef struct _HSPSonicIdxMap {
    char *portName;
    bool mark:1;
    uint32_t ifIndex;
    uint32_t osIndex;
  } HSPSonicIdxMap;

  typedef struct _HSPSonicDBClient {
    redisAsyncContext *ctx;
    int dbNo;
    EVMod *mod;
    char *dbInstance;
    // connect via TCP
    char *hostname;
    int port;
    // or via unix domain socket
    char *unixSocketPath;
    char *passPath;
    EVSocket *sock;
    bool connected;
    uint32_t reads;
    uint32_t writes;
    UTStrBuf *replyBuf;
  } HSPSonicDBClient;

  typedef struct _HSPSonicDBTable {
    char *dbTable;
    int id;
    HSPSonicDBClient *dbClient;
    HSPSonicDBClient *evtClient;
    char *separator;
  } HSPSonicDBTable;

  typedef struct _HSP_mod_SONIC {
    EnumSonicState state;
    // threads (buses)
    EVBus *pollBus;
    EVBus *packetBus;
    // Redis DB
    UTHash *dbInstances;
    UTHash *dbTables;
    char *stateTabSeparator;
    // PORT
    UTHash *portsByName;
    uint32_t portsCursor;
    // PORT_INDEX_TABLE
    UTHash *idxMapByName;
    UTHash *idxMapByOsIndex;
    uint32_t idxMapCursor;
    // LAG
    UTHash *lagsByName;
    UTHash *lagsByOsIndex;
    uint32_t portChannelBaseIndex;
    regex_t *portChannelPattern;
    u_char actorSystemMAC[8];
    // COLLECTOR
    UTHash *collectors;
    uint32_t collectorCursor;
    // change flags
    bool changedPortTable:1;
    bool changedPortIndex:1;
    bool changedPortIndexTable:1;
    bool changedLagTable:1;
    bool changedSFlowGlobalTable:1;
    bool changedCollectorTable:1;
    bool changedLinuxInterfaces:1;
    // port-sync flags
    bool changedSwitchPorts:1;
    bool changedPortAlias:1;
    bool changedPortPriority:1;
    // BGP
    uint32_t localAS;
    // waitReady
    time_t waitReadyStart;
    bool system_ready;
    // sFlow config
    bool sflow_enable;
    uint32_t sflow_polling;
    uint32_t sflow_headerBytes;
    char *sflow_agent;
    uint32_t sflow_dropLimit;
    bool sflow_dropLimit_set;
    char *sflow_direction;
    // event bus
    EVEvent *configStartEvent;
    EVEvent *configEvent;
    EVEvent *configEndEvent;
  } HSP_mod_SONIC;

  static void db_ping(EVMod *mod, HSPSonicDBClient *db);
  static bool db_auth(EVMod *mod, HSPSonicDBClient *db);
  static void signalCounterDiscontinuity(EVMod *mod, HSPSonicIdxMap *idxm);
  static void syncConfig(EVMod *mod);
  static bool setSwitchPort(EVMod *mod, uint32_t osIndex, bool flag);
  static bool getNextIfIndexMap(EVMod *mod);
  static bool getNextPortState(EVMod *mod);
  static bool getNextCollectorInfo(EVMod *mod);
  static bool portSyncToAdaptor(EVMod *mod, HSPSonicPort *prt, bool sync);
  
  /*_________________---------------------------__________________
    _________________      db_replyStr          __________________
    -----------------___________________________------------------
  */

  static char *db_replyStr(redisReply *reply, UTStrBuf *sbuf, bool reset) {
    if(reset)
      UTStrBuf_reset(sbuf);
    if(reply == NULL)
      UTStrBuf_printf(sbuf, "<no reply>");
    else {
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
    }
    return UTSTRBUF_STR(sbuf);
  }

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

  static uint64_t db_getU64(redisReply *reply) {
    uint64_t ans64 = 0;
    switch (reply->type) {
    case REDIS_REPLY_STRING:
#if __WORDSIZE == 64
      ans64 = strtoul(reply->str, NULL, 0);
#else
      ans64 = strtoull(reply->str, NULL, 0);
#endif
      break;
    case REDIS_REPLY_INTEGER:
      ans64 = (uint64_t)reply->integer;
      break;
    }
    return ans64;
  }


  /*_________________---------------------------__________________
    _________________         keyToken          __________________
    -----------------___________________________------------------
  */

  static char *keyToken(EVMod *mod, char *key, char *sep, int tokenNo, char *buf, size_t bufLen) {
    assert(tokenNo > 0); // first token is tokenNo 1
    char *p = key;
    char *tok = NULL;
    while(--tokenNo >= 0)
      tok = parseNextTok(&p, sep, YES, 0, NO, buf, bufLen);
    return tok;
  }

  /*_________________---------------------------__________________
    _________________    setSonicState          __________________
    -----------------___________________________------------------
  */
  
  static void setSonicState(EVMod *mod, EnumSonicState st) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    assert(mdata->state >= HSP_SONIC_STATE_INIT
	   && mdata->state <= HSP_SONIC_STATE_RUN);
    assert(st >= HSP_SONIC_STATE_INIT
	   && st <= HSP_SONIC_STATE_RUN);
    char *from = (char *)SonicStateNames[mdata->state];
    char *to = (char *)SonicStateNames[st];
    EVDebug(mod, 1, "state %s -> %s", from, to);
    mdata->state = st;
  }


  /*_________________---------------------------__________________
    _________________     ports and LAGs        __________________
    -----------------___________________________------------------
  */

  static HSPSonicIdxMap *getIdxMap(EVMod *mod, char *portName, int create) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicIdxMap search = { .portName = portName };
    HSPSonicIdxMap *idxm = UTHashGet(mdata->idxMapByName, &search);
    if(idxm == NULL
       && create) {
      idxm = (HSPSonicIdxMap *)my_calloc(sizeof(HSPSonicIdxMap));
      idxm->portName = my_strdup(portName);
      idxm->ifIndex = HSP_SONIC_IFINDEX_UNDEFINED;
      idxm->osIndex = HSP_SONIC_IFINDEX_UNDEFINED;
      UTHashAdd(mdata->idxMapByName, idxm);
    }
    return idxm;
  }

  static HSPSonicIdxMap *getIdxMapByOsIndex(EVMod *mod, uint32_t osIndex) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicIdxMap search = { .osIndex = osIndex };
    return UTHashGet(mdata->idxMapByOsIndex, &search);
  }

  static HSPSonicPort *getPort(EVMod *mod, char *portName, int create) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort search = { .portName = portName };
    HSPSonicPort *prt = UTHashGet(mdata->portsByName, &search);
    if(prt == NULL
       && create) {
      prt = (HSPSonicPort *)my_calloc(sizeof(HSPSonicPort));
      prt->portName = my_strdup(portName);
      UTHashAdd(mdata->portsByName, prt);
    }
    return prt;
  }

  static SFLAdaptor *idxMapGetAdaptor(EVMod *mod, HSPSonicIdxMap *idxm) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    return adaptorByIndex(sp, idxm->osIndex);
  }
  
  static SFLAdaptor *portGetAdaptor(EVMod *mod, HSPSonicPort *prt) {
    HSPSonicIdxMap *idxm = getIdxMap(mod, prt->portName, NO);
    if(idxm)
      return idxMapGetAdaptor(mod, idxm);
    return NULL;
  }

  static SFLAdaptor *lagGetAdaptor(EVMod *mod, HSPSonicLAG *lag) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // first search the idxMap for the ifIndex that we have
    HSPSonicIdxMap *search=NULL, *idxm=NULL;
    UTHASH_WALK(mdata->idxMapByName, search) {
      if(search->ifIndex == lag->ifIndex) {
	idxm = search;
      }
    }
    if(idxm)
      return idxMapGetAdaptor(mod, idxm);
    // but it might not be in that table,  so fall back on the assumption
    // that the lagName may still match the Linux deviceName
    return adaptorByName(sp, lag->lagName);
  }

  static HSPSonicLAG *getLAG(EVMod *mod, char *lagName, int create) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG search = { .lagName = lagName };
    HSPSonicLAG *lag = UTHashGet(mdata->lagsByName, &search);
    if(lag == NULL
       && create) {
      lag = (HSPSonicLAG *)my_calloc(sizeof(HSPSonicLAG));
      lag->lagName = my_strdup(lagName);
      lag->ifIndex = HSP_SONIC_IFINDEX_UNDEFINED;
      lag->osIndex = HSP_SONIC_IFINDEX_UNDEFINED;
      UTHashAdd(mdata->lagsByName, lag);
    }
    return lag;
  }

  static HSPSonicLAG *getLagByOsIndex(EVMod *mod, uint32_t osIndex) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG search = { .osIndex = osIndex };
    return UTHashGet(mdata->lagsByOsIndex, &search);
  }
  
  static void printLags(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG *lag;
    UTHASH_WALK(mdata->lagsByName, lag) {
      if(lag->components) {
	char *details = strArrayStr(lag->components, "[", NULL, ",", "]");
	EVDebug(mod, 1, "LAG %s: %s", lag->lagName, details);
	my_free(details);
      }
    }
  }

  static void compileLags(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG *lag;
    UTHASH_WALK(mdata->lagsByName, lag) {
      if(lag->components) {
	char *details = strArrayStr(lag->components, "[", NULL, ",", "]");
	EVDebug(mod, 1, "compiling LAG %s: %s", lag->lagName, details);
	my_free(details);
	SFLAdaptor *adaptor = lagGetAdaptor(mod, lag);
	if(adaptor) {
	  HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);

	  nio->bond_master_2 = YES;
	  nio->bond_slave_2 = NO;
	  nio->changed_external = YES;

	  nio->lacp.portState.v.actorAdmin = 2;
	  nio->lacp.portState.v.actorOper = 2;
	  nio->lacp.portState.v.partnerAdmin = 2;
	  nio->lacp.portState.v.partnerOper = 2;
	  // TODO: Do all LAGs really have same actor MAC?
	  memcpy(nio->lacp.actorSystemID, mdata->actorSystemMAC, 6);
	  // TODO: might be able to learn partnerSystemID from LLDP?
	  memset(nio->lacp.partnerSystemID, 0, 6);
	  
	  if(setSwitchPort(mod, adaptor->ifIndex, YES))
	    mdata->changedSwitchPorts = YES;
	  
	  for(int cc=0; cc < strArrayN(lag->components); cc++) {
	    char *c_name = strArrayAt(lag->components, cc);
	    HSPSonicIdxMap *c_idxm = getIdxMap(mod, c_name, NO);
	    if(c_idxm) {
	      // also mark components as switchPorts, just in case they
	      // are not already marked as such. The sFlow standard
	      // requires that counter-samples are sent for both the LAG
	      // and all its components.
	      if(setSwitchPort(mod, c_idxm->osIndex, YES))
		mdata->changedSwitchPorts = YES;
	      SFLAdaptor *c_adaptor = idxMapGetAdaptor(mod, c_idxm);
	      if(c_adaptor) {
		HSPAdaptorNIO *c_nio = ADAPTOR_NIO(c_adaptor);
		c_nio->lacp.attachedAggID = adaptor->ifIndex;
		memcpy(c_nio->lacp.actorSystemID, nio->lacp.actorSystemID, 6);
		memcpy(c_nio->lacp.partnerSystemID, nio->lacp.partnerSystemID, 6);

		c_nio->bond_master_2 = NO;
		c_nio->bond_slave_2 = YES;
		c_nio->changed_external = YES;
		HSPSonicPort *c_prt = getPort(mod, c_name, NO);
		if(c_prt) {
		  c_nio->lacp.portState.v.actorAdmin = c_prt->adminUp ? 2 : 0;
		  c_nio->lacp.portState.v.actorOper = c_prt->operUp ? 2 : 0;
		  c_nio->lacp.portState.v.partnerAdmin = c_prt->adminUp ? 2 : 0; // questionable assumption
		  c_nio->lacp.portState.v.partnerOper = c_prt->operUp ? 2 : 0; // reasonable assumption
		}
	      }
	    }
	  }
	}
      }
    }
  }

  static void resetLags(EVMod *mod) {
    // just have to clear the nio bond flags from LAGs and
    // components, and remove the components list from the LAG port.
    // Any stale nio->lacp* settings will be overwritten with fresh
    // values if port is still in LAG or is involved in a LAG again
    // sometime later.
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG *lag;
    UTHASH_WALK(mdata->lagsByName, lag) {
      SFLAdaptor *adaptor = lagGetAdaptor(mod, lag);
      if(adaptor) {
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	nio->bond_master_2 = NO;
	nio->bond_slave_2 = NO;
	nio->changed_external = YES;
      }
      if(lag->components) {
	strArrayFree(lag->components);
	lag->components = NULL;
      }
    }
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
	EVDebug(mod, 1, "port removed %s", prt->portName);
	portSyncToAdaptor(mod, prt, NO);
	UTHashDel(mdata->portsByName, prt);
	if(prt->portName)
	  my_free(prt->portName);
	if(prt->oid)
	  my_free(prt->oid);
	if(prt->ifAlias)
	  my_free(prt->ifAlias);
	my_free(prt);
      }
    }
  }

   static void markIdxMaps(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicIdxMap *idxm;
    UTHASH_WALK(mdata->idxMapByName, idxm)
      idxm->mark = YES;
  }

  static void deleteMarkedIdxMaps(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicIdxMap *idxm;
    UTHASH_WALK(mdata->idxMapByName, idxm) {
      if(idxm->mark) {
	EVDebug(mod, 1, "idxmap removed %s", idxm->portName);
	UTHashDel(mdata->idxMapByName, idxm);
	UTHashDel(mdata->idxMapByOsIndex, idxm);
	if(idxm->portName)
	  my_free(idxm->portName);
	my_free(idxm);
      }
    }
  }

   static void markLags(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG *lag;
    UTHASH_WALK(mdata->lagsByName, lag)
      lag->mark = YES;
  }

  static void deleteMarkedLags(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicLAG *lag;
    UTHASH_WALK(mdata->lagsByName, lag) {
      if(lag->mark) {
	EVDebug(mod, 1, "lag removed %s", lag->lagName);
	UTHashDel(mdata->lagsByName, lag);
	UTHashDel(mdata->lagsByOsIndex, lag);
	if(lag->lagName)
	  my_free(lag->lagName);
	if(lag->components)
	  strArrayFree(lag->components);
	my_free(lag);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     collectors            __________________
    -----------------___________________________------------------
  */

  static HSPSonicCollector *getCollector(EVMod *mod, char *collectorName, int create) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicCollector search = { .collectorName = collectorName };
    HSPSonicCollector *coll = UTHashGet(mdata->collectors, &search);
    if(coll == NULL
       && create) {
      coll = (HSPSonicCollector *)my_calloc(sizeof(HSPSonicCollector));
      coll->collectorName = my_strdup(collectorName);
      coll->port = SFL_DEFAULT_COLLECTOR_PORT;
      UTHashAdd(mdata->collectors, coll);
    }
    return coll;
  }

  static void markCollectors(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicCollector *coll;
    UTHASH_WALK(mdata->collectors, coll)
      coll->mark = YES;
  }

  static int deleteMarkedCollectors(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicCollector *coll;
    int nDeleted = 0;
    UTHASH_WALK(mdata->collectors, coll) {
      if(coll->mark) {
	EVDebug(mod, 1, "collector removed %s", coll->collectorName);
	UTHashDel(mdata->collectors, coll);
        if(coll->collectorName)
	  my_free(coll->collectorName);
	if(coll->ipStr)
	  my_free(coll->ipStr);
	if(coll->deviceName)
	  my_free(coll->deviceName);
	my_free(coll);
	nDeleted++;
      }
    }
    return nDeleted;
  }

  /*_________________---------------------------__________________
    _________________   get/add db instances    __________________
    -----------------___________________________------------------
  */

  static HSPSonicDBClient *getDB(EVMod *mod, char *dbInstance) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicDBClient search = { .dbInstance = dbInstance };
    return UTHashGet(mdata->dbInstances, &search);
  }

#if 0
  static void freeDB(HSPSonicDBClient *db) {
    my_free(db->dbInstance);
    UTStrBuf_free(db->replyBuf);
    my_free(db->hostname);
    my_free(db->unixSocketPath);
    my_free(db->passPath);
    if(db->ctx) {
      redisAsyncFree(db->ctx);
      db->ctx = NULL;
    }
    my_free(db);
  }
#endif
  
  static HSPSonicDBClient *addDB(EVMod *mod, char *dbInstance, char *hostname, int port, char *unixSocketPath, char *passPath) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "addDB: %s hostname=%s, port=%d, unixSocketPath=%s passPath=%s", dbInstance, hostname, port, unixSocketPath, passPath);
    HSPSonicDBClient *db = getDB(mod, dbInstance);
    if(db == NULL) {
      db = (HSPSonicDBClient *)my_calloc(sizeof(HSPSonicDBClient));
      db->dbInstance = my_strdup(dbInstance);
      db->replyBuf = UTStrBuf_new();
      db->mod = mod;
      UTHashAdd(mdata->dbInstances, db);
    }
    // allow some parameters to change if we are reading the config again
    // (e.g. because there was a connection or authentication failure)
    db->port = port;
    setStr(&db->hostname, hostname);
    setStr(&db->unixSocketPath, unixSocketPath);
    setStr(&db->passPath, passPath);
    // the socket will be opened later
    return db;
  }

  /*_________________---------------------------__________________
    _________________   get/add db tables       __________________
    -----------------___________________________------------------
  */

  static HSPSonicDBTable *getDBTable(EVMod *mod, char *dbTable) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicDBTable search = { .dbTable = dbTable };
    return UTHashGet(mdata->dbTables, &search);
  }

  static HSPSonicDBTable *addDBTable(EVMod *mod, char *dbInstance, char *dbTable, int id, char *sep) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbTab: %s instance=%s, id=%d", dbTable, dbInstance, id);
    HSPSonicDBTable search = { .dbTable = dbTable };
    HSPSonicDBTable *dbTab = UTHashGet(mdata->dbTables, &search);
    if(dbTab == NULL) {
      dbTab = (HSPSonicDBTable *)my_calloc(sizeof(HSPSonicDBTable));
      dbTab->dbTable = my_strdup(dbTable);
      dbTab->id = id;
      dbTab->dbClient = getDB(mod, dbInstance);
      dbTab->separator = my_strdup(sep);
      UTHashAdd(mdata->dbTables, dbTab);
   }
    return dbTab;
  }

  static void freeDBTable(HSPSonicDBTable *dbTab) {
    my_free(dbTab->dbTable);
    my_free(dbTab->separator);
    my_free(dbTab);
  }

  /*_________________---------------------------__________________
    _________________    loadDBConfig           __________________
    -----------------___________________________------------------
  */

  static void resetDBConfig(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicDBTable *dbTab;
    UTHASH_WALK(mdata->dbTables, dbTab) {
      freeDBTable(dbTab);
    }
    UTHashReset(mdata->dbTables);
    // we let the client instances represent
    // all instances seen, so do not touch
    // mdata->dbInstances here. The socket
    // will be closed if the connection is closed.
    // See db_cleanupCB.
  }

  static void loadDBConfig(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    char *fname = sp->sonic.dbconfig ?: HSP_SONIC_DB_JSON;
    EVDebug(mod, 1, "loadDBConfig from %s", fname);
    resetDBConfig(mod);
    FILE *fjson = fopen(fname, "r");
    if(fjson) {
      UTStrBuf *sbuf = UTStrBuf_new();
      char lineBuf[1024];
      int truncated = NO;
      while(my_readline(fjson, lineBuf, 1024, &truncated) != EOF) {
	if(truncated)
	  EVDebug(mod, 1, "ignoring unexpected long line in %s: %s", fname, lineBuf);
	else {
	  UTStrBuf_append(sbuf, lineBuf);
	  UTStrBuf_append(sbuf, "\n");
	}
      }
      const char *errm;
      cJSON *dbconfig = cJSON_ParseWithOpts(UTSTRBUF_STR(sbuf), &errm, YES);
      if(dbconfig == NULL)
	EVDebug(mod, 1, "loadDBConfig JSON parser failed: %s", errm);
      else {
	cJSON *instances = cJSON_GetObjectItem(dbconfig, "INSTANCES");
	cJSON *databases = cJSON_GetObjectItem(dbconfig, "DATABASES");
	for(cJSON *inst = instances->child; inst; inst = inst->next) {
	  cJSON *hostname = cJSON_GetObjectItem(inst, "hostname");
	  cJSON *port = cJSON_GetObjectItem(inst, "port");
	  cJSON *passPath = cJSON_GetObjectItem(inst, "password_path");
	  cJSON *unixSock = cJSON_GetObjectItem(inst, "unix_socket_path");
	  // cJSON *persist = cJSON_GetObjectItem(inst, "persistence_for_warm_boot");
	  addDB(mod,
		inst->string,
		hostname ? hostname->valuestring : NULL,
		port ? port->valueint : 0,
		unixSock ? unixSock->valuestring : NULL,
		passPath ? passPath->valuestring : NULL);
	}
	for(cJSON *dbTab = databases->child; dbTab; dbTab = dbTab->next) {
	  cJSON *id = cJSON_GetObjectItem(dbTab, "id");
	  cJSON *inst = cJSON_GetObjectItem(dbTab, "instance");
	  cJSON *sep = cJSON_GetObjectItem(dbTab, "separator");
	  if(id && inst) {
	    addDBTable(mod, inst->valuestring, dbTab->string, id->valueint, sep->valuestring);
	  }
	}
      }
      // clean up
      cJSON_Delete(dbconfig);
      UTStrBuf_free(sbuf);
      fclose(fjson);
    }
  }

  /*_________________---------------------------__________________
    _________________    addEventClients        __________________
    -----------------___________________________------------------
  */

  static void addEventClients(EVMod *mod) {
    // add separate client connections for events.
    HSPSonicDBTable *configTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(configTab
       && configTab->dbClient) {
      configTab->evtClient = addDB(mod, HSP_SONIC_DB_CONFIG_NAME HSP_SONIC_DB_EVENT_SUFFIX,
				   configTab->dbClient->hostname,
				   configTab->dbClient->port,
				   configTab->dbClient->unixSocketPath,
				   configTab->dbClient->passPath);
    }
    HSPSonicDBTable *stateTab = getDBTable(mod, HSP_SONIC_DB_STATE_NAME);
    if(stateTab
       && stateTab->dbClient) {
      stateTab->evtClient = addDB(mod, HSP_SONIC_DB_STATE_NAME HSP_SONIC_DB_EVENT_SUFFIX,
				  stateTab->dbClient->hostname,
				  stateTab->dbClient->port,
				  stateTab->dbClient->unixSocketPath,
				  stateTab->dbClient->passPath);
    }
  }

  /*_________________---------------------------__________________
    _________________      redis adaptor        __________________
    -----------------___________________________------------------
  */

  static void db_readCB(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)magic;
    db->reads++;
    redisAsyncHandleRead(db->ctx);
  }

  static void db_addWriteCB(void *magic) {
    HSPSonicDBClient *db = (HSPSonicDBClient *)magic;
    // We could modify evbus to regulate writes, but
    // since the write direction consists only of short
    // queries we just assume it's OK to go ahead.
    // (If there were any danger of blocking for more than
    // a second or so then we could set the file descriptor
    // to non-blocking mode with fcntl and looks for an
    // EWOULDBLOCK error.)
    db->writes++;
    redisAsyncHandleWrite(db->ctx);
  }

  static void db_cleanupCB(void *magic) {
    HSPSonicDBClient *db = (HSPSonicDBClient *)magic;
    EVDebug(db->mod, 1, "db_cleanupCB dbSock=%p", db->sock);
    if(db->sock) {
      // set flag to prevent actual closing of file-descriptor.
      // It belongs to libhiredis and should be closed there.
      EVSocketClose(db->mod, db->sock, NO);
      db->sock = NULL;
    }
    // dedided not to free client here. Would have to find and
    // remove it from mdata->dbInstances too. Easier to just
    // let the dbInstances represent all instances seen. If
    // any are not longer referenced, then that's not a big
    // problem, provided the socket is closed.
  }

  /*_________________---------------------------__________________
    _________________    db_connect             __________________
    -----------------___________________________------------------
  */

  static bool db_allConnected(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicDBClient *db;
    UTHASH_WALK(mdata->dbInstances, db) {
      if(!db->connected)
	return NO;
    }
    return YES;
  }

  static void db_connectCB(const redisAsyncContext *ctx, int status) {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)db->mod->data;
    EVDebug(db->mod, 1, "db_connectCB: status= %d", status);
    if(status == REDIS_OK) {
      db->connected = YES;
      if(db_allConnected(db->mod)) {
	setSonicState(db->mod, HSP_SONIC_STATE_WAIT_READY);
	mdata->waitReadyStart = mdata->pollBus->now.tv_sec;
      }
    }
  }

  static void db_disconnectCB(const redisAsyncContext *ctx, int status) {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)db->mod->data;
    EVDebug(db->mod, 1, "db_disconnectCB: status= %d", status);
    db->connected = NO;
    mdata->system_ready = NO;
    setSonicState(db->mod, HSP_SONIC_STATE_CONNECT);
  }

  static bool db_connectClient(EVMod *mod, HSPSonicDBClient *db) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisAsyncContext *ctx = NULL;
    if(sp->sonic.unixsock
       && db->unixSocketPath) {
      EVDebug(mod, 1, "db_connectClient %s = %s", db->dbInstance, db->unixSocketPath);
      ctx = redisAsyncConnectUnix(db->unixSocketPath);
    }
    else if(db->hostname
	    && db->port) {
      EVDebug(mod, 1, "db_connectClient %s = %s:%d", db->dbInstance, db->hostname, db->port);
      ctx = redisAsyncConnect(db->hostname, db->port);
    }
    else {
      EVDebug(mod, 1, "db_connectClient: missing unixsock or host:port");
      return NO;
    }
    int fd = ctx ? ctx->c.fd : -1;
    if(ctx
       && fd >= 0
       && ctx->err == 0) {
      EVDebug(mod, 1, "db_connectClient succeeded: fd=%d", fd);
      redisAsyncSetConnectCallback(ctx, db_connectCB);
      redisAsyncSetDisconnectCallback(ctx, db_disconnectCB);
      db->sock = EVBusAddSocket(mod, mdata->pollBus, fd, db_readCB, db /* magic */);
      // db->ev.addRead = db_addReadCB; // EVBus always ready to read
      // db->ev.delRead = db_delReadCB; // no-op
      ctx->ev.addWrite = db_addWriteCB;
      // db->ev.delWrite = db_delWriteCB; // no-op
      ctx->ev.cleanup = db_cleanupCB;
      ctx->ev.data = db;
      db->ctx = ctx;
      return YES;
    }
    char *errm = ctx ? ctx->errstr : "ctx=NULL";
    EVDebug(mod, 1, "db_connectClient failed (fd=%d) err=%s", fd, errm);
    if(ctx) {
      EVDebug(mod, 1, "Connection failed but context still returned - calling redisAsyncFree(ctx)");
      redisAsyncFree(ctx);
    }
    return NO;
  }

  static void db_connect(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // try to connect all db instances
    HSPSonicDBClient *db;
    UTHASH_WALK(mdata->dbInstances, db) {
      if(!db->connected) {
	if(db_connectClient(mod, db)) {
	  // async connect requires something to do before it will complete,
	  // so go ahead and issue the first query.  Use a neutral "no-op"
	  // and save the actual discovery queries for the next step once
	  // everything is connected.
	  if(db->passPath
	     && db_auth(mod, db)) {
	    EVDebug(mod, 1, "db_connect(%s): auth sent", db->dbInstance);
	  }
	  else {
	    db_ping(mod, db);
	  EVDebug(mod, 1, "db_connect(%s): ping sent", db->dbInstance);
	  }
	}
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    db_select              __________________
    -----------------___________________________------------------
  */

  static void db_selectCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    redisReply *reply = (redisReply *)magic;
    EVDebug(db->mod, 1, "db_selectCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
  }

  static bool db_select(HSPSonicDBClient *db, int dbNo) {
    if(dbNo == db->dbNo)
      return YES;
    EVDebug(db->mod, 1, "db_select(%u)", dbNo);
    int status = redisAsyncCommand(db->ctx, db_selectCB, NULL /*privData*/, "select %u", dbNo);
    EVDebug(db->mod, 1, "db_select returned %d", status);
    if(status == REDIS_OK) {
      db->dbNo = dbNo;
      return YES;
    }
    return NO;
  }

  static bool db_selectTab(HSPSonicDBTable *dbTab) {
    return(dbTab
	   && dbTab->dbClient
	   && db_select(dbTab->dbClient, dbTab->id));
  }

  static HSPSonicDBClient *db_selectClient(EVMod *mod, char *dbTable) {
    // return the dbInstance, pointed to this table id
    HSPSonicDBTable *dbTab = getDBTable(mod, dbTable);
    if(dbTab == NULL)
      return NULL;
    return db_selectTab(dbTab) ? dbTab->dbClient : NULL;
  }


  /*_________________---------------------------__________________
    _________________         db_auth           __________________
    -----------------___________________________------------------
  */

  static void db_authCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    redisReply *reply = (redisReply *)magic;
    EVDebug(mod, 1, "db_authCB: %s reply=%s",
	    db->dbInstance,
	    db_replyStr(reply, db->replyBuf, YES));
    if(reply
       && reply->type == REDIS_REPLY_ERROR) {
      EVDebug(mod, 1, "db_authCB ERROR calling redisAsyncFree() to disconnect");
      redisAsyncFree(db->ctx);
      EVDebug(mod, 1, "resetting state to CONNECT");
      setSonicState(mod, HSP_SONIC_STATE_CONNECT);
    }
  }

  static bool db_auth(EVMod *mod, HSPSonicDBClient *db) {
    EVDebug(mod, 1, "db_auth: %s", db->dbInstance);
    char dbPwBuf[256];
    FILE *fp = fopen(db->passPath, "r");
    if(fp) {
      char *dbPasswd = fgets(dbPwBuf, 256, fp);
      fclose(fp);
      if(dbPasswd) {
	int status = redisAsyncCommand(db->ctx, db_authCB, NULL /*privData*/, "AUTH %s", dbPasswd);
	EVDebug(mod, 1, "db_auth returned %d", status);
	return YES;
      }
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________         db_ping           __________________
    -----------------___________________________------------------
  */

  static void db_pingCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    redisReply *reply = (redisReply *)magic;
    EVDebug(db->mod, 1, "db_pingCB: %s reply=%s",
	    db->dbInstance,
	    db_replyStr(reply, db->replyBuf, YES));
  }

  static void db_ping(EVMod *mod, HSPSonicDBClient *db) {
    EVDebug(mod, 1, "db_ping: %s", db->dbInstance);
    int status = redisAsyncCommand(db->ctx, db_pingCB, NULL /*privData*/, "ping");
    EVDebug(mod, 1, "db_ping returned %d", status);
  }

  /*_________________---------------------------__________________
    _________________      db_getMeta           __________________
    -----------------___________________________------------------
  */

  static void db_metaCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    EVDebug(mod, 1, "db_metaCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;

    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 1, "db_metaCB: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_MAC)
	     && c_val->type == REDIS_REPLY_STRING
	     && c_val->str) {
	    bool parseOK = (hexToBinary((u_char *)c_val->str, mdata->actorSystemMAC, 6) == 6);
	    EVDebug(mod, 1, "db_metaCB: system MAC: %s parsedOK=%s", c_val->str, parseOK ? "YES":"NO");
	  }
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_LOCALAS))
	    mdata->localAS = db_getU32(c_val);
	}
      }
    }
  }

  static void db_getMeta(EVMod *mod) {
    EVDebug(mod, 1, "db_getMeta");
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_CONFIG_NAME); 
    if(db) {
      int status = redisAsyncCommand(db->ctx, db_metaCB, NULL /*privData*/, "HGETALL DEVICE_METADATA|localhost");
      EVDebug(mod, 1, "db_getMeta returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________       setPortAlias        __________________
    -----------------___________________________------------------

    The SONiC port names may not match those of the corresponding Linux netdevs, so
    allow this module to set the IFLA_IFALIAS field in hsflowd's adaptor object as we
    discover the mapping from the SONiC ports to the Linux ifIndex numbers.
  */

  static bool setPortAlias(EVMod *mod, HSPSonicPort *prt, bool setIt) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    if(sp->sonic.setIfAlias) {
      HSPSonicIdxMap *idxm = getIdxMap(mod, prt->portName, NO);
      if(idxm) {
	SFLAdaptor *adaptor = idxMapGetAdaptor(mod, idxm);
	if(adaptor) {
	  if(setAdaptorAlias(sp,
			     adaptor,
			     setIt ? prt->portName : NULL,
			     "MOD_SONIC")) {
	    mdata->changedPortAlias = YES;
	    return YES;
	  }
	}
      }
    }
    return NO;
  }

  /*_________________-------------------------------__________________
    _________________    setPortSelectionPriority   __________________
    -----------------_______________________________------------------

    Set selection priority to influence the automatic agent-address selection so that
    the last tiebreaker is driven by the SONiC ifIndex rather than the Linux ifIndex (osIndex).
    This should stabilize the selection across a warm boot, where the Linux ifIndex numbers
    can end up in a different order.  This will not override other settings based on
    IP address class etc. -- just puts a thumb on the scale for the case where two
    candidates are otherwise tied.
  */
  
  static bool setPortSelectionPriority(EVMod *mod, HSPSonicIdxMap *idxm, bool setIt) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *adaptor = idxMapGetAdaptor(mod, idxm);
    if(adaptor) {
      if(setAdaptorSelectionPriority(sp,
				     adaptor,
				     setIt ? idxm->ifIndex : 0,
				     "MOD_SONIC")) {
	mdata->changedPortPriority = YES;
	return YES;
      }
    }
    return NO;
  }
  
  /*_________________---------------------------__________________
    _________________     setSwitchPort         __________________
    -----------------___________________________------------------
    Telling the underlying adaptor that it is a switch port triggers
    the setup of an sFlow poller, which in turn means we get called back
    for the state+counters for this port.
  */

  static bool setSwitchPort(EVMod *mod, uint32_t osIndex, bool flag) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    SFLAdaptor *adaptor = adaptorByIndex(sp, osIndex);
    if(adaptor) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      if(nio
	 && (nio->switchPort != flag)) {
	EVDebug(mod, 1, "setting adaptor %s switchPort flag from %u to %u",
		adaptor->deviceName,
		nio->switchPort,
		flag);
	nio->switchPort = flag;
	mdata->changedSwitchPorts = YES;
	return YES;
      }
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________  portSyncToAdaptor        __________________
    -----------------___________________________------------------
  */

  static bool portSyncToAdaptor(EVMod *mod, HSPSonicPort *prt, bool sync) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    bool changed = NO;
    HSPSonicIdxMap *idxm = getIdxMap(mod, prt->portName, NO);
    if(idxm) {
      SFLAdaptor *adaptor = idxMapGetAdaptor(mod, idxm);
      if(adaptor) {
	if(setPortAlias(mod, prt, sync))
	  changed = YES;
	if(setPortSelectionPriority(mod, idxm, sync))
	  changed = YES;
	if(setSwitchPort(mod, idxm->osIndex, sync))
	  changed = YES;
	// It's OK to set ifSpeed because we turned off the other
	// ways that readInterfaces() might use to discover it, and
	// it doesn't check it when considering whether an interface
	// has changed. However it might be cleaner to repair this
	// in the counter-samples (and for portChannels too).
	if(setAdaptorSpeed(sp, adaptor, prt->ifSpeed, "MOD_SONIC"))
	  changed = YES;
	if(changed) {
	  EVDebug(mod, 2, "portSyncToAdaptor: %s %s adaptor(ifIndex=%u)",
		  prt->portName,
		  sync ? "synced to" : "unsynced from",
		  adaptor->ifIndex);
	}
      }
    }
    // return true if anything changed
    return changed;
  }

  /*_________________---------------------------__________________
    _________________  syncPortsToAdaptors      __________________
    -----------------___________________________------------------
  */

  static bool syncPortsToAdaptors(EVMod *mod, bool sync) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt;
    bool changed = NO;
    UTHASH_WALK(mdata->portsByName, prt) {
      if(portSyncToAdaptor(mod, prt, sync))
	changed = YES;
    }
    // return true if anything changed
    return changed;
  }

  /*_________________---------------------------__________________
    _________________    db_getifIndexMap       __________________
    -----------------___________________________------------------
  */

  static void db_ifIndexMapCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    HSPSonicIdxMap *idxm = (HSPSonicIdxMap *)req_magic;
    EVDebug(mod, 1, "db_ifIndexMapCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // stay in the same state - will retry
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      uint32_t ifIndex = 0;
      uint32_t osIndex = 0;
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 1, "db_ifIndexMapCB: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFINDEX))
	    ifIndex = db_getU32(c_val);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFINDEX_OS))
	    osIndex = db_getU32(c_val);
	  if(ifIndex
	     && osIndex) {
	    // valid entry
	    EVDebug(mod, 1, "ifIndexMap %s ifIndex=%u - osIndex=%u",
		    idxm->portName,
		    ifIndex,
		    osIndex);
	    // see if we have a port for this one
	    // (we may well not - it could just be a VLAN interface)
	    HSPSonicPort *prt = getPort(mod, idxm->portName, NO);
	    if(prt
	       && prt->oidChanged) {
	      signalCounterDiscontinuity(mod, idxm);
	    }
	    // update ifIndex
	    if(idxm->ifIndex != ifIndex) {
	      if(idxm->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED) {
		EVDebug(mod, 1, "ifIndex for port %s changed from %u to %u",
			idxm->portName,
			idxm->ifIndex,
			ifIndex);
		signalCounterDiscontinuity(mod, idxm);
		mdata->changedPortIndex = YES; // triggers rediscovery
	      }
	      idxm->ifIndex = ifIndex;
	    }
	    // update osIndex
	    if(idxm->osIndex != osIndex) {
	      if(idxm->osIndex != HSP_SONIC_IFINDEX_UNDEFINED) {
		EVDebug(mod, 1, "osIndex for port %s changed from %u to %u",
			idxm->portName,
			idxm->osIndex,
			osIndex);
		signalCounterDiscontinuity(mod, idxm);
		UTHashDel(mdata->idxMapByOsIndex, idxm);
	      }
	      idxm->osIndex = osIndex;
	      UTHashAdd(mdata->idxMapByOsIndex, idxm);
	      if(prt) {
		// tell hsflowd we want counters for this one - this
		// would happen anyway in RUN state but I don't think
		// there is any harm in propagating it here too. It
		// will allow us to spotlight anything that *does*
		// get changed after we are in the RUN state, which
		// should be unusual.
		portSyncToAdaptor(mod, prt, YES);
	      }
	    }
	    // If we have a port and it saw a change then make sure
	    // we signal a discontinuity for the new osIndex too, in
	    // case it is different.
	    if(prt
	       && prt->oidChanged) {
	      signalCounterDiscontinuity(mod, idxm);
	      // and now we can rearm this flag
	      prt->oidChanged = NO;
	    }
	  }
	}
      }
    }
    // there may be more to map
    //    mapPorts(mod);
    getNextIfIndexMap(mod);
  }

  static void db_getIfIndexMap(EVMod *mod, HSPSonicIdxMap *idxm) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_STATE_NAME);
    if(db_selectTab(dbTab)) {
      EVDebug(mod, 1, "db_getIfIndexMap(%s)", idxm->portName);
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_ifIndexMapCB,
				     idxm,
				     "HGETALL PORT_INDEX_TABLE%s%s", dbTab->separator, idxm->portName);
      EVDebug(mod, 1, "db_getIfIndexMap(%s) returned %d", idxm->portName, status);
    }
  }

  static bool getNextIfIndexMap(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicIdxMap *idxm = UTHashNext(mdata->idxMapByName, &mdata->idxMapCursor);
    if(idxm) {
      db_getIfIndexMap(mod, idxm);
      return YES;
    }
    else {
      setSonicState(mod, HSP_SONIC_STATE_DISCOVER_LAGS);
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________  db_getifIndexMapNames    __________________
    -----------------___________________________------------------
  */

  static void db_ifIndexMapNamesCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    char *sep = (char *)req_magic;
    EVDebug(mod, 1, "db_ifIndexMapNamesCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // stay in the same state - will retry
    markIdxMaps(mod);
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0) {
      for(int ii = 0; ii < reply->elements; ii++) {
	redisReply *elem = reply->element[ii];
	if(elem->type == REDIS_REPLY_STRING) {
	  // expect something like "PORT_INDEX_TABLE|Ethernet7"
	  char buf[HSP_SONIC_MAX_PORTNAME_LEN];
	  char *portName = keyToken(mod, elem->str, sep, 2, buf, HSP_SONIC_MAX_PORTNAME_LEN);
	  if(portName) {
	    HSPSonicIdxMap *idxm = getIdxMap(mod, portName, YES);
	    idxm->mark = NO;
	  }
	}
      }
    }
    deleteMarkedIdxMaps(mod);
    // kick off a walk of this HT to fill in the details
    mdata->idxMapCursor = 0;
    getNextIfIndexMap(mod);
  }

  static void db_getIfIndexMapNames(EVMod *mod) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_STATE_NAME);
    if(db_selectTab(dbTab)) {
      EVDebug(mod, 1, "db_getIfIndexMapNames");
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_ifIndexMapNamesCB,
				     dbTab->separator,
				     "KEYS PORT_INDEX_TABLE%s*", dbTab->separator);
      EVDebug(mod, 1, "db_getIfIndexMapNames returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________      db_getPortNames      __________________
    -----------------___________________________------------------
  */

  static void signalCounterDiscontinuity(EVMod *mod, HSPSonicIdxMap *idxm) {
    SFLAdaptor *adaptor = idxMapGetAdaptor(mod, idxm);
    if(adaptor) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      if(nio
	 && nio->poller)
	sfl_poller_resetCountersSeqNo(nio->poller);
    }
  }

  static void db_portNamesCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    EVDebug(mod, 1, "db_portNamesCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; //  stay in same state and try again next tick
    markPorts(mod);
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *p_name = reply->element[ii];
	redisReply *p_oid = reply->element[ii + 1];
	if(p_name->type == REDIS_REPLY_STRING
	   && p_oid->type == REDIS_REPLY_STRING) {
	  HSPSonicPort *prt = getPort(mod, p_name->str, NO);
	  if(prt == NULL) {
	    // add with OID
	    prt = getPort(mod, p_name->str, YES);
	    prt->oid = my_strdup(p_oid->str);
	    EVDebug(mod, 1, "db_portNamesCB: new port %s -> %s", prt->portName, prt->oid);
	  }
	  else if(!my_strequal(prt->oid, p_oid->str)) {
	    // OID changed under our feet
	    EVDebug(mod, 1, "db_portNamesCB: port %s oid %s -> %s",
		    prt->portName,
		    prt->oid ?: "NULL",
		    p_oid->str ?: "NULL");
	    setStr(&prt->oid, p_oid->str);
	    prt->oidChanged = YES;
	  }	  
	  prt->mark = NO;
	}
      }
    }
    deleteMarkedPorts(mod);

    // now trigger a walk of this HT to fill in the details
    mdata->portsCursor = 0;
    getNextPortState(mod);
  }

  static void db_getPortNames(EVMod *mod) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_COUNTERS_NAME);
    if(db) {
      EVDebug(mod, 1, "db_getPortNames()");
      int status = redisAsyncCommand(db->ctx, db_portNamesCB, NULL, "HGETALL COUNTERS_PORT_NAME_MAP");
      EVDebug(mod, 1, "db_getPortNames() returned %d", status);
    }
  }


  /*_________________---------------------------__________________
    _________________      db_getPortState      __________________
    -----------------___________________________------------------
  */

  static void db_portStateCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;
    EVDebug(mod, 1, "db_portStateCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // will skip this port and go to the next
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 1, "db_portStateCB: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));
	  // This "index" field is neither ifIndex nor osIndex, so ignore it.
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFSPEED))
	    prt->ifSpeed = db_getU64(c_val) * HSP_SONIC_FIELD_IFSPEED_UNITS;
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFALIAS)
	     && !my_strequal(prt->ifAlias, c_val->str)) {
	    if(prt->ifAlias)
	      my_free(prt->ifAlias);
	    prt->ifAlias = my_strdup(c_val->str);
	  }
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFADMINSTATUS))
	    prt->adminUp = my_strequal(c_val->str, "up");
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOPERSTATUS))
	    prt->operUp = my_strequal(c_val->str, "up");
	}
      }
    }
    getNextPortState(mod);
  }

  static void db_getPortState(EVMod *mod, HSPSonicPort *prt) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_APPL_NAME);
    if(db) {
      EVDebug(mod, 1, "db_getPortState()");
      int status = redisAsyncCommand(db->ctx, db_portStateCB, prt, "HGETALL PORT_TABLE:%s", prt->portName);
      EVDebug(mod, 1, "db_getPortState returned %d", status);
    }
  }

  static bool getNextPortState(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt = UTHashNext(mdata->portsByName, &mdata->portsCursor);
    if(prt) {
      db_getPortState(mod, prt);
      return YES;
    }
    else {
      // advance from DISCOVER to DISCOVER_MAPPING, but if we are in, say, the RUN
      // state then don't do anything here. We are probably just polling counters.
      if(mdata->state == HSP_SONIC_STATE_DISCOVER)
	setSonicState(mod, HSP_SONIC_STATE_DISCOVER_MAPPING);
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________      db_getPortCounters   __________________
    -----------------___________________________------------------
  */

  static void db_portCountersCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;

    EVDebug(mod, 1, "portCounters: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // will skip this poll
    memset(&prt->ctrs, 0, sizeof(prt->ctrs));
    memset(&prt->et_ctrs, 0, sizeof(prt->et_ctrs));
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 2, "portCounters: %s %s=%s",
		  prt->portName,
		  c_name->str,
		  db_replyStr(c_val, db->replyBuf, YES));

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

	  prt->et_ctrs.operStatus = prt->operUp;
	  prt->et_ctrs.adminStatus = prt->adminUp;
	}
      }
    }

    // sumbit counters for deltas to be accumulated
    SFLAdaptor *adaptor = portGetAdaptor(mod, prt);
    if(adaptor) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      if(nio) {
	nio->et_found = HSP_ETCTR_MC_IN
	  | HSP_ETCTR_MC_OUT
	  | HSP_ETCTR_BC_IN
	  | HSP_ETCTR_BC_OUT
	  | HSP_ETCTR_UNKN
	  | HSP_ETCTR_OPER
	  | HSP_ETCTR_ADMIN;
	accumulateNioCounters(sp, adaptor, &prt->ctrs, &prt->et_ctrs);
	nio->last_update = mdata->pollBus->now.tv_sec;
      }
    }
  }

  static void db_getPortCounters(EVMod *mod, HSPSonicPort *prt) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_COUNTERS_NAME);
    if(db) {
      EVDebug(mod, 1, "getPortCounters(%s) oid=%s", prt->portName, prt->oid ?: "<none>");
      if(prt->oid) {
	int status = redisAsyncCommand(db->ctx, db_portCountersCB, prt, "HGETALL COUNTERS:%s", prt->oid);
	EVDebug(mod, 1, "getPortCounters() returned %d", status);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________      db_getLagInfo        __________________
    -----------------___________________________------------------
  */

  static void db_getLagInfoCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    char *sep = (char *)req_magic;

    EVDebug(mod, 1, "getLagInfoCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      goto LAG_DISCOVERY_DONE;
    markLags(mod);
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0) {
      resetLags(mod);
      for(int ii = 0; ii < reply->elements; ii++) {
	redisReply *elem = reply->element[ii];
	if(elem->type == REDIS_REPLY_STRING) {
	  // expect e.g.: "PORTCHANNEL_MEMBER|PortChannel502|Ethernet60"
	  char buf_tab[HSP_SONIC_MAX_PORTNAME_LEN];
	  char buf_lag[HSP_SONIC_MAX_PORTNAME_LEN];
	  char buf_mem[HSP_SONIC_MAX_PORTNAME_LEN];
	  char *tabName = keyToken(mod, elem->str, sep, 1, buf_tab, HSP_SONIC_MAX_PORTNAME_LEN);
	  char *lagName = keyToken(mod, elem->str, sep, 2, buf_lag, HSP_SONIC_MAX_PORTNAME_LEN);
	  char *memName = keyToken(mod, elem->str, sep, 3, buf_mem, HSP_SONIC_MAX_PORTNAME_LEN);
	  if(my_strequal(tabName, "PORTCHANNEL_MEMBER")) {
	    HSPSonicLAG *lag = getLAG(mod, lagName, YES);
	    // first check the PORT_INDEX_TABLE in case there is an entry there
	    HSPSonicIdxMap *idxm = getIdxMap(mod, lagName, NO);
	    if(idxm) {
	      EVDebug(mod, 1, "found lag %s in PORT_INDEX_TABLE: ifIndex=%u, osIndex=%u",
		      lagName,
		      idxm->ifIndex,
		      idxm->osIndex);
	      lag->ifIndex = idxm->ifIndex;
	      lag->osIndex = idxm->osIndex;
	    }
	    // but if not found we can generate from regex and base-index convention
	    if(lag->ifIndex == HSP_SONIC_IFINDEX_UNDEFINED
	       && mdata->portChannelPattern) {
	      int lagNo = -1;
	      if(UTRegexExtractInt(mdata->portChannelPattern, lagName, 1, &lagNo, NULL, NULL)) {
		lag->ifIndex = mdata->portChannelBaseIndex + lagNo;
		EVDebug(mod, 1, "Extracted LAG number %u from \"%s\" => inferring SONiC ifIndex=%u",
			lagNo,
			lagName,
			lag->ifIndex);
	      }
	    }
	    // may still need the osIndex
	    if(lag->osIndex == HSP_SONIC_IFINDEX_UNDEFINED) {
	      SFLAdaptor *adaptor = lagGetAdaptor(mod, lag);
	      if(adaptor) {
		lag->osIndex = adaptor->ifIndex;
	      }
	    }
	    if(lag->osIndex != HSP_SONIC_IFINDEX_UNDEFINED) {
	      EVDebug(mod, 1, "LAG %s has Linux osIndex=%u", lagName, lag->osIndex);
	      // schedule counter-samples for the LAG
	      setSwitchPort(mod, lag->osIndex, YES);
	      UTHashAdd(mdata->lagsByOsIndex, lag);
	    }
	    
	    if(lag->components == NULL)
	      lag->components = strArrayNew();
	    if(memName) {
	      EVDebug(mod, 1, "getLagInfoCB: port %s is member of port-channel %s", memName, lagName);
	      strArrayAdd(lag->components, memName);
	    }
	  }
	}
      }
      deleteMarkedLags(mod);
      printLags(mod);
      compileLags(mod);
    }
  LAG_DISCOVERY_DONE:
    setSonicState(mod, HSP_SONIC_STATE_SYNC_CONFIG);
  }

  static void db_getLagInfo(EVMod *mod) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db_selectTab(dbTab)) {
      EVDebug(mod, 1, "getLagInfo()");
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_getLagInfoCB,
				     dbTab->separator,
				     "KEYS PORTCHANNEL_MEMBER%s*", dbTab->separator);
      EVDebug(mod, 1, "getLagInfo() returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________    db_getsFlowGlobal      __________________
    -----------------___________________________------------------
  */

  static void db_getsFlowGlobalCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;

    EVDebug(mod, 1, "getSflowGlobalCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // will stay in same state (e,g. HSP_SONIC_STATE_CONNECTED)
    // first extract the latest settings
    bool sflow_enable = NO;
    char *sflow_agent = NULL;
    uint32_t sflow_polling = HSP_SONIC_DEFAULT_POLLING_INTERVAL;
    uint32_t sflow_headerBytes = SFL_DEFAULT_HEADER_SIZE;
    uint32_t sflow_dropLimit = 0;
    char *sflow_direction = NULL;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *f_name = reply->element[ii];
	redisReply *f_val = reply->element[ii + 1];
	if(f_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 1, "sflow: %s=%s", f_name->str, db_replyStr(f_val, db->replyBuf, YES));

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_ADMIN_STATE))
	    sflow_enable = my_strequal(f_val->str, "up"); // note: was "enable" before

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_AGENT))
	    sflow_agent = f_val->str;

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_POLLING))
	    sflow_polling = db_getU32(f_val);

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_HEADER_BYTES))
	    sflow_headerBytes = db_getU32(f_val);

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_DROP_MONITOR_LIMIT)) {
	    sflow_dropLimit = db_getU32(f_val);
	    mdata->sflow_dropLimit_set = YES;
	  }

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_SAMPLE_DIRECTION))
	    sflow_direction = f_val->str;
	}
      }
    }
    // now see if there are any changes. 
    if(sflow_enable != mdata->sflow_enable) {
      EVDebug(mod, 1, "sflow_enable %u -> %u", mdata->sflow_enable, sflow_enable);
      mdata->sflow_enable = sflow_enable;
    }
    // The sflow_agent entry will disappear if it is deleted from the config, so sflow_agent
    // may still be NULL here:
    if(!my_strequal(sflow_agent, mdata->sflow_agent)) {
      EVDebug(mod, 1, "sflow_agent %s -> %s",
	      mdata->sflow_agent ?: "<not set>",
	      sflow_agent ?: "<not set>");
      setStr(&mdata->sflow_agent, sflow_agent);
    }
    if(sflow_polling != mdata->sflow_polling) {
      EVDebug(mod, 1, "sflow_polling %u -> %u", mdata->sflow_polling, sflow_polling);
      mdata->sflow_polling = sflow_polling;
    }
    if(sflow_headerBytes != mdata->sflow_headerBytes) {
      EVDebug(mod, 1, "sflow_headerBytes %u -> %u", mdata->sflow_headerBytes, sflow_headerBytes);
      mdata->sflow_headerBytes = sflow_headerBytes;
    }
    if(sflow_dropLimit != mdata->sflow_dropLimit) {
      EVDebug(mod, 1, "sflow_dropLimit %u -> %u", mdata->sflow_dropLimit, sflow_dropLimit);
      mdata->sflow_dropLimit = sflow_dropLimit;
    }
    if(!my_strequal(sflow_direction, mdata->sflow_direction)) {
      // For SONiC mod_psample is configured to accept egress samples if they appear,
      // so just print this setting for now.  If we ever have to observe it more tightly
      // then we will have to check the per-interface settings too.
      EVDebug(mod, 1, "sflow_direction %s -> %s",
	      mdata->sflow_direction ?: "<not set>",
	      sflow_direction ?: "<not set>");
      setStr(&mdata->sflow_direction, sflow_direction);
    }

    setSonicState(mod, HSP_SONIC_STATE_COLLECTORS);
  }

  static void db_getsFlowGlobal(EVMod *mod) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db) {
      EVDebug(mod, 1, "getsFlowGlobal()");
      int status = redisAsyncCommand(db->ctx, db_getsFlowGlobalCB, NULL, "HGETALL SFLOW|global");
      EVDebug(mod, 1, "getsFlowGlobal() returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________    db_getCollectorInfo    __________________
    -----------------___________________________------------------
  */

  static void db_getCollectorInfoCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    redisReply *reply = (redisReply *)magic;
    HSPSonicCollector *coll = (HSPSonicCollector *)req_magic;
    EVDebug(mod, 1, "getCollectorInfoCB(%s): reply=%s",
	    coll->collectorName,
	    db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      goto COLLECTOR_INFO_DONE; // will skip this one and try next
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      // reset fields that might have been deleted under our feet
      coll->port = SFL_DEFAULT_COLLECTOR_PORT;
      if(coll->ipStr) {
	my_free(coll->ipStr);
	coll->ipStr = NULL;
      }
      if(coll->deviceName) {
	my_free(coll->deviceName);
	coll->deviceName = NULL;
      }
      // now see what we got
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *f_name = reply->element[ii];
	redisReply *f_val = reply->element[ii + 1];
	if(f_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 1, "sflow collector: %s=%s", f_name->str, db_replyStr(f_val, db->replyBuf, YES));
	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_COLLECTOR_IP)) {
	    SFLAddress ip;
	    coll->ipStr = my_strdup(f_val->str);
	    coll->parseOK = parseNumericAddress(f_val->str, NULL, &ip, 0);
	  }
	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_COLLECTOR_PORT)) {
	    coll->port = db_getU32(f_val);
	    if(coll->port > 65536)
	      coll->parseOK = NO;
	    // interpret port=0 to mean port=<default>
	    if(coll->port == 0)
	      coll->port = SFL_DEFAULT_COLLECTOR_PORT;
	  }
	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_COLLECTOR_VRF)) {
	    // only set deviceName if the VRF is not the default
	    if(!my_strequal(f_val->str, HSP_SONIC_VRF_DEFAULT))
	      coll->deviceName = my_strdup(f_val->str);
	  }
	}
      }
    }
  COLLECTOR_INFO_DONE:
    getNextCollectorInfo(mod);
  }

  static void db_getCollectorInfo(EVMod *mod, HSPSonicCollector *coll) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db) {
      EVDebug(mod, 1, "getCollectorInfo(%s)", coll->collectorName);
      int status = redisAsyncCommand(db->ctx, db_getCollectorInfoCB, coll, "HGETALL SFLOW_COLLECTOR|%s", coll->collectorName);
      EVDebug(mod, 1, "getCollectorInfo(%s) returned %d", coll->collectorName, status);
    }
  }

  static bool getNextCollectorInfo(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicCollector *coll = UTHashNext(mdata->collectors, &mdata->collectorCursor);
    if(coll) {
      db_getCollectorInfo(mod, coll);
      return YES;
    }
    else {
      // got them all
      setSonicState(mod, HSP_SONIC_STATE_DISCOVER);
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________    db_getCollectorNames   __________________
    -----------------___________________________------------------
  */

  static void db_getCollectorNamesCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    char *sep = (char *)req_magic;

    EVDebug(mod, 1, "getCollectorNamesCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // stay in same state - may try again next tick
    markCollectors(mod);
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0) {
      for(int ii = 0; ii < reply->elements; ii++) {
	redisReply *elem = reply->element[ii];
	if(elem->type == REDIS_REPLY_STRING) {
#define HSP_SONIC_MAX_COLLECTORNAME_LEN 512
	  char buf1[HSP_SONIC_MAX_COLLECTORNAME_LEN];
	  char buf2[HSP_SONIC_MAX_COLLECTORNAME_LEN];
	  char *pcmem = keyToken(mod, elem->str, sep, 1, buf1, HSP_SONIC_MAX_COLLECTORNAME_LEN);
	  if(my_strequal(pcmem, "SFLOW_COLLECTOR")) {
	    char *collectorName = keyToken(mod, elem->str, sep, 2, buf2, HSP_SONIC_MAX_COLLECTORNAME_LEN);
	    if(collectorName) {
	      HSPSonicCollector *coll = getCollector(mod, collectorName, YES);
	      coll->mark = NO;
	    }
	  }
	}
      }
    }
    deleteMarkedCollectors(mod);
    // start the walk (note that there may be none, but
    // if so the state machine will still advance and
    // we'll get to SYNC_CONFIG)
    mdata->collectorCursor = 0;
    getNextCollectorInfo(mod);
  }

  static void db_getCollectorNames(EVMod *mod) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db_selectTab(dbTab)) {
      EVDebug(mod, 1, "getCollectorNames()");
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_getCollectorNamesCB,
				     dbTab->separator,
				     "KEYS SFLOW_COLLECTOR|*");
      EVDebug(mod, 1, "getCollectorNames() returned %d", status);
    }
  }


  /*_________________---------------------------__________________
    _________________    db_getSystemReady      __________________
    -----------------___________________________------------------
  */

  static void db_getSystemReadyCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;

    EVDebug(mod, 1, "getSystemReadyCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return; // will stay in same state (e,g. HSP_SONIC_STATE_WAIT_READY)
    bool system_ready = NO;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *f_name = reply->element[ii];
	redisReply *f_val = reply->element[ii + 1];
	if(f_name->type == REDIS_REPLY_STRING) {
	  EVDebug(mod, 1, "getSystemReadyCB: %s=%s", f_name->str, db_replyStr(f_val, db->replyBuf, YES));
	  
	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SYSTEMREADY_STATUS))
	    system_ready = my_strequal(f_val->str, "UP");
	}
      }
    }
    // now see if there are any changes. 
    if(system_ready != mdata->system_ready) {
      EVDebug(mod, 1, "system_ready %u -> %u", mdata->system_ready, system_ready);
      mdata->system_ready = system_ready;
    }
    if(system_ready
       && mdata->state == HSP_SONIC_STATE_WAIT_READY)
      setSonicState(mod, HSP_SONIC_STATE_CONNECTED);
  }

  static void db_getSystemReady(EVMod *mod) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_STATE_NAME);
    if(db) {
      EVDebug(mod, 1, "getSystemReady()");
      int status = redisAsyncCommand(db->ctx, db_getSystemReadyCB, NULL, "HGETALL SYSTEM_READY|SYSTEM_STATE");
      EVDebug(mod, 1, "getSystemReady() returned %d", status);
    }
  }
  
  /*_________________---------------------------__________________
    _________________      dbEvt_subscribe      __________________
    -----------------___________________________------------------
  */

  typedef void (*opCBFn)(EVMod *mod, char *key, char *op);

#if 0
  static void dbEvt_counterOp(EVMod *mod, char *portOID, char *op) {
    // TODO: use this to observe how counters are updated,  so see if
    // we can move to an edge-triggered polling tick.
    EVDebug(mod, 1, "dbEvt_counterOp: %s (%s)", portOID, op);
  }

  static void dbEvt_sflowInterfaceOp(EVMod *mod, char *key, char *op) {
    EVDebug(mod, 1, "dbEvt_sflowInterfaceOp: %s (%s)", key, op);
    // This is a no-op because we will still poll counters for all
    // interfaces and the sampling-rate settings are controlled
    // externally (and learned in mod_psample).
  }
#endif

  static void dbEvt_lagOp(EVMod *mod, char *memberStr, char *op) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbEvt_lagOp: %s (%s)", memberStr, op);
    mdata->changedLagTable = YES;
  }

  static void dbEvt_sflowOp(EVMod *mod, char *key, char *op) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbEvt_sflowOp: %s (%s)", key, op);
    mdata->changedSFlowGlobalTable = YES;
  }

  static void dbEvt_portOp(EVMod *mod, char *key, char *op) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbEvt_portOp: %s (%s)", key, op);
    mdata->changedPortTable = YES;
  }

  static void dbEvt_sflowCollectorOp(EVMod *mod, char *key, char *op) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbEvt_sflowCollectorOp: %s (%s)", key, op);
    mdata->changedCollectorTable = YES;
  }

  static void dbEvt_indexOp(EVMod *mod, char *key, char *op) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbEvt_indexOp: %s (%s)", key, op);
    // key will take the form "__keyspace@6__:PORT_INDEX_TABLE|Ethernet100"
    // so we can extract the portName like this:
    char buf[HSP_SONIC_MAX_PORTNAME_LEN];
    char *sep = mdata->stateTabSeparator;
    char *portName = keyToken(mod, key, sep, 2, buf, HSP_SONIC_MAX_PORTNAME_LEN);
    if(portName)
      EVDebug(mod, 1, "PORT_INDEX_TABLE changed entry for: %s", portName);
    mdata->changedPortIndexTable = YES;
  }

  static void dbEvt_subscribeCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    redisReply *reply = (redisReply *)magic;
    EVDebug(mod, 3, "dbEvt_subscribeCB: reply=%s",
	    db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements == 4) {
      if(EVDebug(mod, 3, NULL)) {
	for(int ii = 0; ii < reply->elements; ii++) {
	  redisReply *elem = reply->element[ii];
	  EVDebug(mod, 1, "dbEvt_subscribeCB: (%d)=%s", ii, db_replyStr(elem, db->replyBuf, YES));
	}
      }
      opCBFn opCB = (opCBFn)req_magic;
      opCB(mod, reply->element[2]->str, reply->element[3]->str);
    }
  }

  static void dbEvt_subscribePattern(EVMod *mod, char *pattern, opCBFn opCB, HSPSonicDBTable *dbTab) {
    HSPSonicDBClient *db = dbTab->evtClient;
#define HSP_SONIC_SUBSCRIBE_LEN 256
    char requestPattern[HSP_SONIC_SUBSCRIBE_LEN];
    snprintf(requestPattern, HSP_SONIC_SUBSCRIBE_LEN, pattern, dbTab->id);
    int status = redisAsyncCommand(db->ctx,
				   dbEvt_subscribeCB,
				   opCB,
				   requestPattern);
    EVDebug(mod, 1, "dbEvt_subscribePattern(%s) returned %d", requestPattern, status);
  }

  static void dbEvt_subscribe(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "dbEvt_subscribe");
    // SFLOW and LAG settings are in the CONFIG_DB table, whose events client
    // was added in addEventClients(), so it should be available to us here:
    HSPSonicDBTable *configTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(configTab) {
      HSPSonicDBClient *db = configTab->evtClient;
      if(db
	 && db->sock) {
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@%u__:PORTCHANNEL_MEMBER*", dbEvt_lagOp, configTab);
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@%u__:SFLOW|global*", dbEvt_sflowOp, configTab);
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@%u__:SFLOW_COLLECTOR*", dbEvt_sflowCollectorOp, configTab);
	// dbEvt_subscribePattern(mod,  "psubscribe __keyspace@%u__:SFLOW_SESSION*", dbEvt_sflowInterfaceOp, configTab);
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@%u__:PORT|*", dbEvt_portOp, configTab);
      }
    }
    // While the port index table is in the STATE db
    HSPSonicDBTable *stateTab = getDBTable(mod, HSP_SONIC_DB_STATE_NAME);
    if(stateTab) {
      HSPSonicDBClient *db = stateTab->evtClient;
      // have to remember this separator here because it is not so easy to pass to callback
      setStr(&mdata->stateTabSeparator, stateTab->separator);
      if(db
	 && db->sock) {
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@%u__:PORT_INDEX_TABLE*", dbEvt_indexOp, stateTab);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    syncConfig             __________________
    -----------------___________________________------------------
   Any changes here should be reflected in hsflowconfig.c:dynamic_config_line
  */

  static void syncConfig(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    EVDebug(mod, 1, "syncConfig");
    char cfgLine[EV_MAX_EVT_DATALEN];
    EVEventTx(mod, mdata->configStartEvent, NULL, 0);
    int num_servers = 0;
    if(mdata->sflow_enable) {
      if(mdata->sflow_agent) {
	snprintf(cfgLine, EV_MAX_EVT_DATALEN, "agent=%s", mdata->sflow_agent);
	EVEventTx(mod, mdata->configEvent, cfgLine, my_strlen(cfgLine));
      }
      snprintf(cfgLine, EV_MAX_EVT_DATALEN, "polling=%u", mdata->sflow_polling);
      EVEventTx(mod, mdata->configEvent, cfgLine, my_strlen(cfgLine));
      snprintf(cfgLine, EV_MAX_EVT_DATALEN, "headerBytes=%u", mdata->sflow_headerBytes);
      EVEventTx(mod, mdata->configEvent, cfgLine, my_strlen(cfgLine));
      if(mdata->sflow_dropLimit_set) {
	snprintf(cfgLine, EV_MAX_EVT_DATALEN, "dropLimit=%u", mdata->sflow_dropLimit);
	EVEventTx(mod, mdata->configEvent, cfgLine, my_strlen(cfgLine));
      }
      // TODO: add headerBytes, datagramBytes (when settable in redis) too?
      HSPSonicCollector *coll;
      UTHASH_WALK(mdata->collectors, coll) {
	if(coll->parseOK) {
	  num_servers++;
	  // dynamic config requires the key=val form. Fields here are addr, port, dev and namespace
	  snprintf(cfgLine, EV_MAX_EVT_DATALEN, "collector=%s/%u/%s", coll->ipStr, coll->port, coll->deviceName ?: "");
	  EVEventTx(mod, mdata->configEvent, cfgLine, my_strlen(cfgLine));
	}
      }
    }
    EVEventTx(mod, mdata->configEndEvent, &num_servers, sizeof(num_servers));
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
      mdata->changedSwitchPorts = NO;
    }
  }

  /*_________________---------------------------__________________
    _________________      evt_intf_read        __________________
    -----------------___________________________------------------
  */

  static void evt_poll_intf_read(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    SFLAdaptor *adaptor = *(SFLAdaptor **)data;
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);

    EVDebug(mod, 1, "evt_poll_intf_read(%s)", adaptor->deviceName);
    // turn off the use of ethtool_GSET so it doesn't get the wrong speed
    // and turn off other ethtool requests because they won't add to the picture
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
    mdata->changedLinuxInterfaces = YES;
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

    if(mdata->state < HSP_SONIC_STATE_DISCOVER)
      return; // this can happen if we lose the redis connection and go back

    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    
    EVDebug(mod, 1, "pollCounters(adaptor=%s, alias=%s)",
	    adaptor->deviceName,
	    nio->deviceAlias ?: "<none>");
    
    if(nio->loopback)
      return;
    
    if(nio->bond_master_2) {
      // trigger synthesizeBondMetaData
      accumulateNioCounters(sp, adaptor, NULL, NULL);
      return;
    }

    HSPSonicIdxMap *idxm = getIdxMapByOsIndex(mod, adaptor->ifIndex);
    if(idxm == NULL) {
      EVDebug(mod, 1, "evt_poll_update_nio: idxMap for %s not found", adaptor->deviceName);
    }
    else {
      HSPSonicPort *prt = getPort(mod, idxm->portName, NO);
      if(prt == NULL) {
	EVDebug(mod, 1, "evt_poll_update_nio: port for %s not found", idxm->portName);
      }
      else {
	// OK to queue 4 requests on the TCP connection, and ordering
	// is preserved, so can just ask for state-refresh and counters
	// together:
	db_getPortState(mod, prt);
	db_getPortCounters(mod, prt);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________   buildRegexPatterns      __________________
    -----------------___________________________------------------
  */

  static void buildRegexPatterns(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    if(mdata->portChannelPattern) {
      // rebuild regex so it can clean up memory usage
      regfree(mdata->portChannelPattern);
      my_free(mdata->portChannelPattern);
    }
    mdata->portChannelPattern = UTRegexCompile(HSP_SONIC_PORTCHANNEL_RE);
  }

  /*_________________---------------------------__________________
    _________________    evt_tick               __________________
    -----------------___________________________------------------
  */

  static void evt_tick(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    
    switch(mdata->state) {
    case HSP_SONIC_STATE_INIT:
      // used to wait for evt_config_changed
      // but now we start with no config (like DNS-SD)
      // so get things started here after a polite
      // startup delay of one tick:
      setSonicState(mod, HSP_SONIC_STATE_CONNECT);
      break;
    case HSP_SONIC_STATE_CONNECT:
      // got config - try to connect
      loadDBConfig(mod);
      addEventClients(mod);
      db_connect(mod);
      break;
    case HSP_SONIC_STATE_WAIT_READY:
      // all dbs connected - wait for SYSTEM_READY
      {
	time_t waiting = mdata->pollBus->now.tv_sec - mdata->waitReadyStart;
	if(waiting < sp->sonic.waitReady) {
	  db_getSystemReady(mod);
	}
	else {
	  EVDebug(mod, 1, "sonic: waitReady timeout after %u seconds", waiting);
	  setSonicState(mod, HSP_SONIC_STATE_CONNECTED);
	}
      }
      break;
    case HSP_SONIC_STATE_CONNECTED:
      // connected and ready - learn config
      db_getMeta(mod);
      dbEvt_subscribe(mod);
      // the next steps read the starting agent/polling/collector
      // config. Any subsequent changes will be detected via dbEvt.
      setSonicState(mod, HSP_SONIC_STATE_SFLOWGLOBAL);
      break;
    case HSP_SONIC_STATE_SFLOWGLOBAL:
      mdata->changedSFlowGlobalTable = NO;
      db_getsFlowGlobal(mod);
      break;
    case HSP_SONIC_STATE_COLLECTORS:
      mdata->changedCollectorTable = NO;
      db_getCollectorNames(mod);
      break;
    case HSP_SONIC_STATE_DISCOVER:
      // learn dynamic port->oid mappings
      // we can jump back here from HSP_SONIC_STATE_RUN if we
      // are notified that the interfaces have changed.
      mdata->changedPortTable = NO;
      mdata->changedPortIndex = NO;
      mdata->changedLinuxInterfaces = NO;
      db_getPortNames(mod);
      break;
    case HSP_SONIC_STATE_DISCOVER_MAPPING:
      // learn mapping to native Linux ifIndex numbers
      mdata->changedPortIndexTable = NO;
      db_getIfIndexMapNames(mod);
      break;
    case HSP_SONIC_STATE_DISCOVER_LAGS:
      mdata->changedLagTable = NO;
      db_getLagInfo(mod);
      break;
    case HSP_SONIC_STATE_SYNC_CONFIG:
      syncSwitchPorts(mod);
      syncConfig(mod);
      setSonicState(mod, HSP_SONIC_STATE_RUN);
      break;
    case HSP_SONIC_STATE_RUN:
      if(mdata->changedSFlowGlobalTable) {
	EVDebug(mod, 1, "change detected: SFLOWGLOBAL");
	setSonicState(mod, HSP_SONIC_STATE_SFLOWGLOBAL);
      }
      else if(mdata->changedCollectorTable) {
	EVDebug(mod, 1, "change detected: COLLECTOR");
	setSonicState(mod, HSP_SONIC_STATE_COLLECTORS);
      }
      else if(mdata->changedPortTable
	      || mdata->changedPortIndex
	      || mdata->changedPortIndexTable
	      || mdata->changedLagTable
	      || mdata->changedLinuxInterfaces) {
	EVDebug(mod, 1, "change detected: PORT=%u INDEX=%u INDEXTABLE=%u LAG=%u LINUX=%u",
		mdata->changedPortTable,
		mdata->changedPortIndex,
		mdata->changedPortIndexTable,
		mdata->changedLagTable,
		mdata->changedLinuxInterfaces);
	setSonicState(mod, HSP_SONIC_STATE_DISCOVER);
      }
      else {
	// RUN state
	// We don't always know whether a port will appear first in redis or Linux.
	// Or even which redis table it will appear in first (PORT, PORT_INDEX or LAG).
	// One solution to that ordering problem is to run this resync regularly.
	// By doing it here we know it can't happen more than once per second, so
	// we don't risk generating excessive load. On the other hand we also know
	// that consistent state will be reached even it takes indeterminate time
	// for the ports defined in redis to appear in Linux or vice-versa.
	if(syncPortsToAdaptors(mod, YES)) {
	  // something changed. We have to tell hsflowd in case it needs
	  // to run a new agent-address election or start/stop pollers.
	  syncSwitchPorts(mod);
	  syncConfig(mod);
	}
      }
      break;
    }

    if((EVCurrentBus()->now.tv_sec % 60) == 0) {
      // rebuild regex periodically - prevents memory leak
      buildRegexPatterns(mod);
    }
  }

  /*_________________---------------------------__________________
    _________________        evt_final          __________________
    -----------------___________________________------------------
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    EVDebug(mod, 1, "evt_final");
  }

  /*_________________---------------------------__________________
    _________________       evt_flow_sample     __________________
    -----------------___________________________------------------
   packet bus
  */

  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPPendingSample *ps = (HSPPendingSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the SONiC ifIndex namespace. For packet samples that means:
    // 1. sampler ds_index
    // 2. flow_sample input, output ports
    // If a mapping is missing for the sampler we have to block the sample.
    // If a mapping is missing for in/out ports we have to zero it out (0 == unknown)
    uint32_t osIndex = SFL_DS_INDEX(ps->sampler->dsi);
    // Make the assumption that we will not see LAG ifIndex numbers here
    // (though if they appear in the PORT_INDEX_TABLE then that would be OK)
    HSPSonicIdxMap *idxm = getIdxMapByOsIndex(mod, osIndex);
    if(idxm == NULL
       || idxm->ifIndex == HSP_SONIC_IFINDEX_UNDEFINED) {
      // for troubleshooting we can allow this through (untranslated) with:
      // "sonic{suppressOther=off}"
      if(!sp->sonic.suppressOther)
	return;
      // block this sample from being sent out.
      // Note: if sample_pool is maintained upstream then it may need
      // to be adjusted if this happens a lot... but that would imply
      // a lot of PSAMPLE activity that SONiC has no knowledge of,  or
      // a systematic problem with the adaptorSync.
      EVDebug(mod, 2, "suppress packet sample from non-sonic port (osIndex=%u)", osIndex);
      ps->suppress = YES;
    }
    else {
      // fix datasource
      sfl_sampler_set_dsAlias(ps->sampler, idxm->ifIndex);
      // fix in/out
      if(ps->fs->input
	 && ps->fs->input != SFL_INTERNAL_INTERFACE) {
	// translate, or mark unknown
	HSPSonicIdxMap *in = getIdxMapByOsIndex(mod, ps->fs->input);
	ps->fs->input = (in && in->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	  ? in->ifIndex
	  : 0;
      }
      if(ps->fs->output
	 && ps->fs->output != SFL_INTERNAL_INTERFACE
	 && (ps->fs->output & 0x80000000) == 0) {
	// translate, or mark unknown
	HSPSonicIdxMap *out = getIdxMapByOsIndex(mod, ps->fs->output);
	ps->fs->output = (out && out->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	  ? out->ifIndex
	  : 0;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_discard_sample     __________________
    -----------------___________________________------------------
   packet bus
  */

  static void evt_discard_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSPPendingEvtSample *ps = (HSPPendingEvtSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the SONiC ifIndex namespace.
    uint32_t dsClass = ps->discard->ds_class;
    uint32_t osIndex = ps->discard->ds_index;
    HSPSonicIdxMap *idxm = NULL;
    uint32_t dsIndexAlias = 0;
    if(dsClass == SFL_DSCLASS_IFINDEX
       && osIndex != 0) {
      idxm = getIdxMapByOsIndex(mod, osIndex);
      dsIndexAlias = idxm ? idxm->ifIndex : 0;
      // Note that if dsIndexAlias is 0 that means "no alias"
      sfl_notifier_set_dsAlias(ps->notifier, dsIndexAlias);
    }
    // fix in/out
    if(ps->discard->input
       && ps->discard->input != SFL_INTERNAL_INTERFACE) {
      // translate, or mark unknown
      HSPSonicIdxMap *in = getIdxMapByOsIndex(mod, ps->discard->input);
      ps->discard->input = (in && in->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	? in->ifIndex
	: 0;
    }
    if(ps->discard->output
       && ps->discard->output != SFL_INTERNAL_INTERFACE
       && (ps->discard->output & 0x80000000) == 0) {
      // translate, or mark unknown
      HSPSonicIdxMap *out = getIdxMapByOsIndex(mod, ps->discard->output);
      ps->discard->output = (out && out->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	? out->ifIndex
	: 0;
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_cntr_sample     __________________
    -----------------___________________________------------------
    poll bus
  */

  static void evt_cntr_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSPPendingCSample *ps = (HSPPendingCSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the SONiC ifIndex namespace. For interface counter samples that means:
    // 1. poller ds_index
    // 2. generic counters ifIndex
    // 3. LAG stucture aggregationID
    // 4. entity structures?
    // 5. Optical structures?
    // 6. Parent structure?
    uint32_t osIndex = SFL_DS_INDEX(ps->poller->dsi);
    // may need to access all three of these
    HSPSonicIdxMap *idxm = getIdxMapByOsIndex(mod, osIndex);
    HSPSonicLAG *lag = getLagByOsIndex(mod, osIndex);
    HSPSonicPort *prt = NULL;
    if(idxm)
      prt = getPort(mod, idxm->portName, NO);
    // see if we can get an ifIndex - but it has to be for a port or lag.
    uint32_t ifIndex = HSP_SONIC_IFINDEX_UNDEFINED;
    if(prt)
      ifIndex = idxm->ifIndex;
    else if(lag)
      ifIndex = lag->ifIndex;
    if(ifIndex == HSP_SONIC_IFINDEX_UNDEFINED) {
      // for troubleshooting we can allow this through (untranslated) with:
      // "sonic{suppressOther=off}"
      if(!sp->sonic.suppressOther)
	return;
      // block this sample from being sent out
      EVDebug(mod, 2, "suppress counter sample from non-sonic port (osIndex=%u)", osIndex);
      ps->suppress = YES;
    }
    else {
      // fix datasource
      sfl_poller_set_dsAlias(ps->poller, ifIndex);
      // look through counter structures
      for(SFLCounters_sample_element *elem = ps->cs->elements;
	  elem != NULL;
	  elem = elem->nxt) {
	if(elem->tag == SFLCOUNTERS_GENERIC) {
	  // fix generic ifIndex
	  elem->counterBlock.generic.ifIndex = ifIndex;
	  // note: ifStatus is OK because it is queried in db_getPortCounters() and does
	  // not overwrite nio->up flag (so it won't trigger readInterfaces() to say that
	  // something changed every time).
	}
	else if(elem->tag == SFLCOUNTERS_LACP) {
	  // fix LAG aggregation ID
	  uint32_t aggID = elem->counterBlock.lacp.attachedAggID;
	  if(aggID) {
	    // translate, or mark unknown
	    elem->counterBlock.lacp.attachedAggID = (lag && lag->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	      ? lag->ifIndex
	      : 0;
	  }
	}
      }
    }
  }
  
  /*_________________---------------------------__________________
    _________________  initPortChannelBaseIndex __________________
    -----------------___________________________------------------
  */

  static void initPortChannelBaseIndex(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    mdata->portChannelBaseIndex = HSP_SONIC_DEFAULT_PORTCHANNEL_BASEINDEX;
    char *pcbi = getenv(HSP_SONIC_PORTCHANNEL_BASEINDEX_ENVVAR);
    if(pcbi) {
      uint32_t baseIdx = strtol(pcbi, NULL, 0);
      EVDebug(mod, 1, "ENV \"%s\" overriding portchannel base-index from %u to %u",
	      STRINGIFY_DEF(HSP_SONIC_PORTCHANNEL_BASEINDEX_ENVVAR),
	      mdata->portChannelBaseIndex,
	      baseIdx);
      mdata->portChannelBaseIndex = baseIdx;
    }
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
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    // REDIS access
    mdata->dbInstances = UTHASH_NEW(HSPSonicDBClient, dbInstance, UTHASH_SKEY);
    mdata->dbTables = UTHASH_NEW(HSPSonicDBTable, dbTable, UTHASH_SKEY);
    // PORT_TABLE
    mdata->portsByName = UTHASH_NEW(HSPSonicPort, portName, UTHASH_SKEY);
    // PORT_INDEX_TABLE
    mdata->idxMapByName = UTHASH_NEW(HSPSonicIdxMap, portName, UTHASH_SKEY);
    mdata->idxMapByOsIndex = UTHASH_NEW(HSPSonicIdxMap, osIndex, UTHASH_DFLT);
    // LAGS
    mdata->lagsByName = UTHASH_NEW(HSPSonicLAG, lagName, UTHASH_SKEY);
    mdata->lagsByOsIndex = UTHASH_NEW(HSPSonicLAG, osIndex, UTHASH_DFLT);
    // collectors
    mdata->collectors = UTHASH_NEW(HSPSonicCollector, collectorName, UTHASH_SKEY);

    agentDeviceStrictRequest(mod, "may be SONiC CLI setting");

    // PortChannel regex and base-index
    initPortChannelBaseIndex(mod);
    buildRegexPatterns(mod);

    // ask that bond counters be accumuated from their components
    setSynthesizeBondCounters(mod, YES);

    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_READ), evt_poll_intf_read);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTFS_CHANGED), evt_poll_intfs_changed);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_UPDATE_NIO), evt_poll_update_nio);

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

    // to submit config changes just like DNS-SD
    mdata->configStartEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_START);
    mdata->configEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_LINE);
    mdata->configEndEvent = EVGetEvent(mdata->pollBus, HSPEVENT_CONFIG_END);

    // intercept samples before they go out so we can rewrite ifindex numbers
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_FLOW_SAMPLE), evt_flow_sample);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTF_EVENT_SAMPLE), evt_discard_sample);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_COUNTER_SAMPLE), evt_cntr_sample);
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
