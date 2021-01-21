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
#define HSP_SONIC_FIELD_COLLECTOR_IP "collector_ip"
#define HSP_SONIC_FIELD_COLLECTOR_PORT "collector_port"
#define HSP_SONIC_FIELD_COLLECTOR_VRF "collector_vrf"
#define HSP_SONIC_VRF_DEFAULT "default"

#define HSP_SONIC_DEFAULT_POLLING_INTERVAL 20
#define HSP_SONIC_MIN_POLLING_INTERVAL 5

#define ISEVEN(i) (((i) & 1) == 0)

  typedef enum {
    HSP_SONIC_STATE_INIT=0,
    HSP_SONIC_STATE_CONNECT,
    HSP_SONIC_STATE_CONNECTED,
    HSP_SONIC_STATE_DISCOVER,
    HSP_SONIC_STATE_RUN } EnumSonicState;

  typedef struct _HSPSonicCollector {
    char *collectorName;
    bool mark:1;
    bool parseOK:1;
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
    uint32_t ifIndex;
    uint32_t osIndex;
    uint32_t osIndex_expected;
    uint64_t ifSpeed;
    char *ifAlias;
    SFLHost_nio_counters ctrs;
    HSP_ethtool_counters et_ctrs;
    UTStringArray *components;
  } HSPSonicPort;

  typedef struct _HSPSonicDBClient {
    redisAsyncContext *ctx;
    int dbNo;
    EVMod *mod;
    char *dbInstance;
    char *hostname;
    int port;
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
    EVBus *pollBus;
    EVBus *packetBus;
    UTHash *dbInstances;
    UTHash *dbTables;
    UTHash *portsByName;
    UTHash *portsByOsIndex;
    UTArray *newPorts;
    UTArray *unmappedPorts;
    bool changedSwitchPorts:1;
    u_char actorSystemMAC[8];
    uint32_t localAS;
    bool sflow_enable;
    uint32_t sflow_polling;
    char *sflow_agent;
    UTHash *collectors;
    UTArray *newCollectors;
    EVEvent *configStartEvent;
    EVEvent *configEvent;
    EVEvent *configEndEvent;
  } HSP_mod_SONIC;

  static void db_ping(EVMod *mod, HSPSonicDBClient *db);
  static bool mapPorts(EVMod *mod);
  static bool discoverNewPorts(EVMod *mod);
  static void signalCounterDiscontinuity(EVMod *mod, HSPSonicPort *prt);
  static bool discoverNewCollectors(EVMod *mod);
  static void syncConfig(EVMod *mod);
  static void dbEvt_subscribe(EVMod *mod);

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
    _________________     ports and LAGs        __________________
    -----------------___________________________------------------
  */

  static HSPSonicPort *getPort(EVMod *mod, char *portName, int create) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort search = { .portName = portName };
    HSPSonicPort *prt = UTHashGet(mdata->portsByName, &search);
    if(prt == NULL
       && create) {
      prt = (HSPSonicPort *)my_calloc(sizeof(HSPSonicPort));
      prt->portName = my_strdup(portName);
      prt->ifIndex = HSP_SONIC_IFINDEX_UNDEFINED;
      prt->osIndex = HSP_SONIC_IFINDEX_UNDEFINED;
      prt->osIndex_expected = HSP_SONIC_IFINDEX_UNDEFINED;
      UTHashAdd(mdata->portsByName, prt);
    }
    return prt;
  }

  static void printLags(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt;
    UTHASH_WALK(mdata->portsByName, prt) {
      if(prt->components) {
	char *details = strArrayStr(prt->components, "[", NULL, ",", "]");
	myDebug(1, "LAG %s: %s", prt->portName, details);
	my_free(details);
      }
    }
  }

  static void compileLags(EVMod *mod) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt;
    UTHASH_WALK(mdata->portsByName, prt) {
      if(prt->components) {
	char *details = strArrayStr(prt->components, "[", NULL, ",", "]");
	myDebug(1, "compiling LAG %s: %s", prt->portName, details);
	my_free(details);
	SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);
	if(adaptor) {
	  prt->ifIndex = adaptor->ifIndex;
	  HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	  nio->bond_master = YES;
	  nio->bond_slave = NO;
	  nio->lacp.portState.v.actorAdmin = prt->adminUp ? 2 : 0;
	  nio->lacp.portState.v.actorOper = prt->operUp ? 2 : 0;
	  nio->lacp.portState.v.partnerAdmin = prt->adminUp ? 2 : 0; // questionable assumption
	  nio->lacp.portState.v.partnerOper = prt->operUp ? 2 : 0; // reasonable assumption
	  // TODO: Do all LAGs really have same actor MAC?
	  memcpy(nio->lacp.actorSystemID, mdata->actorSystemMAC, 6);
	  // TODO: might be able to learn partnerSystemID from LLDP?
	  memset(nio->lacp.partnerSystemID, 0, 6);
	  for(int cc=0; cc < strArrayN(prt->components); cc++) {
	    char *c_name = strArrayAt(prt->components, cc);
	    HSPSonicPort *c_prt = getPort(mod, c_name, NO);
	    if(c_prt) {
	      SFLAdaptor *c_adaptor = adaptorByName(sp, c_prt->portName);
	      if(c_adaptor) {
		HSPAdaptorNIO *c_nio = ADAPTOR_NIO(c_adaptor);
		c_nio->lacp.attachedAggID = adaptor->ifIndex;
		memcpy(c_nio->lacp.actorSystemID, nio->lacp.actorSystemID, 6);
		memcpy(c_nio->lacp.partnerSystemID, nio->lacp.partnerSystemID, 6);
		if(c_nio->switchPort) {
		  if(!nio->switchPort) {
		    myDebug(1, "sonic marking bond %s as switchPort", prt->portName);
		    nio->switchPort = YES;
		  }
		}
		if(nio->switchPort
		   && !c_nio->switchPort) {
		  myDebug(1, "sonic warning: bond %s slave %s not marked as switchPort",
			  prt->portName,
			  c_prt->portName);
		}
		c_nio->bond_master = NO;
		c_nio->bond_slave = YES;
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

  static void resetLags(EVMod *mod) {
    // just have to clear the nio bond flags from LAGs and
    // components, and remove the components list from the LAG port.
    // Any stale nio->lacp* settings will be overwritten with fresh
    // values if port is still in LAG or is involved in a LAG again
    // sometime later.
    HSP *sp = (HSP *)EVROOTDATA(mod);
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort *prt;
    UTHASH_WALK(mdata->portsByName, prt) {
      SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);
      if(adaptor) {
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	nio->bond_master = NO;
	nio->bond_slave = NO;
      }
      if(prt->components) {
	strArrayFree(prt->components);
	prt->components = NULL;
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
      if(prt->components) {
	// LAG. If it's no longer current then
	// the components will be removed and
	// it will be deleted next time,
	continue;
      }
      if(prt->mark) {
	myDebug(1, "sonic port removed %s", prt->portName);
	UTHashDel(mdata->portsByName, prt);
	if(prt->portName)
	  my_free(prt->portName);
	if(prt->oid)
	  my_free(prt->oid);
	if(prt->ifAlias)
	  my_free(prt->ifAlias);
	//if(prt->components)
	//  strArrayFree(prt->components);
	my_free(prt);
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
	myDebug(1, "sonic collector removed %s", coll->collectorName);
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

  static HSPSonicDBClient *addDB(EVMod *mod, char *dbInstance, char *hostname, int port) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "addDB: %s hostname=%s, port=%d", dbInstance, hostname, port);
    HSPSonicDBClient *db = getDB(mod, dbInstance);
    if(db == NULL) {
      db = (HSPSonicDBClient *)my_calloc(sizeof(HSPSonicDBClient));
      db->dbInstance = my_strdup(dbInstance);
      db->replyBuf = UTStrBuf_new();
      db->mod = mod;
      db->hostname = my_strdup(hostname);
      db->port = port;
      UTHashAdd(mdata->dbInstances, db);
      // the socket will be opened later
    }
    return db;
  }

#if 0
  static void freeDB(HSPSonicDBTable *db) {
    my_free(db->dbInstance);
    UTStrBuf_free(db->replyBuf);
    my_free(db->hostname);
    my_free(db);
  }
#endif

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
    myDebug(1, "dbTab: %s instance=%s, id=%d", dbTable, dbInstance, id);
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
    char *fname = HSP_SONIC_DB_JSON;
    myDebug(1, "sonic loadDBConfig from %s", fname);
    resetDBConfig(mod);
    FILE *fjson = fopen(fname, "r");
    if(fjson) {
      UTStrBuf *sbuf = UTStrBuf_new();
      char lineBuf[1024];
      int truncated = NO;
      while(my_readline(fjson, lineBuf, 1024, &truncated) != EOF) {
	if(truncated)
	  myDebug(1, "ignoring unexpected long line in %s: %s", fname, lineBuf);
	else {
	  UTStrBuf_append(sbuf, lineBuf);
	  UTStrBuf_append(sbuf, "\n");
	}
      }
      const char *errm;
      cJSON *dbconfig = cJSON_ParseWithOpts(UTSTRBUF_STR(sbuf), &errm, YES);
      if(dbconfig == NULL)
	myDebug(1, "sonic loadDBConfig JSON parser failed: %s", errm);
      else {
	cJSON *instances = cJSON_GetObjectItem(dbconfig, "INSTANCES");
	cJSON *databases = cJSON_GetObjectItem(dbconfig, "DATABASES");
	for(cJSON *inst = instances->child; inst; inst = inst->next) {
	  cJSON *hostname = cJSON_GetObjectItem(inst, "hostname");
	  cJSON *port = cJSON_GetObjectItem(inst, "port");
	  // cJSON *unixSockPath = cJSON_GetObjectItem(inst, "unix_socket_path");
	  // cJSON *persist = cJSON_GetObjectItem(inst, "persistence_for_warm_boot");
	  addDB(mod, inst->string, hostname->valuestring, port->valueint);
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
    // Currently we only need one, for the CONFIG_DB table.
    HSPSonicDBTable *configTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(configTab
       && configTab->dbClient) {
      configTab->evtClient = addDB(mod, HSP_SONIC_DB_CONFIG_NAME HSP_SONIC_DB_EVENT_SUFFIX,
				   configTab->dbClient->hostname,
				   configTab->dbClient->port);
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
    myDebug(1, "sonic db_cleanupCB dbSock=%p", db->sock);
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
    myDebug(1, "sonic db_connectCB: status= %d", status);
    if(status == REDIS_OK) {
      db->connected = YES;
      if(db_allConnected(db->mod))
	mdata->state = HSP_SONIC_STATE_CONNECTED;
    }
  }

  static void db_disconnectCB(const redisAsyncContext *ctx, int status) {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)db->mod->data;
    myDebug(1, "sonic db_disconnectCB: status= %d", status);
    db->connected = NO;
    mdata->state = HSP_SONIC_STATE_CONNECT;
  }

  static bool db_connectClient(EVMod *mod, HSPSonicDBClient *db) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "sonic db_connectClient %s = %s:%d", db->dbInstance, db->hostname, db->port);
    redisAsyncContext *ctx = db->ctx = redisAsyncConnect(db->hostname, db->port);
    if(ctx) {
      redisAsyncSetConnectCallback(ctx, db_connectCB);
      redisAsyncSetDisconnectCallback(ctx, db_disconnectCB);
      int fd = ctx->c.fd;
      if(fd > 0) {
	myDebug(1, "sonic redis fd == %d", fd);
	db->sock = EVBusAddSocket(mod, mdata->pollBus, fd, db_readCB, db /* magic */);
	// db->ev.addRead = db_addReadCB; // EVBus always ready to read
	// db->ev.delRead = db_delReadCB; // no-op
	ctx->ev.addWrite = db_addWriteCB;
	// db->ev.delWrite = db_delWriteCB; // no-op
	ctx->ev.cleanup = db_cleanupCB;
	ctx->ev.data = db;
	return YES;
      }
    }
    return NO;
  }

  static void db_connect(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // try to connect all db instances
    HSPSonicDBClient *db;
    UTHASH_WALK(mdata->dbInstances, db) {
      if(!db->connected) {
	db_connectClient(mod, db);
	// async connect requires something to do before it will complete,
	// so go ahead and issue the first query.  Use a neutral "no-op"
	// and save the actual discovery queries for the next step once
	// everything is connected.
	db_ping(mod, db);
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
    myDebug(1, "sonic db_selectCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
  }

  static bool db_select(HSPSonicDBClient *db, int dbNo) {
    if(dbNo == db->dbNo)
      return YES;
    myDebug(1, "sonic db_select(%u)", dbNo);
    int status = redisAsyncCommand(db->ctx, db_selectCB, NULL /*privData*/, "select %u", dbNo);
    myDebug(1, "sonic db_select returned %d", status);
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
    _________________         db_ping           __________________
    -----------------___________________________------------------
  */

  static void db_pingCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    redisReply *reply = (redisReply *)magic;
    myDebug(1, "sonic db_pingCB: %s reply=%s",
	    db->dbInstance,
	    db_replyStr(reply, db->replyBuf, YES));
  }

  static void db_ping(EVMod *mod, HSPSonicDBClient *db) {
    myDebug(1, "sonic db_ping: %s", db->dbInstance);
    int status = redisAsyncCommand(db->ctx, db_pingCB, NULL /*privData*/, "ping");
    myDebug(1, "sonic db_ping returned %d", status);
  }

  /*_________________---------------------------__________________
    _________________      db_getMeta           __________________
    -----------------___________________________------------------
  */

  static void db_metaCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)db->mod->data;
    redisReply *reply = (redisReply *)magic;
    myDebug(1, "sonic db_metaCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;

    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  myDebug(1, "sonic db_metaCB: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_MAC)
	     && c_val->type == REDIS_REPLY_STRING
	     && c_val->str) {
	    bool parseOK = (hexToBinary((u_char *)c_val->str, mdata->actorSystemMAC, 6) == 6);
	    myDebug(1, "sonic db_metaCB: system MAC: %s parsedOK=%s", c_val->str, parseOK ? "YES":"NO");
	  }
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_LOCALAS))
	    mdata->localAS = db_getU32(c_val);
	}
      }
    }
  }

  static void db_getMeta(EVMod *mod) {
    myDebug(1, "sonic db_getMeta");
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_CONFIG_NAME); 
    if(db) {
      int status = redisAsyncCommand(db->ctx, db_metaCB, NULL /*privData*/, "HGETALL DEVICE_METADATA|localhost");
      myDebug(1, "sonic db_getMeta returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________      db_getifIndexMap     __________________
    -----------------___________________________------------------
  */

  static void db_ifIndexMapCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;
    myDebug(1, "sonic db_ifIndexMapCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  myDebug(1, "sonic db_ifIndexMapCB: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFINDEX)) {
	    uint32_t idx = db_getU32(c_val);
	    if(prt->ifIndex != idx) {
	      if(prt->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED) {
		myDebug(1, "sonic ifIndex for port %s changed from %u to %u",
			prt->portName,
			prt->ifIndex,
			idx);
		signalCounterDiscontinuity(mod, prt);
	      }
	      prt->ifIndex = idx;
	    }
	  }
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFINDEX_OS)) {
	    uint32_t idx = db_getU32(c_val);
	    if(prt->osIndex != idx) {
	      if(prt->osIndex != HSP_SONIC_IFINDEX_UNDEFINED) {
		myDebug(1, "sonic osIndex for port %s changed from %u to %u",
			prt->portName,
			prt->osIndex,
			idx);
		signalCounterDiscontinuity(mod, prt);
		UTHashDel(mdata->portsByOsIndex, prt);
	      }
	      prt->osIndex = idx;
	      UTHashAdd(mdata->portsByOsIndex, prt);
	      if(prt->osIndex != prt->osIndex_expected) {
		// either this port not found in readInterfaces() discovery,
		// or we found it, but with a different linux ifIndex.
		if(prt->osIndex_expected == HSP_SONIC_IFINDEX_UNDEFINED)
		  myDebug(1, "sonic osIndex for port %s == %u : not expected from adaptor discovery",
			  prt->portName,
			  prt->osIndex);
		else
		  myDebug(1, "sonic osIndex for port %s expected %u, but got %u",
			  prt->portName,
			  prt->osIndex_expected,
			  prt->osIndex);
	      }
	    }
	  }
	}
      }
    }
    // there may be more to map
    mapPorts(mod);
  }

  static void db_getIfIndexMap(EVMod *mod, HSPSonicPort *prt) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_STATE_NAME);
    if(db_selectTab(dbTab)) {
      myDebug(1, "sonic db_getIfIndexMap()");
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_ifIndexMapCB,
				     prt,
				     "HGETALL PORT_INDEX_TABLE%s%s", dbTab->separator, prt->portName);
      myDebug(1, "sonic db_getIfIndexMap() returned %d", status);
    }
  }

  static bool mapPorts(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // kick off just one - starts a chain reaction if there are more.
    // Gets the ifIndex and Linux (OS) ifIndex
    HSPSonicPort *prt = UTArrayPop(mdata->unmappedPorts);
    if(prt) {
      db_getIfIndexMap(mod, prt);
      return YES;
    }
    return NO;
  }

  /*_________________---------------------------__________________
    _________________      db_getPortNames      __________________
    -----------------___________________________------------------
  */

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
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    myDebug(1, "sonic db_portNamesCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
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
	    // add with OID and queue for discovery
	    prt = getPort(mod, p_name->str, YES);
	    prt->oid = my_strdup(p_oid->str);
	    UTArrayPush(mdata->newPorts, prt);
	    myDebug(1, "sonic db_portNamesCB: new port %s -> %s", prt->portName, prt->oid);
	  }
	  else if(!my_strequal(prt->oid, p_oid->str)) {
	    // OID changed under our feet
	    setStr(&prt->oid, p_oid->str);
	    signalCounterDiscontinuity(mod, prt);
	  }
	  if(prt->osIndex == HSP_SONIC_IFINDEX_UNDEFINED) {
	    // queue it for ifIndex discovery
	    UTArrayPush(mdata->unmappedPorts, prt);
	  }
	  prt->mark = NO;
	}
      }
    }
    deleteMarkedPorts(mod);
    mdata->state = HSP_SONIC_STATE_RUN;
  }

  static void db_getPortNames(EVMod *mod) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_COUNTERS_NAME);
    if(db) {
      myDebug(1, "sonic db_getPortNames()");
      int status = redisAsyncCommand(db->ctx, db_portNamesCB, NULL, "HGETALL COUNTERS_PORT_NAME_MAP");
      myDebug(1, "sonic db_getPortNames() returned %d", status);
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
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;
    myDebug(1, "sonic db_portStateCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  myDebug(1, "sonic db_portStateCB: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));
	  // This "index" field is neither ifIndex nor osIndex, so ignore it.
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFSPEED))
	    prt->ifSpeed = db_getU64(c_val) * HSP_SONIC_FIELD_IFSPEED_UNITS;
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFALIAS))
	    prt->ifAlias = my_strdup(c_val->str);
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFADMINSTATUS))
	    prt->adminUp = my_strequal(c_val->str, "up");
	  if(my_strequal(c_name->str, HSP_SONIC_FIELD_IFOPERSTATUS))
	    prt->operUp = my_strequal(c_val->str, "up");
	}
      }
      SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);

#ifdef HSP_SONIC_TEST_REDISONLY
      if(adaptor == NULL) {
	// get here when testing a redis dump on a system that does not
	// have the same interfaces. Go ahead and add anyway.  Note that
	// readInterfaces() will remove these again unless prevented from
	// doing so by setting sp->allowDeleteAdaptor=NO
	adaptor = nioAdaptorNew(prt->portName, NULL, prt->ifIndex);
	adaptorAddOrReplace(sp->adaptorsByName, adaptor);
	adaptorAddOrReplace(sp->adaptorsByIndex, adaptor);
      }
#endif

      if(adaptor) {
	// The adaptor ifIndex will probably match the osIndex,
	// Record it here so we can cross-check.
	prt->osIndex_expected = adaptor->ifIndex;
      
	// TODO: readVlans
	// TODO: read bond state (may need the nio->bond flag right away)
	HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
	if(nio) {
	  nio->up = prt->operUp;
	  if(!nio->switchPort) {
	    nio->switchPort = YES;
	    mdata->changedSwitchPorts = YES;
	  }
	}
	setAdaptorSpeed(sp, adaptor, prt->ifSpeed, "MOD_SONIC");
      }
    }
    // we may still have a batch of new ports to discover
    discoverNewPorts(mod);
  }

  static void db_getPortState(EVMod *mod, HSPSonicPort *prt) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_APPL_NAME);
    if(db) {
      myDebug(1, "sonic db_getPortState()");
      int status = redisAsyncCommand(db->ctx, db_portStateCB, prt, "HGETALL PORT_TABLE:%s", prt->portName);
      myDebug(1, "sonic db_getPortState returned %d", status);
    }
  }

  static bool discoverNewPorts(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // kick off just one - starts a chain reaction if there are more.
    // Gets the state (index, speed etc.) so we can add it as an adaptor.
    HSPSonicPort *prt = UTArrayPop(mdata->newPorts);
    if(prt) {
      db_getPortState(mod, prt);
      return YES;
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
    redisReply *reply = (redisReply *)magic;
    HSPSonicPort *prt = (HSPSonicPort *)req_magic;

    myDebug(1, "sonic portCounters: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    memset(&prt->ctrs, 0, sizeof(prt->ctrs));
    memset(&prt->et_ctrs, 0, sizeof(prt->et_ctrs));
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *c_name = reply->element[ii];
	redisReply *c_val = reply->element[ii + 1];
	if(c_name->type == REDIS_REPLY_STRING) {
	  myDebug(1, "sonic portCounters: %s=%s", c_name->str, db_replyStr(c_val, db->replyBuf, YES));

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
    SFLAdaptor *adaptor = adaptorByName(sp, prt->portName);
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
	nio->last_update = sp->pollBus->now.tv_sec;
      }
    }
  }

  static void db_getPortCounters(EVMod *mod, HSPSonicPort *prt) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_COUNTERS_NAME);
    if(db) {
      myDebug(1, "sonic getPortCounters(%s) oid=%s", prt->portName, prt->oid ?: "<none>");
      if(prt->oid) {
	int status = redisAsyncCommand(db->ctx, db_portCountersCB, prt, "HGETALL COUNTERS:%s", prt->oid);
	myDebug(1, "sonic getPortCounters() returned %d", status);
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
    redisReply *reply = (redisReply *)magic;
    char *sep = (char *)req_magic;

    myDebug(1, "sonic getLagInfoCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0) {
      resetLags(mod);
      for(int ii = 0; ii < reply->elements; ii++) {
	redisReply *elem = reply->element[ii];
	if(elem->type == REDIS_REPLY_STRING) {
	  char *p = elem->str;
#define HSP_SONIC_MAX_PORTNAME_LEN 512
	  char buf[HSP_SONIC_MAX_PORTNAME_LEN];
	  char *pcmem = parseNextTok(&p, sep, YES, 0, NO, buf, HSP_SONIC_MAX_PORTNAME_LEN);
	  if(my_strequal(pcmem, "PORTCHANNEL_MEMBER")) {
	    char *lagName = parseNextTok(&p, sep, YES, 0, NO, buf, HSP_SONIC_MAX_PORTNAME_LEN);
	    // This may add the port as a port with no oid
	    HSPSonicPort *lagPort = getPort(mod, lagName, YES);
	    if(lagPort->components == NULL)
	      lagPort->components = strArrayNew();
	    char *member = parseNextTok(&p, sep, YES, 0, NO, buf, HSP_SONIC_MAX_PORTNAME_LEN);
	    if(member) {
	      myDebug(1, "sonic getLagInfoCB: port %s is member of port-channel %s", member, lagName);
	      strArrayAdd(lagPort->components, member);
	    }
	  }
	}
      }
      printLags(mod);
      compileLags(mod);
    }
  }

  static void db_getLagInfo(EVMod *mod) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db_selectTab(dbTab)) {
      myDebug(1, "sonic getLagInfo()");
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_getLagInfoCB,
				     dbTab->separator,
				     "KEYS PORTCHANNEL_MEMBER%s*", dbTab->separator);
      myDebug(1, "sonic getLagInfo() returned %d", status);
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

    myDebug(1, "sonic getSflowGlobalCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    // first extract the latest settings
    bool sflow_enable = NO;
    char *sflow_agent = NULL;
    uint32_t sflow_polling = HSP_SONIC_DEFAULT_POLLING_INTERVAL;;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0
       && ISEVEN(reply->elements)) {
      for(int ii = 0; ii < reply->elements; ii += 2) {
	redisReply *f_name = reply->element[ii];
	redisReply *f_val = reply->element[ii + 1];
	if(f_name->type == REDIS_REPLY_STRING) {
	  myDebug(1, "sonic sflow: %s=%s", f_name->str, db_replyStr(f_val, db->replyBuf, YES));

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_ADMIN_STATE))
	    sflow_enable = my_strequal(f_val->str, "up"); // note: was "enable" before

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_AGENT))
	    sflow_agent = f_val->str;

	  if(my_strequal(f_name->str, HSP_SONIC_FIELD_SFLOW_POLLING))
	    sflow_polling = db_getU32(f_val);
	}
      }
    }
    // now see if there are any changes. 
    if(sflow_enable != mdata->sflow_enable) {
      myDebug(1, "sonic sflow_enable %u -> %u", mdata->sflow_enable, sflow_enable);
      mdata->sflow_enable = sflow_enable;
    }
    // The sflow_agent entry will disappear if it is deleted from the config, so sflow_agent
    // may still be NULL here:
    if(!my_strequal(sflow_agent, mdata->sflow_agent)) {
      myDebug(1, "sonic sflow_agent %s -> %s",
	      mdata->sflow_agent ?: "<not set>",
	      sflow_agent ?: "<not set>");
      setStr(&mdata->sflow_agent, sflow_agent);
    }
    if(sflow_polling != mdata->sflow_polling) {
      myDebug(1, "sonic sflow_polling %u -> %u", mdata->sflow_polling, sflow_polling);
      mdata->sflow_polling = sflow_polling;
    }
    // if this is normal startup then don't syncConfig yet (that happens when the collectors
    // have been discovered for the first time).  However if it was a dynamic reconfig then go
    // ahead and syncConfig right away...
    if(mdata->state != HSP_SONIC_STATE_CONNECTED)
      syncConfig(mod);
  }

  static void db_getsFlowGlobal(EVMod *mod) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db) {
      myDebug(1, "sonic getsFlowGlobal()");
      int status = redisAsyncCommand(db->ctx, db_getsFlowGlobalCB, NULL, "HGETALL SFLOW|global");
      myDebug(1, "sonic getsFlowGlobal() returned %d", status);
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
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    redisReply *reply = (redisReply *)magic;
    HSPSonicCollector *coll = (HSPSonicCollector *)req_magic;
    myDebug(1, "sonic getCollectorInfoCB(%s): reply=%s",
	    coll->collectorName,
	    db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
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
	  myDebug(1, "sonic sflow collector: %s=%s", f_name->str, db_replyStr(f_val, db->replyBuf, YES));
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
    if(UTArrayN(mdata->newCollectors) == 0) {
      // got them all, now sync
      syncConfig(mod);
    }
    else {
      // we still have more to discover
      discoverNewCollectors(mod);
    }
  }

  static void db_getCollectorInfo(EVMod *mod, HSPSonicCollector *coll) {
    HSPSonicDBClient *db = db_selectClient(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db) {
      myDebug(1, "sonic getCollectorInfo(%s)", coll->collectorName);
      int status = redisAsyncCommand(db->ctx, db_getCollectorInfoCB, coll, "HGETALL SFLOW_COLLECTOR|%s", coll->collectorName);
      myDebug(1, "sonic getCollectorInfo(%s) returned %d", coll->collectorName, status);
    }
  }

  static bool discoverNewCollectors(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    // kick off just one - starts a chain reaction if there are more.
    HSPSonicCollector *coll = UTArrayPop(mdata->newCollectors);
    if(coll) {
      db_getCollectorInfo(mod, coll);
      return YES;
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

    myDebug(1, "sonic getCollectorNamesCB: reply=%s", db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    markCollectors(mod);
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements > 0) {
      for(int ii = 0; ii < reply->elements; ii++) {
	redisReply *elem = reply->element[ii];
	if(elem->type == REDIS_REPLY_STRING) {
	  char *p = elem->str;
#define HSP_SONIC_MAX_COLLECTORNAME_LEN 512
	  char buf[HSP_SONIC_MAX_COLLECTORNAME_LEN];
	  char *pcmem = parseNextTok(&p, sep, YES, 0, NO, buf, HSP_SONIC_MAX_COLLECTORNAME_LEN);
	  if(my_strequal(pcmem, "SFLOW_COLLECTOR")) {
	    char *collectorName = parseNextTok(&p, sep, YES, 0, NO, buf, HSP_SONIC_MAX_COLLECTORNAME_LEN);
	    if(collectorName) {
	      HSPSonicCollector *coll = getCollector(mod, collectorName, YES);
	      coll->mark = NO;
	      UTArrayPush(mdata->newCollectors, coll);
	    }
	  }
	}
      }
    }
    if(deleteMarkedCollectors(mod) > 0
       && UTArrayN(mdata->newCollectors) == 0) {
      // collector(s) deleted and none added, so we need to sync here.
      // Otherwise the sync happens when the new collector(s) are fully discovered.
      syncConfig(mod);
    }

    // if this was initial startup then we need to bump the state-machine forward here
    if(mdata->state == HSP_SONIC_STATE_CONNECTED)
      mdata->state = HSP_SONIC_STATE_DISCOVER;
  }

  static void db_getCollectorNames(EVMod *mod) {
    HSPSonicDBTable *dbTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(db_selectTab(dbTab)) {
      myDebug(1, "sonic getCollectorNames()");
      int status = redisAsyncCommand(dbTab->dbClient->ctx,
				     db_getCollectorNamesCB,
				     dbTab->separator,
				     "KEYS SFLOW_COLLECTOR|*");
      myDebug(1, "sonic getCollectorNames() returned %d", status);
    }
  }

  /*_________________---------------------------__________________
    _________________      dbEvt_subscribe      __________________
    -----------------___________________________------------------
  */

  typedef void (*opCBFn)(EVMod *mod, char *key, char *op);

#if 0
  static void dbEvt_counterOp(EVMod *mod, char *portOID, char *op) {
    myDebug(1, "sonic dbEvt_counterOp: %s (%s)", portOID, op);
  }

  static void dbEvt_sflowInterfaceOp(EVMod *mod, char *key, char *op) {
    myDebug(1, "sonic dbEvt_sflowInterfaceOp: %s (%s)", key, op);
    // This is a no-op because we will still poll counters for all
    // interfaces and the sampling-rate settings are controlled
    // externally (and learned in mod_psample).
  }
#endif

  static void dbEvt_lagOp(EVMod *mod, char *memberStr, char *op) {
    myDebug(1, "sonic dbEvt_lagOp: %s (%s)", memberStr, op);
    db_getLagInfo(mod);
  }

  static void dbEvt_sflowOp(EVMod *mod, char *key, char *op) {
    myDebug(1, "sonic dbEvt_sflowOp: %s (%s)", key, op);
    db_getsFlowGlobal(mod);
  }

  static void dbEvt_sflowCollectorOp(EVMod *mod, char *key, char *op) {
    myDebug(1, "sonic dbEvt_sflowCollectorOp: %s (%s)", key, op);
    db_getCollectorNames(mod);
  }

  static void dbEvt_subscribeCB(redisAsyncContext *ctx, void *magic, void *req_magic)
  {
    HSPSonicDBClient *db = (HSPSonicDBClient *)ctx->ev.data;
    EVMod *mod = db->mod;
    redisReply *reply = (redisReply *)magic;
    myDebug(3, "sonic dbEvt_subscribeCB: reply=%s",
	    db_replyStr(reply, db->replyBuf, YES));
    if(reply == NULL)
      return;
    if(reply->type == REDIS_REPLY_ARRAY
       && reply->elements == 4) {
      if(debug(3)) {
	for(int ii = 0; ii < reply->elements; ii++) {
	  redisReply *elem = reply->element[ii];
	  myDebug(1, "sonic dbEvt_subscribeCB: (%d)=%s", ii, db_replyStr(elem, db->replyBuf, YES));
	}
      }
      opCBFn opCB = (opCBFn)req_magic;
      opCB(mod, reply->element[2]->str, reply->element[3]->str);
    }
  }

  static void dbEvt_subscribePattern(EVMod *mod, char *pattern, opCBFn opCB, HSPSonicDBClient *db) {
    int status = redisAsyncCommand(db->ctx,
				   dbEvt_subscribeCB,
				   opCB,
				   pattern);
    myDebug(1, "sonic dbEvt_subscribePattern() returned %d", status);
  }

  static void dbEvt_subscribe(EVMod *mod) {
    myDebug(1, "sonic dbEvt_subscribe");
    // SFLOW and LAG settings are in the CONFIG_DB table, whose events client
    // was added in addEventClients(), so it should be available to us here:
    HSPSonicDBTable *configTab = getDBTable(mod, HSP_SONIC_DB_CONFIG_NAME);
    if(configTab) {
      HSPSonicDBClient *db = configTab->evtClient;
      if(db
	 && db->sock) {
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@4__:PORTCHANNEL_MEMBER*", dbEvt_lagOp, db);
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@4__:SFLOW|global*", dbEvt_sflowOp, db);
	dbEvt_subscribePattern(mod,  "psubscribe __keyspace@4__:SFLOW_COLLECTOR*", dbEvt_sflowCollectorOp, db);
	// dbEvt_subscribePattern(mod,  "psubscribe __keyspace@4__:SFLOW_SESSION*", dbEvt_sflowInterfaceOp, db);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________    syncConfig             __________________
    -----------------___________________________------------------
  */

  static void syncConfig(EVMod *mod) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    myDebug(1, "sonic syncConfig");
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
      EVEventTxAll(sp->rootModule, HSPEVENT_INTFS_CHANGED, NULL, 0);
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

    myDebug(1, "evt_poll_intf_read(%s)", adaptor->deviceName);
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

    if(mdata->state != HSP_SONIC_STATE_RUN
       && mdata->state != HSP_SONIC_STATE_DISCOVER)
      return; // this can happen if we lose the redis connection and go back

    myDebug(1, "pollCounters(adaptor=%s)", adaptor->deviceName);

    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);

    if(nio->loopback)
      return;

    if(nio->bond_master) {
      // trigger synthesizeBondMetaData
      accumulateNioCounters(sp, adaptor, NULL, NULL);
      return;
    }

    HSPSonicPort *prt = getPort(mod, adaptor->deviceName, NO);
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
      // used to wait for evt_config_changed
      // but now we start with no config (like DNS-SD)
      // so get things started here after a polite
      // startup delay of one tick:
      mdata->state = HSP_SONIC_STATE_CONNECT;
      break;
    case HSP_SONIC_STATE_CONNECT:
      // got config - try to connect
      loadDBConfig(mod);
      addEventClients(mod);
      db_connect(mod);
      break;
    case HSP_SONIC_STATE_CONNECTED:
      // connected - learn config
      db_getMeta(mod);
      dbEvt_subscribe(mod);
      // the next step is to read the starting agent/polling/collector
      // config. Any subsequent changes will be detected via dbEvt.
      db_getsFlowGlobal(mod);
      db_getCollectorNames(mod);
      break;
    case HSP_SONIC_STATE_DISCOVER:
      // learn dynamic port->oid mappings
      db_getPortNames(mod);
      db_getLagInfo(mod);
      break;
    case HSP_SONIC_STATE_RUN:
      // check for new ports
      if(!discoverNewPorts(mod))
	mapPorts(mod);
      syncSwitchPorts(mod);
      discoverNewCollectors(mod);
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
    _________________   port by osIndex         __________________
    -----------------___________________________------------------
  */

  static HSPSonicPort *getPortByOsIndex(EVMod *mod, uint32_t osIndex) {
    HSP_mod_SONIC *mdata = (HSP_mod_SONIC *)mod->data;
    HSPSonicPort search = { .osIndex = osIndex };
    return UTHashGet(mdata->portsByOsIndex, &search);
  }

  /*_________________---------------------------__________________
    _________________       evt_flow_sample     __________________
    -----------------___________________________------------------
   packet bus
  */

  static void evt_flow_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSPPendingSample *ps = (HSPPendingSample *)data;
    // find and translate all ifIndex fields from the OS (Linux) ifIndex namespace to
    // the SONiC ifIndex namespace. For packet samples that means:
    // 1. sampler ds_index
    // 2. flow_sample input, output ports
    // If a mapping is missing for the sampler we have to block the sample.
    // If a mapping is missing for in/out ports we have to zero it out (0 == unknown)
    uint32_t osIndex = SFL_DS_INDEX(ps->sampler->dsi);
    HSPSonicPort *prt = getPortByOsIndex(mod, osIndex);
    if(prt == NULL || prt->ifIndex == HSP_SONIC_IFINDEX_UNDEFINED) {
      // block this sample from being sent out.
      // TODO: if sample_pool is maintained upstream then it
      // may need to be adjusted here.
      ps->suppress = YES;
    }
    else {
      // fix datasource
      sfl_sampler_set_dsAlias(ps->sampler, prt->ifIndex);
      // fix in/out
      if(ps->fs->input
	 && ps->fs->input != SFL_INTERNAL_INTERFACE) {
	// translate, or mark unknown
	HSPSonicPort *in = getPortByOsIndex(mod, ps->fs->input);
	ps->fs->input = (in && in->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	  ? in->ifIndex
	  : 0;
      }
      if(ps->fs->output
	 && ps->fs->output != SFL_INTERNAL_INTERFACE
	 && (ps->fs->output & 0x80000000) == 0) {
	// translate, or mark unknown
	HSPSonicPort *out = getPortByOsIndex(mod, ps->fs->output);
	ps->fs->output = (out && out->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	  ? out->ifIndex
	  : 0;
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       evt_cntr_sample     __________________
    -----------------___________________________------------------
  */

  static void evt_cntr_sample(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
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
    HSPSonicPort *prt = getPortByOsIndex(mod, osIndex);
    if(prt == NULL || prt->ifIndex == HSP_SONIC_IFINDEX_UNDEFINED) {
      // block this sample from being sent out
      ps->suppress = YES;
    }
    else {
      // fix datasource
      sfl_poller_set_dsAlias(ps->poller, prt->ifIndex);
      // look through counter structures
      for(SFLCounters_sample_element *elem = ps->cs->elements;
	  elem != NULL;
	  elem = elem->nxt) {
	if(elem->tag == SFLCOUNTERS_GENERIC) {
	  // fix generic ifIndex
	  elem->counterBlock.generic.ifIndex = prt->ifIndex;
	}
	else if(elem->tag == SFLCOUNTERS_LACP) {
	  // fix LAG aggregation ID
	  uint32_t aggID = elem->counterBlock.lacp.attachedAggID;
	  if(aggID) {
	    // translate, or mark unknown
	    HSPSonicPort *lagPort = getPortByOsIndex(mod, aggID);
	    elem->counterBlock.lacp.attachedAggID = (lagPort && lagPort->ifIndex != HSP_SONIC_IFINDEX_UNDEFINED)
	      ? lagPort->ifIndex
	      : 0;
	  }
	}
      }
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
    mdata->dbInstances = UTHASH_NEW(HSPSonicDBClient, dbInstance, UTHASH_SKEY);
    mdata->dbTables = UTHASH_NEW(HSPSonicDBTable, dbTable, UTHASH_SKEY);
    mdata->portsByName = UTHASH_NEW(HSPSonicPort, portName, UTHASH_SKEY);
    mdata->portsByOsIndex = UTHASH_NEW(HSPSonicPort, osIndex, UTHASH_DFLT);
    mdata->collectors = UTHASH_NEW(HSPSonicCollector, collectorName, UTHASH_SKEY);
    mdata->newPorts = UTArrayNew(UTARRAY_DFLT);
    mdata->unmappedPorts = UTArrayNew(UTARRAY_DFLT);
    mdata->newCollectors = UTArrayNew(UTARRAY_DFLT);
    // retainRootRequest(mod, "Needed to call out to OPX scripts (PYTHONPATH)");

#ifdef HSP_SONIC_TEST_REDISONLY
    // don't allow readInterfaces to destroy 'imaginary'
    // adaptors we added that were found in db.
    sp->allowDeleteAdaptor = NO;
#endif

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
    EVEventRx(mod, EVGetEvent(mdata->pollBus, HSPEVENT_INTF_COUNTER_SAMPLE), evt_cntr_sample);
  }


#if defined(__cplusplus)
} /* extern "C" */
#endif
