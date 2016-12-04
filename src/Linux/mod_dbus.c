/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

/* with grateful reference to:
 * http://www.spinics.net/lists/bluez-devel/msg00109.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/types.h>
#include <sys/prctl.h>
#include <sched.h>
#include <dbus/dbus.h>
#define HSP_TELEMETRY_NAMES 1
#include "hsflowd.h"

  typedef void (*HSPDBusHandler)(EVMod *mod, DBusMessage *dbm, void *magic);

  typedef struct _HSP_mod_DBUS {
    DBusConnection *connection;
    DBusError error;
    int dbus_soc;
    uint32_t dbus_tx;
    uint32_t dbus_rx;
    EVBus *pollBus;
  } HSP_mod_DBUS;


static const char* introspect_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\";>\n"
"<node>\n"
"	<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
"		<method name=\"Introspect\">\n"
"			<arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
"		</method>\n"
"	</interface>\n"
"	<interface name=\"org.sflow.hsflowd.telemetry\">\n"
"		<method name=\"GetVersion\">\n"
"		</method>\n"
"		<method name=\"GetAll\">\n"
"		</method>\n"
"		<method name=\"Get\">\n"
"                     <arg name=\"field\" type=\"s\" direction=\"in\"/>\n"
"		</method>\n"
"	</interface>\n"
"</node>\n";

  static const char *hsp_version = STRINGIFY_DEF(HSP_VERSION);

  /*_________________---------------------------__________________
    _________________    utils to help debug    __________________
    -----------------___________________________------------------
  */

  static void log_dbus_error(EVMod *mod, char *msg) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    if (dbus_error_is_set(&mdata->error))
      myLog(LOG_ERR, "DBUS Error(%s) = %s", msg, mdata->error.message);
    else if(msg)
      myLog(LOG_ERR, "DBUS Error(%s)", msg);
  }

  static const char *messageTypeStr(int mtype)  {
    switch (mtype) {
    case DBUS_MESSAGE_TYPE_SIGNAL: return "signal";
    case DBUS_MESSAGE_TYPE_METHOD_CALL: return "method_call";
    case DBUS_MESSAGE_TYPE_METHOD_RETURN: return "method_return";
    case DBUS_MESSAGE_TYPE_ERROR:  return "error";
    default: return "(unknown message type)";
    }
  }

  /*_________________---------------------------__________________
    _________________    parseDbusElem          __________________
    -----------------___________________________------------------
  */

  static void indent(UTStrBuf *buf, int depth) {
    for(int ii = 0; ii < depth; ii++)
      UTStrBuf_append(buf, "  ");
  }

#define PARSE_DBUS_VAR(it,type,format,buf) do {	\
    type val;					\
    dbus_message_iter_get_basic(it, &val);	\
    UTStrBuf_printf(buf, format, val);		\
} while(0)
  
  static void parseDBusElem(DBusMessageIter *it, UTStrBuf *buf, bool ind, int depth, char *suffix) {
    if(ind) indent(buf, depth);
    int atype = dbus_message_iter_get_arg_type(it);
    switch(atype) {
    case DBUS_TYPE_INVALID: break;
    case DBUS_TYPE_STRING: PARSE_DBUS_VAR(it, char *, "\"%s\"", buf); break;
    case DBUS_TYPE_OBJECT_PATH: PARSE_DBUS_VAR(it, char *, "obj=%s", buf); break;
    case DBUS_TYPE_BYTE: PARSE_DBUS_VAR(it, uint8_t, "0x%02x", buf); break;
    case DBUS_TYPE_INT16: PARSE_DBUS_VAR(it, int16_t, "%d", buf); break;
    case DBUS_TYPE_INT32: PARSE_DBUS_VAR(it, int32_t, "%d", buf); break;
    case DBUS_TYPE_INT64: PARSE_DBUS_VAR(it, int64_t, "%"PRId64, buf); break;
    case DBUS_TYPE_UINT16: PARSE_DBUS_VAR(it, uint16_t, "%u", buf); break;
    case DBUS_TYPE_UINT32: PARSE_DBUS_VAR(it, uint32_t, "%u", buf); break;
    case DBUS_TYPE_UINT64: PARSE_DBUS_VAR(it, uint64_t, "%"PRIu64, buf); break;
    case DBUS_TYPE_DOUBLE: PARSE_DBUS_VAR(it, double, "%f", buf); break;
    case DBUS_TYPE_BOOLEAN: { 
      dbus_bool_t val;
      dbus_message_iter_get_basic(it, &val);
      UTStrBuf_printf(buf, "%s", val ? "true":"false");
      break;
    }
    case DBUS_TYPE_VARIANT: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      UTStrBuf_printf(buf, "(");
      parseDBusElem(&sub, buf, NO, depth+1, ")");
      break;
    }
    case DBUS_TYPE_ARRAY: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      // handle empty array
      int elemType = dbus_message_iter_get_arg_type(&sub);
      if(elemType == DBUS_TYPE_INVALID) {
	UTStrBuf_printf(buf, "[]");
      }
      else {
	UTStrBuf_printf(buf, "[\n");
	do parseDBusElem(&sub, buf, YES, depth+1, ",\n");
	while (dbus_message_iter_next(&sub));
	indent(buf, depth);
	UTStrBuf_printf(buf, "]");
      }
      break;
    }
    case DBUS_TYPE_DICT_ENTRY: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      // iterate over key-value pairs (usually only one pair)
      do {
	parseDBusElem(&sub, buf, NO, depth+1, " => ");
	dbus_message_iter_next(&sub);
	parseDBusElem(&sub, buf, NO, depth+1, NULL);
      }
      while (dbus_message_iter_next(&sub));
      break;
    }
    case DBUS_TYPE_STRUCT: {
      DBusMessageIter sub;
      dbus_message_iter_recurse(it, &sub);
      UTStrBuf_printf(buf, "struct {\n");
      do parseDBusElem(&sub, buf, YES, depth+1, ",\n");
      while (dbus_message_iter_next(&sub));
      indent(buf, depth);
      UTStrBuf_printf(buf, "}");
      break;
    }
    default:
      UTStrBuf_printf(buf, "unknown-type=%d", atype);
      break;
    }
    if(suffix) UTStrBuf_append(buf, suffix);
  }


  /*_________________---------------------------__________________
    _________________    parseDbusMessage       __________________
    -----------------___________________________------------------
  */

  static void parseDBusMessage(EVMod *mod, DBusMessage *msg) {
    // HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    myLog(LOG_INFO, "DBUS: dbusCB got message");
    int mtype = dbus_message_get_type(msg);
    const char *src = dbus_message_get_sender(msg);
    const char *dst = dbus_message_get_destination(msg);
    UTStrBuf *buf = UTStrBuf_new();
    UTStrBuf_printf(buf, "DBUS %s->%s %s(",
		    src?:"<no src>", 
		    dst?:"<no dst>", 
		    messageTypeStr(mtype));
    UTStrBuf_printf(buf, "(");
    switch(mtype) {
    case DBUS_MESSAGE_TYPE_METHOD_CALL:
    case DBUS_MESSAGE_TYPE_SIGNAL:
      UTStrBuf_printf(buf, "serial=%u,path=%s,interface=%s,member=%s",
		      dbus_message_get_serial(msg),
		      dbus_message_get_path(msg),
		      dbus_message_get_interface(msg),
		      dbus_message_get_member(msg));
      break;
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
      UTStrBuf_printf(buf, "reply_serial=%u",
		      dbus_message_get_reply_serial(msg));
      break;
    case DBUS_MESSAGE_TYPE_ERROR:
      UTStrBuf_printf(buf, "error_name=%s,reply_serial=%u",
		      dbus_message_get_error_name(msg),
		      dbus_message_get_reply_serial(msg));
      break;
    default:
      break;
    }
    UTStrBuf_printf(buf, ") {");
    DBusMessageIter iterator;
    if(dbus_message_iter_init(msg, &iterator)) {
      do parseDBusElem(&iterator, buf, YES, 1, "\n");
      while (dbus_message_iter_next(&iterator));
    }
    UTStrBuf_append(buf, "}\n");
    myDebug(1, "DBUS message: %s", buf->buf);
    UTStrBuf_free(buf);
  }
  

  /*_________________---------------------------__________________
    _________________         evt_deci          __________________
    -----------------___________________________------------------
  */
  
  static void evt_deci(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    uint32_t curr_tx = mdata->dbus_tx;
    uint32_t curr_rx = mdata->dbus_rx;
    for(;;) {
      // keep iterating here as long as visible progress is made
      dbus_connection_read_write_dispatch(mdata->connection, 0);
      if(curr_tx == mdata->dbus_tx &&
	 curr_rx == mdata->dbus_rx)
	break;
      curr_tx = mdata->dbus_tx;
      curr_rx = mdata->dbus_rx;
    }
  }

  /*_________________---------------------------__________________
    _________________         evt_final         __________________
    -----------------___________________________------------------
  */

  static void evt_final(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    if(mdata->connection) {
      dbus_connection_close(mdata->connection);
      mdata->connection = NULL;
    }
  }

  /*_________________---------------------------__________________
    _________________       send_reply          __________________
    -----------------___________________________------------------
  */
  static void send_reply(EVMod *mod, DBusMessage *reply) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    dbus_connection_send(mdata->connection, reply, NULL);
    mdata->dbus_tx++;
  }
  /*_________________---------------------------__________________
    _________________       send_reply_err      __________________
    -----------------___________________________------------------
  */

  static void send_reply_err(EVMod *mod, DBusMessage *msg, char *errm) {
    DBusMessage *reply_err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, errm);
    send_reply(mod, reply_err);
    dbus_message_unref(reply_err);
  }

  /*_________________---------------------------__________________
    _________________     method_introspect     __________________
    -----------------___________________________------------------
  */

  static DBusHandlerResult method_introspect(EVMod *mod, DBusMessage *msg) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    dbus_message_append_args(reply,
			     DBUS_TYPE_STRING, &introspect_xml,
			     DBUS_TYPE_INVALID);
    send_reply(mod, reply);    
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________     method_getVersion     __________________
    -----------------___________________________------------------
  */
  static DBusHandlerResult method_getVersion(EVMod *mod, DBusMessage *msg) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    dbus_message_append_args(reply,
			     DBUS_TYPE_STRING, &hsp_version,
			     DBUS_TYPE_INVALID);
    send_reply(mod, reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________     method_getAll         __________________
    -----------------___________________________------------------
    with reference to:
    http://git.kernel.org/cgit/network/connman/connman.git/tree/gdbus/object.c
  */
  static DBusHandlerResult method_getAll(EVMod *mod, DBusMessage *msg) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    DBusMessageIter it1, it2, it3;
    dbus_message_iter_init_append(reply, &it1);
    if(!dbus_message_iter_open_container(&it1, DBUS_TYPE_ARRAY, "{sx}", &it2))
      return DBUS_HANDLER_RESULT_NEED_MEMORY;

    for(int ii = 0; ii < HSP_TELEMETRY_NUM_COUNTERS; ii++) {
      if(!dbus_message_iter_open_container(&it2, DBUS_TYPE_DICT_ENTRY, NULL, &it3))
	return DBUS_HANDLER_RESULT_NEED_MEMORY;
      dbus_message_iter_append_basic(&it3, DBUS_TYPE_STRING, &HSPTelemetryNames[ii]);
      dbus_message_iter_append_basic(&it3, DBUS_TYPE_INT64, &sp->telemetry[ii]);
      dbus_message_iter_close_container(&it2, &it3);
    }

    dbus_message_iter_close_container(&it1, &it2);

    send_reply(mod, reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________     method_get            __________________
    -----------------___________________________------------------
  */
  static DBusHandlerResult method_get(EVMod *mod, DBusMessage *msg) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    DBusMessageIter it;
    if(!dbus_message_iter_init(msg, &it))
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    int atype = dbus_message_iter_get_arg_type(&it);
    if(atype != DBUS_TYPE_STRING) {
      send_reply_err(mod, msg, "expected string arg");
      return DBUS_HANDLER_RESULT_HANDLED;
    }
    char *varname=NULL;
    uint64_t *pval64=NULL;
    dbus_message_iter_get_basic(&it, &varname);
    for(int ii = 0; ii < HSP_TELEMETRY_NUM_COUNTERS; ii++) {
      if(my_strequal(varname, HSPTelemetryNames[ii]))
	pval64 = &sp->telemetry[ii];
    }
    if(!pval64) {
      send_reply_err(mod, msg, "unknown field");
      return DBUS_HANDLER_RESULT_HANDLED;
    }
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    dbus_message_append_args(reply, DBUS_TYPE_INT64, pval64,  DBUS_TYPE_INVALID);
    send_reply(mod, reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________       dbusCB              __________________
    -----------------___________________________------------------
  */

static DBusHandlerResult dbusCB(DBusConnection *connection, DBusMessage *msg, void *user_data)
{
  EVMod *mod = user_data;
  HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
  mdata->dbus_rx++;
  
  if(debug(2))
    parseDBusMessage(mod, msg);
  
  switch(dbus_message_get_type(msg)) {

  case DBUS_MESSAGE_TYPE_METHOD_CALL: {
    const char *method = dbus_message_get_member(msg);
    const char *iface = dbus_message_get_interface(msg);
    if(!strcmp("org.freedesktop.DBus.Introspectable", iface)) {
      if(!strcmp("Introspect", method)) return method_introspect(mod, msg);
    }
    else if(!strcmp("org.sflow.hsflowd.telemetry", iface)) {
      if(!strcmp("GetVersion", method)) return method_getVersion(mod, msg);
      if(!strcmp("GetAll", method)) return method_getAll(mod, msg);
      if(!strcmp("Get", method)) return method_get(mod, msg);
    }
    break;
  }

  case DBUS_MESSAGE_TYPE_METHOD_RETURN:
  case DBUS_MESSAGE_TYPE_SIGNAL:
  case DBUS_MESSAGE_TYPE_ERROR:
  default:
    break;
      
  }  
  
  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

  /*_________________---------------------------__________________
    _________________    addMatch               __________________
    -----------------___________________________------------------
  */
#if 0
  static void addMatch(EVMod *mod, char *type) {
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    char rule[128];
    sprintf(rule, "eavesdrop=true,type='%s'", type);
    dbus_bus_add_match(mdata->connection, rule, &mdata->error);
    if(dbus_error_is_set(&mdata->error)) {
      myLog(LOG_ERR, "DBUS: addMatch() error adding <%s>", rule);
    }
  }
#endif
  
  static void unregister(DBusConnection *connection, void *user_data) { }
  
  static DBusObjectPathVTable agent_table = {
    .unregister_function = unregister,
    .message_function = dbusCB,
  };
  
  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  void mod_dbus(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_DBUS));
    HSP_mod_DBUS *mdata = (HSP_mod_DBUS *)mod->data;
    // HSP *sp = (HSP *)EVROOTDATA(mod);

    // this mod operates entirely on the pollBus thread
    mdata->pollBus = EVGetBus(mod, HSPBUS_POLL, YES);
    dbus_error_init(&mdata->error);
    if((mdata->connection = dbus_bus_get(DBUS_BUS_SYSTEM, &mdata->error)) == NULL) {
      myLog(LOG_ERR, "dbus_bug_get error");
      return;
    }

    //addMatch(mod, "signal");
    //addMatch(mod, "method_call");
    //addMatch(mod, "method_return");
    //addMatch(mod, "error");

    if(!dbus_connection_add_filter(mdata->connection, dbusCB, mod, NULL)) {
      log_dbus_error(mod, "dbus_connection_add_filter");
      return;
    }

    // request name
    dbus_bus_request_name(mdata->connection, "org.sflow.hsflowd", DBUS_NAME_FLAG_REPLACE_EXISTING, &mdata->error);
    if(dbus_error_is_set(&mdata->error)) {
      log_dbus_error(mod, "dbus_bus_request_name");
    }

    if(!dbus_connection_register_object_path(mdata->connection, "/org/sflow/hsflowd", &agent_table, mod)) {
      log_dbus_error(mod, "dbus_connection_register_object_path");
      return;
    }

    // TODO: add introspection
    
    // connection OK - so register call-backs
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_DECI), evt_deci);
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_FINAL), evt_final);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
