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
#include "util_dbus.h"

  typedef void (*HSPDBusHandler)(EVMod *mod, DBusMessage *dbm, void *magic);

  typedef struct _HSP_mod_DBUS {
    DBusConnection *connection;
    DBusError error;
    int dbus_soc;
    uint32_t dbus_tx;
    uint32_t dbus_rx;
    EVBus *pollBus;
  } HSP_mod_DBUS;

#define HSP_DBUS_OBJ "/net/sflow/" HSP_DAEMON_NAME
#define HSP_DBUS_NAME "net.sflow." HSP_DAEMON_NAME
#define HSP_DBUS_INTF_TELEMETRY HSP_DBUS_NAME ".telemetry"
#define HSP_DBUS_INTF_SWITCHPORT HSP_DBUS_NAME ".switchport"

static const char* introspect_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node>\n"
"	<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
"		<method name=\"Introspect\">\n"
"			<arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
"		</method>\n"
"	</interface>\n"
"	<interface name=\"" HSP_DBUS_INTF_TELEMETRY "\">\n"
"		<method name=\"GetVersion\">\n"
"		</method>\n"
"		<method name=\"GetAgent\">\n"
"		</method>\n"
"		<method name=\"GetAll\">\n"
"		</method>\n"
"		<method name=\"Get\">\n"
"                     <arg name=\"field\" type=\"s\" direction=\"in\"/>\n"
"		</method>\n"
"	</interface>\n"
"	<interface name=\"" HSP_DBUS_INTF_SWITCHPORT "\">\n"
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
    _________________        m_Introspect       __________________
    -----------------___________________________------------------
  */

  static DBusHandlerResult m_Introspect(EVMod *mod, DBusMessage *msg) {
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
    _________________     my_dbus_strdup        __________________
    -----------------___________________________------------------
  */
  
  static char *my_dbus_strdup(char *str) {
    if(str == NULL)
      return NULL;
    int len = my_strlen(str);
    char *ans = dbus_malloc(len + 1);
    strncpy(ans, str, len);
    return ans;
  }

  /*_________________---------------------------__________________
    _________________  m_telemetry_GetVersion   __________________
    -----------------___________________________------------------
  */
  static DBusHandlerResult m_telemetry_GetVersion(EVMod *mod, DBusMessage *msg) {
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
    _________________  m_telemetry_GetAgent     __________________
    -----------------___________________________------------------
  */


  static DBusHandlerResult m_telemetry_GetAgent(EVMod *mod, DBusMessage *msg) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    static char ipbuf[51];
    SFLAddress_print(&sp->agentIP, ipbuf, 50);
    // DBUS expects this to be free()-able using dbus_free(). If we don't
    // copy to heap we get a segfault.  It might be possible to supply
    // my own free function (DbusFreeFunction) but the following works
    // so no problem:
    char *ip = my_dbus_strdup(ipbuf);
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    dbus_message_append_args(reply,
			     DBUS_TYPE_STRING, &ip,
			     DBUS_TYPE_INVALID);
    send_reply(mod, reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________     m_telemetry_GetAll    __________________
    -----------------___________________________------------------
    with reference to:
    http://git.kernel.org/cgit/network/connman/connman.git/tree/gdbus/object.c
  */
  static DBusHandlerResult m_telemetry_GetAll(EVMod *mod, DBusMessage *msg) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    DBusMessageIter it1, it2, it3;
    dbus_message_iter_init_append(reply, &it1);
    if(!dbus_message_iter_open_container(&it1, DBUS_TYPE_ARRAY, "{st}", &it2))
      return DBUS_HANDLER_RESULT_NEED_MEMORY;

    for(int ii = 0; ii < HSP_TELEMETRY_NUM_COUNTERS; ii++) {
      if(!dbus_message_iter_open_container(&it2, DBUS_TYPE_DICT_ENTRY, NULL, &it3))
	return DBUS_HANDLER_RESULT_NEED_MEMORY;
      dbus_message_iter_append_basic(&it3, DBUS_TYPE_STRING, &HSPTelemetryNames[ii]);
      dbus_message_iter_append_basic(&it3, DBUS_TYPE_UINT64, &sp->telemetry[ii]);
      dbus_message_iter_close_container(&it2, &it3);
    }

    dbus_message_iter_close_container(&it1, &it2);
    send_reply(mod, reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________     m_telemetry_Get       __________________
    -----------------___________________________------------------
  */
  static DBusHandlerResult m_telemetry_Get(EVMod *mod, DBusMessage *msg) {
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
    _________________     addSwitchPort         __________________
    -----------------___________________________------------------
  */
  static void addSwitchPort(EVMod *mod, SFLAdaptor *adaptor, DBusMessageIter *it)
  {
    HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
    uint64_t speed_bps = adaptor->ifSpeed;
    uint32_t sampling_n = nio->sampling_n;
    uint32_t polling_secs = nio->poller ? nio->poller->sFlowCpInterval : 0;
    dbus_message_iter_append_basic(it, DBUS_TYPE_STRING, &adaptor->deviceName);
    dbus_message_iter_append_basic(it, DBUS_TYPE_UINT64, &speed_bps);
    dbus_message_iter_append_basic(it, DBUS_TYPE_UINT32, &sampling_n);
    dbus_message_iter_append_basic(it, DBUS_TYPE_UINT32, &polling_secs);
  }

  /*_________________---------------------------__________________
    _________________     m_switchport_Get      __________________
    -----------------___________________________------------------
  */

  static DBusHandlerResult m_switchport_Get(EVMod *mod, DBusMessage *msg) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    DBusMessageIter it;
    if(!dbus_message_iter_init(msg, &it))
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    int atype = dbus_message_iter_get_arg_type(&it);
    if(atype != DBUS_TYPE_STRING) {
      send_reply_err(mod, msg, "expected string arg");
      return DBUS_HANDLER_RESULT_HANDLED;
    }
    char *dev=NULL;
    dbus_message_iter_get_basic(&it, &dev);
    SFLAdaptor *adaptor = dev ? adaptorByName(sp, dev) : NULL;
    if(!adaptor || !ADAPTOR_NIO(adaptor)->switchPort) {
      send_reply_err(mod, msg, "not a switch port");
      return DBUS_HANDLER_RESULT_HANDLED;
    }
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    DBusMessageIter it1, it2;
    dbus_message_iter_init_append(reply, &it1);
    if(!dbus_message_iter_open_container(&it1, DBUS_TYPE_STRUCT, NULL, &it2))
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    addSwitchPort(mod, adaptor, &it2);
    dbus_message_iter_close_container(&it1, &it2);
    send_reply(mod, reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  /*_________________---------------------------__________________
    _________________     m_switchport_GetAll   __________________
    -----------------___________________________------------------
  */
  static DBusHandlerResult m_switchport_GetAll(EVMod *mod, DBusMessage *msg) {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
      return DBUS_HANDLER_RESULT_NEED_MEMORY;
    DBusMessageIter it1, it2, it3;
    dbus_message_iter_init_append(reply, &it1);
    if(!dbus_message_iter_open_container(&it1, DBUS_TYPE_ARRAY, "(stuu)", &it2))
      return DBUS_HANDLER_RESULT_NEED_MEMORY;

    SFLAdaptor *adaptor;
    UTHASH_WALK(sp->adaptorsByName, adaptor) {
      HSPAdaptorNIO *nio = ADAPTOR_NIO(adaptor);
      if(nio->switchPort) {
	if(!dbus_message_iter_open_container(&it2, DBUS_TYPE_STRUCT, NULL, &it3))
	  return DBUS_HANDLER_RESULT_NEED_MEMORY;
	addSwitchPort(mod, adaptor, &it3);
	dbus_message_iter_close_container(&it2, &it3);
      }
    }

    dbus_message_iter_close_container(&it1, &it2);
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
  
  if(EVDebug(mod, 2, NULL))
    parseDBusMessage(msg);

  switch(dbus_message_get_type(msg)) {

  case DBUS_MESSAGE_TYPE_METHOD_CALL: {
    const char *method = dbus_message_get_member(msg);
    const char *iface = dbus_message_get_interface(msg);
    if(!strcmp("org.freedesktop.DBus.Introspectable", iface)) {
      if(!strcmp("Introspect", method)) return m_Introspect(mod, msg);
    }
    else if(!strcmp(HSP_DBUS_INTF_TELEMETRY, iface)) {
      if(!strcmp("GetVersion", method)) return m_telemetry_GetVersion(mod, msg);
      if(!strcmp("GetAgent", method)) return m_telemetry_GetAgent(mod, msg);
      if(!strcmp("GetAll", method)) return m_telemetry_GetAll(mod, msg);
      if(!strcmp("Get", method)) return m_telemetry_Get(mod, msg);
    }
    else if(!strcmp(HSP_DBUS_INTF_SWITCHPORT, iface)) {
      if(!strcmp("GetAll", method)) return m_switchport_GetAll(mod, msg);
      if(!strcmp("Get", method)) return m_switchport_Get(mod, msg);
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
    _________________    registration           __________________
    -----------------___________________________------------------
  */

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

    if(!dbus_connection_add_filter(mdata->connection, dbusCB, mod, NULL)) {
      log_dbus_error(mod, "dbus_connection_add_filter");
      return;
    }

    // request name
    dbus_bus_request_name(mdata->connection, HSP_DBUS_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING, &mdata->error);
    if(dbus_error_is_set(&mdata->error)) {
      log_dbus_error(mod, "dbus_bus_request_name");
    }

    if(!dbus_connection_register_object_path(mdata->connection, HSP_DBUS_OBJ, &agent_table, mod)) {
      log_dbus_error(mod, "dbus_connection_register_object_path");
      return;
    }

    // connection OK - so register call-backs
    EVEventRx(mod, EVGetEvent(mdata->pollBus, EVEVENT_DECI), evt_deci);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
