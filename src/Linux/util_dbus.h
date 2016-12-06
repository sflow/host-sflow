/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef UTIL_DBUS_H
#define UTIL_DBUS_H 1

#if defined(__cplusplus)
extern "C" {
#endif

  void parseDBusMessage(DBusMessage *msg);
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_DBUS_H */
