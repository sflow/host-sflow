/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef UTIL_DBUS_H
#define UTIL_DBUS_H 1

#if defined(__cplusplus)
extern "C" {
#endif

  void parseDBusMessage(DBusMessage *msg);

  // DBusBasicValue is not always defined in dbus-types.h,  but we
  // only use .bool_val and .str so the easiest solution is to define
  // our own version of it here:
  typedef union {
    unsigned char bytes[8]; // make sure it's always at least 8 bytes
    dbus_bool_t  bool_val;
    char *str;
  } MyDBusBasicValue;
  
#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* UTIL_DBUS_H */
