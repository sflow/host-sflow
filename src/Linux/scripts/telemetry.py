#!/usr/bin/python
import dbus
bus = dbus.SystemBus()
sflow = bus.get_object('net.sflow.hsflowd', '/net/sflow/hsflowd')
sflow_telemetry = dbus.Interface(sflow, dbus_interface='net.sflow.hsflowd.telemetry')

print "hsflowd version is: " + sflow_telemetry.GetVersion()
print "datagrams sent = " + str(sflow_telemetry.Get("datagrams"))

