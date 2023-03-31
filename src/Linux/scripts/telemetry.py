#!/usr/bin/python3
import dbus
bus = dbus.SystemBus()

# Note that without root permissions the introspection will fail
# with an error, but subsequent requests should still succeed.

sflow = bus.get_object('net.sflow.hsflowd', '/net/sflow/hsflowd')

# telemetry
sflow_telemetry = dbus.Interface(sflow, dbus_interface='net.sflow.hsflowd.telemetry')
#print ("all telemetry = " + str(sflow_telemetry.GetAll()))
print ("hsflowd version is: " + sflow_telemetry.GetVersion())
print ("hsflowd agent IP address is: " + sflow_telemetry.GetAgent())
print ("packet samples dropped internally = " + str(sflow_telemetry.Get("dropped_samples")))
print ("packet samples sent = " + str(sflow_telemetry.Get("flow_samples")))
print ("counter samples sent = " + str(sflow_telemetry.Get("counter_samples")))
print ("drop event samples sent = " + str(sflow_telemetry.Get("event_samples")))
print ("drop event samples suppressed = " + str(sflow_telemetry.Get("event_samples_suppressed")))
print ("datagrams sent = " + str(sflow_telemetry.Get("datagrams")))

# switchport
sflow_switchport = dbus.Interface(sflow, dbus_interface='net.sflow.hsflowd.switchport')
#print ("port enp0s5 = " + str(sflow_switchport.Get("enp0s5"))
for port in sflow_switchport.GetAll():
  print ("port=" + port[0] + " speed =" + str(port[1]) + " sampling_n=" + str(port[2]) + " polling_secs=" + str(port[3]))

