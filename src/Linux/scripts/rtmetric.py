#!/usr/bin/env python3

# command-line utility to send JSON-encoded rtmetric values through hsflowd.
# requires "json { udpport=36343 }" in hsflowd.conf.

import argparse
import json
import socket

parser = argparse.ArgumentParser(epilog="Repeat name, type and value options to send multiple metrics.")
parser.add_argument("-d", "--datasource",
  dest="datasource", required=True,
  help="datasource name")
parser.add_argument("-n", "--name",
  dest="name", action="append", required=True,
  help="metric name")
parser.add_argument("-t", "--type",
  dest="type", action="append", required=True,
  choices=["string","counter32","counter64","gauge32","gauge64","gaugeFloat","gaugeDouble"],
  help="metric type")
parser.add_argument("-v", "--value",
  dest="value", action="append", required=True,
  help="metric value")
args = parser.parse_args()

metrics = {"datasource":args.datasource}
for i in range(0, len(args.name)):
  val = args.value[i]
  if "string" != args.type[i]:
    try:
      val = int(val)
    except ValueError:
      val = float(val)

  metrics[args.name[i]]={"type":args.type[i],'value':val}

msg = {"rtmetric":metrics}
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.sendto(json.dumps(msg),("127.0.0.1",36343))
