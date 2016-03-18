#!/usr/bin/env python

# command-line utility to send JSON-encoded rtflow records through hsflowd.
# requires "jsonPort=36343" in hsflowd.conf.

import argparse
import json
import socket

parser = argparse.ArgumentParser(epilog="Repeat name, type and value options to send multiple attributes.")
parser.add_argument("-d", "--datasource",
  dest="datasource", required=True,
  help="datasource name")
parser.add_argument("-s", "--samplingrate",
  dest="samplingrate", required=False, type=int,
  help="sampling rate")
parser.add_argument("-n", "--name",
  dest="name", action="append", required=True,
  help="attribute name")
parser.add_argument("-t", "--type",
  dest="type", action="append", required=True,
  choices=["string","mac","ip","ip6","int32","int64","float","double"],
  help="attribute type")
parser.add_argument("-v", "--value",
  dest="value", action="append", required=True,
  help="attribute value")
args = parser.parse_args()

metrics = {"datasource":args.datasource}
if 'samplingrate' in args:
  metrics["sampling_rate"] = args.samplingrate

for i in range(0, len(args.name)):
  val = args.value[i]
  if args.type[i] in {"int32","int64","float","double"}:
    try:
      val = int(val)
    except ValueError:
      val = float(val)

  metrics[args.name[i]]={"type":args.type[i],'value':val}

msg = {"rtflow":metrics}
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.sendto(json.dumps(msg),("127.0.0.1",36343))
