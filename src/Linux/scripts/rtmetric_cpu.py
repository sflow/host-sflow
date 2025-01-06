#!/usr/bin/env python3

# Send JSON-encoded rtmetric messages through hsflowd to provide
# separate moniting of every CPU.

# Requires "json { udpport=36343 }" in hsflowd.conf.

# This should be executed periodically e.g. by cron(1)
# or like this at the shell prompt for testing:
# while true; do ./rtmetric_cpu.py; sleep 10; done

import re
import socket
import json
import time
cpuPattern = re.compile('cpu[0-9]+')
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
inputfile=open('/proc/stat')
for line in inputfile:
    toks=line.split()
    if cpuPattern.match(toks[0]) :
        msg = {
            'rtmetric': {
                'datasource': toks[0],
                'cpu_x_user': { "type":"counter32", "value": int(toks[1]) },
                'cpu_x_nice': { "type":"counter32", "value": int(toks[2]) },
                'cpu_x_system': { "type":"counter32", "value": int(toks[3]) },
                'cpu_x_idle': { "type":"counter32", "value": int(toks[4]) },
                'cpu_x_wio': { "type":"counter32", "value": int(toks[5]) },
                'cpu_x_intr': { "type":"counter32", "value": int(toks[6]) },
                'cpu_x_sintr': { "type":"counter32", "value": int(toks[7]) }
            }
        }
        sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 36343))
inputfile.close()
