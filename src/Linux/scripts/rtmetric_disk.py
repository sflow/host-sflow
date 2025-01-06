#!/usr/bin/env python3

# Send JSON-encoded rtmetric through hsflowd to provide
# separate moniting of every local disk partition.

# Requires "json {udpport=36343 }" in hsflowd.conf.

# This should be executed periodically e.g. by cron(1)
# or like this at the shell prompt for testing:
# while true; do ./rtmetric_disk.py; sleep 10; done

import socket
import json
import time
import os
import re

# we are going to translate '/' to '_' in the mount point names
transtab = str.maketrans("/", "_")

# match the subset of mount points that we want to report on
pattern = re.compile('^/$|^/tmp|^/usr/')

# open socket to send to hsflowd
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# get data from df(1) command
p = os.popen("df --output='target,pcent'")

for line in p.read().splitlines() :
    toks = line.split()
    target = toks[0]
    pcent = toks[1]
    if pcent[-1:] == "%" and pattern.match(target):
        mname = "MNT" + target.translate(transtab)
        # construct rtmetric message
        msg = {
            'rtmetric': {
                'datasource': mname,
                'disk_mount': { "type":"string", "value": target },
                    'disk_util': { "type":"gauge32", "value": pcent[:-1] }
            }
        }
        # print json.dumps(msg)
        sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 36343))
p.close()
