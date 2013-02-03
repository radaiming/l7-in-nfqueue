#!/usr/bin/env python2
# coding:utf-8

import sys
import os
import re
from netfilterqueue import NetfilterQueue

if len(sys.argv) == 1:
    print 'usage: ' + os.path.basename(sys.argv[0]) + ' path-to-protocol-config-file'
    exit(1)
config_file = open(sys.argv[1],'r')
pattern = ''
for line in config_file:
    if not line.startswith('#') and line.strip('\n') != os.path.basename(sys.argv[1])[0:-4] and len(line):
        pattern = line.strip('\n')

def print_and_accept(pkt):
    ip_payload = pkt.get_payload()
    if ip_payload[9] == '\x06':                 # tcp
        layer7_payload = ip_payload[40:]
    elif ip_payload[9] == '\x11':               # udp
        layer7_payload = ip_payload[28:]

    if re.match(pattern,layer7_payload):
        print 'package droped,length ' + str(len(layer7_payload))
        pkt.drop()
    else:
        #print 'package accepted,length ' + str(len(layer7_payload))
        pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
nfqueue.unbind()
