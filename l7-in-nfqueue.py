#!/usr/bin/env python2
# coding:utf-8

import sys
import os
import re
from netfilterqueue import NetfilterQueue

def print_err_msg():
    print 'if you want to use l7 pattern file:' + os.path.basename(sys.argv[0]) + ' /path/to/your/l7_pattern_file'
    print 'if you want to use regex to search payload in layer 7,add -P'
    exit(1)

def print_pkt_drop_info(ip_payload,ip_header_length,pkt_length):
    src_addr = str(ord(ip_payload[12])) + '.' + str(ord(ip_payload[13])) + '.' + str(ord(ip_payload[14])) + '.' + str(ord(ip_payload[15]))
    dst_addr = str(ord(ip_payload[16])) + '.' + str(ord(ip_payload[17])) + '.' + str(ord(ip_payload[18])) + '.' + str(ord(ip_payload[19]))
    src_port = str(int(hex(ord(ip_payload[ip_header_length:ip_header_length + 1]))[2:] + hex(ord(ip_payload[ip_header_length + 1:ip_header_length + 2]))[2:],16))
    dst_port = str(int(hex(ord(ip_payload[ip_header_length + 2:ip_header_length + 3]))[2:] + hex(ord(ip_payload[ip_header_length + 3:ip_header_length + 4]))[2:],16))
    print 'packet dropped,from ' + (src_addr + ':' + src_port).ljust(21) + ' to ' + (dst_addr + ':' + dst_port).ljust(21) + ' with length ' + str(pkt_length)

def pkt_check(pkt):
    ip_payload = pkt.get_payload()
    ip_header_length = (ord(ip_payload[0]) & 15)*4
    if ip_payload[9] == '\x06':                 ####### tcp ####### 
        tcp_header_length = ((ord(ip_payload[ip_header_length + 13 - 1]) & 240) >> 4)*4
        layer7_payload = ip_payload[ip_header_length + tcp_header_length:]
    elif ip_payload[9] == '\x11':               ####### udp ####### 
        udp_header_length = 8
        layer7_payload = ip_payload[ip_header_length + udp_header_length:]

    if regex:
        if re.search(pattern,layer7_payload):
            print_pkt_drop_info(ip_payload,ip_header_length,pkt.get_payload_len())
            pkt.drop()
        else:
            pkt.accept()
    else:
        if re.search(pattern,layer7_payload.replace('\x00',''),flags=re.IGNORECASE):
            print_pkt_drop_info(ip_payload,ip_header_length,pkt.get_payload_len())
            pkt.drop()
        else:
            pkt.accept()

####### read arguments #######
if len(sys.argv) == 3:
    if sys.argv[1].startswith('-'):
        argument = sys.argv[1]
        path_to_pattern_file = sys.argv[2]
    elif sys.argv[2].startswith('-'):
        argument = sys.argv[2]
        path_to_pattern_file = sys.argv[1]
    else:
        print_err_msg()
elif len(sys.argv) == 2:
    argument = ''
    path_to_pattern_file = sys.argv[1]
else:
    print_err_msg()

####### check argument #######
if argument == '-P':
    regex = 1
else:
    regex = 0
if not os.path.exists(path_to_pattern_file):
    print 'file ' + path_to_pattern_file + ' does not exist'
    exit(1)

####### read l7 pattern file #######
pattern_file = open(path_to_pattern_file,'r')
for line in pattern_file:
    if not line.startswith('#') and not line.startswith('userspace') and line.strip('\n') != os.path.basename(sys.argv[1])[0:-4] and len(line):
        pattern = line.strip('\n')
pattern_file.close()

####### now start checking packets from nfqueue #######
nfqueue = NetfilterQueue()
nfqueue.bind(1, pkt_check)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
nfqueue.unbind()
