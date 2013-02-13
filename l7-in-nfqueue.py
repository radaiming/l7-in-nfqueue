#!/usr/bin/env python2
# coding:utf-8

import sys
import os
import re
from netfilterqueue import NetfilterQueue

###### seems could not pass argument to pkt_check in nfqueue.bind(1, pkt_check),so use some global variables ######
global regex
global patterns
patterns = []

def print_parse_err_msg():
    print 'if you want to use l7 pattern file:' + os.path.basename(sys.argv[0]) + ' /path/to/your/l7_pattern_file'
    print 'if you want to use regex to search payload in layer 7,add -P'
    exit(1)

def print_pkt_drop_info(ip_payload,ip_header_length,pkt_length):
    src_addr = str(ord(ip_payload[12])) + '.' + str(ord(ip_payload[13])) + '.' + str(ord(ip_payload[14])) + '.' + str(ord(ip_payload[15]))
    dst_addr = str(ord(ip_payload[16])) + '.' + str(ord(ip_payload[17])) + '.' + str(ord(ip_payload[18])) + '.' + str(ord(ip_payload[19]))
    src_port = str(int(hex(ord(ip_payload[ip_header_length:ip_header_length + 1]))[2:] + hex(ord(ip_payload[ip_header_length + 1:ip_header_length + 2]))[2:],16))
    dst_port = str(int(hex(ord(ip_payload[ip_header_length + 2:ip_header_length + 3]))[2:] + hex(ord(ip_payload[ip_header_length + 3:ip_header_length + 4]))[2:],16))
    #print 'packet dropped,from  ' + (src_addr + ':' + src_port).ljust(21) + '  to  ' + (dst_addr + ':' + dst_port).ljust(21) + '  with length ' + str(pkt_length).ljust(4) + ' bytes'
    print 'packet dropped: ' + (src_addr + ':' + src_port).ljust(21) + ' --> ' + (dst_addr + ':' + dst_port).ljust(21) + ' | ' + str(pkt_length).ljust(4) + ' bytes'

def pkt_check(pkt):
    global regex
    global patterns
    ip_payload = pkt.get_payload()
    ip_header_length = (ord(ip_payload[0]) & 15)*4
    if ip_payload[9] == '\x06':                 ####### tcp ####### 
        tcp_header_length = ((ord(ip_payload[ip_header_length + 13 - 1]) & 240) >> 4)*4
        layer7_payload = ip_payload[ip_header_length + tcp_header_length:]
    elif ip_payload[9] == '\x11':               ####### udp ####### 
        udp_header_length = 8
        layer7_payload = ip_payload[ip_header_length + udp_header_length:]

    ACCEPT_THIS_PKT = True
    if regex:
        for pattern in patterns:
            if re.search(pattern,layer7_payload):
                print_pkt_drop_info(ip_payload,ip_header_length,pkt.get_payload_len())
                pkt.drop()
                ACCEPT_THIS_PKT = False
                break
        if ACCEPT_THIS_PKT:
            pkt.accept()
    else:
        for pattern in patterns:
            if re.search(pattern,layer7_payload.replace('\x00',''),flags=re.IGNORECASE):
                print_pkt_drop_info(ip_payload,ip_header_length,pkt.get_payload_len())
                pkt.drop()
                ACCEPT_THIS_PKT = False
                break
        if ACCEPT_THIS_PKT:
            pkt.accept()

def parse_arg_and_patterns():
    global regex
    global patterns
    ####### read & check arguments #######

    path_to_pattern_files = list(sys.argv)[1:]
    if len(path_to_pattern_files) < 2:
        print_parse_err_msg()
    if '-P' in path_to_pattern_files:
        regex = True
        path_to_pattern_files.remove('-P')
    elif '-e' in path_to_pattern_files:
        regex = True
        path_to_pattern_files.remove('-e')
    else:
        regex = False

    for path_to_pattern_file in path_to_pattern_files:
        if not os.path.exists(path_to_pattern_file):
            print 'file ' + path_to_pattern_file + ' does not exist'
            exit(1)
    
    ####### read l7 pattern file #######
    for path_to_pattern_file in path_to_pattern_files:
        pattern_file = open(path_to_pattern_file,'r')
        for line in pattern_file:
            if not line.startswith('#') and not line.startswith('userspace') and line.strip() != os.path.basename(path_to_pattern_file)[0:-4] and len(line.strip()):
                patterns.append(line.strip())
        pattern_file.close()

def main():
    parse_arg_and_patterns()
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, pkt_check)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print
    finally:
        nfqueue.unbind()

if __name__ == '__main__':
    main()
