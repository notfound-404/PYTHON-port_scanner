#!/usr/bin/env python3
# http://www.binarytides.com/python-packet-sniffer-code-linux/

import sys
import socket as s
from struct import *


protocole = {"01": "ICMP", "02": "IGMP", "06": "TCP", "17": "UDP"}


def _usage():
    print("[+] Usage: ./"+sys.argv[0]+" <ip to scan>")


def _parser(pkt):
    IP_H = pkt[0][0:20]
    IPH = unpack('!BBHHHBBH4s4s', str(IP_H))
    # IPH = unpack('!BBBBH4s4s', str(IP_H))
    print IPH
    print IPH
    VERSION = IPH[0] >> 4
    IHL = IPH[0] & 0xf
    TTL = IPH[5]
    PROTO = IPH[6] >> 2
    print VERSION+IHL+TTL+PROTO


if (len(sys.argv) < 2):
    _usage()
    exit(1)
else:
    try:
        IP = s.gethostbyname(sys.argv[1])
    except:
        print("Can't resolv this name")
        exit(2)

S = s.socket(2, 3, 6)

REPLY = S.recvfrom(65535)
_parser(REPLY)
