#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP
import time

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def send(dst, packets):
    print('Sending {} packets to {}'.format(packets, dst))
    addr = socket.gethostbyname()
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))

    for _ in range(packets):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / TCP(dport=7777, sport)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dst',     type=str, required=True, help='Destination name')
    parser.add_argument('-p', '--packets', type=int, required=True, help='Number of packets')
    args = parser.parse_args()

    send(args.dst, args.packets)
