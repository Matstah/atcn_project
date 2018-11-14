#!/usr/bin/env python
import os
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
        #pkt = pkt / IP(dst=addr) / TCP(dport=7777, sport)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--src', type=str, required=False, help='Source host in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')

    # args for actual functionality
    parser.add_argument('-d', '--dst',     type=str, required=True, help='Destination name')
    parser.add_argument('-p', '--packets', type=int, required=True, help='Number of packets')
    args = parser.parse_args()

    if (args.local and not args.on_remote):
        # call script on host with same params, plus on_remote flag to avoid loop
        from subprocess import call
        cmd = ["mx", args.src, 'python'] + sys.argv + ['--on_remote']
        print("Run the following command:\n{}".format(cmd))
        call(cmd)
    else:
        send(args.dst, args.packets)
