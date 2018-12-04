#!/usr/bin/env python
import os
import argparse
import sys
import socket
import random
import struct
import logging as log

from p4utils.utils.topology import Topology
from scapy.all import *
import time
import re

# GLOBALS
topo=None

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# resolves host to ipv4 and checks first if
def get_host_ip(host):
    if not re.match(r'(\d{1,3}\.){3}\d{1,3}', host):
        return topo.get_host_ip(host)
    else:
        return socket.gethostbyname(host)

def client_tcp_start(src, dst, packets, sleep, showPacket=False):
    log.debug('TCP handshake and {} packets with {}'.format(packets, dst))
    src_ip = get_host_ip(src)
    dst_ip = get_host_ip(dst)
    iface = get_if()

    ether_src = get_if_hwaddr(iface)
    log.debug("ether_src={}".format(ether_src))

    ether_dst = topo.get_host_mac(dst)
    log.debug("ether_dst={}".format(ether_dst))

    # info before actions
    log.info("sending on interface %s from %s to %s" % (iface, str(src_ip), str(dst_ip)))

    # the actual work
    dport = 80
    # fixed sport because we manually suppress Linux RST msgs
    # see: http://blog.facilelogin.com/2010/12/hand-crafting-tcp-handshake-with-scapy.html
    sport = 1500
    seq = 100
    eth = Ether(src=ether_src, dst=ether_dst)
    ip = IP(src=src_ip, dst=dst_ip)

    # HANDSHAKE
    SYN=TCP(sport=sport, dport=dport, flags="S", seq=seq)
    SYNACK=srp1(eth/ip/SYN) # sends packet and waits for corresponding response
    seq = seq + 1
    ACK=TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=(SYNACK.seq+1))
    time.sleep(sleep)

    # send data
    count = 1
    while count <= packets:
        response = srp1(eth/ip/ACK/'This is the {}. line!'.format(count))
        seq = seq + 1
        ACK=TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=(response.seq+1))
        time.sleep(sleep)
        count = count + 1

    log.debug('sent all data')

    # count = 0
    # for _ in range(packets):
    #     count = count + 1
    #     pkt =
    #     pkt = pkt / ip / TCP(dport=80, sport=sport) / "Hello {}. #{}".format(dst, count)
    #     sendp(pkt, iface=iface, verbose=False)
    #     if showPacket:
    #         print('The following packet was sent:')
    #         pkt.show()
    #         print('-'*20)
    #     time.sleep(sleep)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--src', type=str, required=True, help='Source host NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')

    # args for actual functionality
    parser.add_argument('-d', '--dst',     type=str, required=False, default='ser', help='Destination NAME or IPv4 [default server]')
    parser.add_argument('-p', '--packets', type=int, required=False, default=5, help='Number of packets AFTER HANDSHAKE [default 5]')
    parser.add_argument('--sleep', type=float, required=False, default=0.1, help='Sleep time between packets [default 0.1]')
    parser.add_argument('--show', action='store_true', required=False, help='If set, all sent packets are printed')

    # other args
    parser.add_argument('--debug', action='store_true', required=False, help='Activate debug messages')

    # parse arguments
    args = parser.parse_args()

    # configure debugger
    if(args.debug):
        log.basicConfig(stream=sys.stderr, level=log.DEBUG)
    else:
        log.basicConfig(stream=sys.stderr, level=log.INFO)

    # start sending from host or dispatch to host
    if (args.local and not args.on_remote):
        from subprocess import call
        cmd = ["mx", args.src, 'python'] + sys.argv + ['--on_remote']
        log.debug("Run the following command:\n{}".format(cmd))
        call(cmd)
    else:
        # load globals
        topo = Topology(db="/home/p4/atcn-project/Project/topology.db")

        client_tcp_start(args.src, args.dst, args.packets, args.sleep, showPacket=args.show)
# END MAIN
