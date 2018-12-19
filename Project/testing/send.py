#!/usr/bin/env python
import os
import argparse
import sys
import socket
import random
import struct
import logging as log

from p4utils.utils.topology import Topology
from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP
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

# get mac address for ethernet header based on dst and an option
def get_mac(host, option=None):
    if option == 'broadcast':
        return 'ff:ff:ff:ff:ff:ff'
    else:
        return topo.get_host_mac(host)

def send(dst, packets, sleep, udp, i2e=False, showPacket=False):
    log.debug('Sending {} packets to {}'.format(packets, dst))
    ip_addr = get_host_ip(dst)
    iface = get_if()

    ether_src = get_if_hwaddr(iface)
    log.debug("ether_src={}".format(ether_src))

    ether_dst = get_mac(dst)
    log.debug("ether_dst={}".format(ether_dst))

    # info before actions
    log.info("sending on interface %s to %s" % (iface, str(ip_addr)))

    # the actual work
    # sport = random.randint(49152,65535)
    sport = 101 if i2e else 105;
    dport = 105 if i2e else 101;
    msg = "Hello {}. #{}"
    transport = UDP(dport=dport, sport=sport) if udp else TCP(dport=dport, sport=sport)
    count = 0
    for _ in range(packets):
        count = count + 1
        pkt = Ether(src=ether_src, dst=ether_dst)
        pkt = pkt / IP(dst=ip_addr) / transport / msg.format(dst, count)
        sendp(pkt, iface=iface, verbose=False)
        if showPacket:
            print('The following packet was sent:')
            pkt.show()
            print('-'*20)
        time.sleep(sleep)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--src', type=str, required=False, help='Source host NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')

    # args for actual functionality
    parser.add_argument('-d', '--dst',     type=str, required=True, help='Destination NAME or IPv4')
    parser.add_argument('-p', '--packets', type=int, required=False, default=1, help='Number of packets')
    parser.add_argument('-u', '--udp', action='store_true', required=False, help='If protocol should be UDP instead of TCP')
    parser.add_argument('--sleep', type=float, required=False, default=0.0, help='Sleep time between packets')
    parser.add_argument('--show', action='store_true', required=False, help='If set, all sent packets are printed')

    # other args
    parser.add_argument('--debug', action='store_true', required=False, help='Activate debug messages')

    parser.add_argument('--i2e', action='store_true', required=False, help='If set: sport=101, dport=105, otherwise the opposite.'
                        + '[simultate flow between external and internal host]')

    # parse arguments
    args = parser.parse_args()

    # configure debugger
    if(args.debug):
        log.basicConfig(stream=sys.stderr, level=log.DEBUG)
    else:
        log.basicConfig(stream=sys.stderr, level=log.INFO)

    # start sending from host or dispatch to host
    if (args.local and not args.on_remote):
        # call script on host with same params, plus on_remote flag to avoid loop
        from subprocess import call
        cmd = ["mx", args.src, 'python'] + sys.argv + ['--on_remote']
        log.debug("Run the following command:\n{}".format(cmd))
        call(cmd)
    else:
        # load globals
        script_path = os.path.split(os.path.abspath(__file__))[0]
        topo = Topology(db=script_path+'/../topology.db')

        # start
        send(args.dst, args.packets, args.sleep, args.udp, args.i2e, showPacket=args.show)
# END MAIN
