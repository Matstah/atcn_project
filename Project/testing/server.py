#!/usr/bin/env python
import sys
import os
import socket
import random
import argparse
import logging as log
import time

sys.path.append('/home/p4/atcn-project/Utils')
from TopoHelper import TopoHelper

from scapy.all import *

# CONSTANTS
TOPO_FILE = '../topology.db'

# HELPER
def get_interface():
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

# SERVER
class Server():
    def __init__(self, name):
        self.helper = TopoHelper(TOPO_FILE, disable_print=True)
        self.name = name

        self.node_infos = {}
        self.ip = self.get_info(self.name, 'IP')
        self.interface = get_interface()
        self.flows = {}

    # SERVER HELPER
    def get_info(self, node, info):
        if hasattr(self, info):
            return getattr(self, info)
        elif not hasattr(self.node_infos, node):
            self.node_infos[node] = self.helper.node_info(node)
        return self.node_infos[node][info]

    # SERVER FUNCS
    def answer_syn(self, pkt):
        log.debug('answer_syn called')
        log.debug('packet content:\n' + pkt.show(dump=True))
        eth = pkt.getlayer(Ether)
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)

        # register flow
        id = '{}:{}'.format(ip.src, tcp.sport)
        self.flows[id] = Ether(src=eth.dst, dst=eth.src)/IP(src=ip.dst, dst=ip.src)

        # send (SYN)ACK
        dport=tcp.sport
        sport=tcp.dport
        seq = 300
        SYNACK = TCP(sport=sport, dport=dport, flags = 'A', seq=seq, ack=(tcp.seq+1))
        answer = self.flows[id] / SYNACK
        log.debug('prepared answer:\n' + answer.show(dump=True))

        # ack all received data
        while True:
            data_pkt = srp1(answer, timeout=3, verbose=0)
            # data_pkt.show()
            seq = seq + 1

            try:
                tcp = data_pkt.getlayer(TCP)
            except:
                break
            print(tcp.payload)
            # print(tcp.seq)
            ACK = TCP(sport=sport, dport=dport, flags = 'A', seq=seq, ack=(tcp.seq+1))
            answer = self.flows[id] / ACK
            time.sleep(1) # waits a second to ack the data packet

        print('CONNECTION TO {} TERMINATED'.format(id))



    def send(dst):
        ## TODO:
        a = 1


    # SERVER RUN
    def run(self):
        log.debug('wait for SYN on interface ' + self.interface)
        sniff(iface=self.interface, prn=lambda x: self.answer_syn(x), count=1)

        print('WE ARE DONE HERE')
        # while True:
        #     print('Server is running')
        #     time.sleep(3.0)

# MAIN
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--server', type=str, required=False, default='ser', help='server NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')

    # other args
    parser.add_argument('--debug', action='store_true', required=False, help='Activate debug messages')

    # parse arguments
    args = parser.parse_args()

    # configure debugger
    if(args.debug):
        log.basicConfig(stream=sys.stderr, level=log.DEBUG)
    else:
        log.basicConfig(stream=sys.stderr, level=log.INFO)

    # start receving from host or dispatch to host
    if (args.local and not args.on_remote):
        # call script on host with same params, plus on_remote flag to avoid loop
        from subprocess import call
        cmd = ["mx", args.server, 'python'] + sys.argv + ['--on_remote']
        log.debug("Run the following command:\n{}".format(cmd))
        call(cmd)
    else:
        server = Server(args.server)
        server.run()
