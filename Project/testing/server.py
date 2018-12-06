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
SYNACK_FLAG=0x12
FIN_FLAG=1
FINACK_FLAG=0x10

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

# copied (and modified) from: https://gist.github.com/tintinweb/8523a9a43a2fb61a6770 handle_recv
def tcp_flags(pkt):
    if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[TCP].flags & 2 != 0:
            return 'SYN' # TODO: ???
        elif pkt[TCP].flags & 0x3f == 0x12:   # SYN+ACK
            # log.debug("RCV: SYN+ACK")
            return 'SYNACK'
        elif pkt[TCP].flags & 16 != 0:      # ACK
            return 'ACK' # TODO: ????
        elif  pkt[TCP].flags & 4 != 0:      # RST
            # log.debug("RCV: RST")
            return 'RST'
        elif pkt[TCP].flags & 0x1 == 1:     # FIN
            # log.debug("RCV: FIN")
            return 'FIN'
        elif pkt[TCP].flags & 0x3f == 0x10: # FIN+ACK
            # log.debug("RCV: FIN+ACK")
            return 'FINACK'
    return 'UNKNOWN'

# SERVER
class Server():
    def __init__(self, name, firewall, bad_client):
        self.helper = TopoHelper(TOPO_FILE, disable_print=True)
        self.name = name
        self.act_as_firewall = firewall
        self.client_is_bad = bad_client

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
    def listen_to_syns(self, pkt):
        log.debug('GOT {} with ack={}, seq={}'.format(tcp_flags(pkt), pkt.ack, pkt.seq))

    def answer_syn(self, pkt):
        log.debug('answer_syn called')
        # log.debug('packet content:\n' + pkt.show(dump=True))
        log.debug('GOT {} with ack={}, seq={}'.format(tcp_flags(pkt), pkt.ack, pkt.seq))
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
        SYNACK = TCP(sport=sport, dport=dport, flags = SYNACK_FLAG, seq=seq, ack=(tcp.seq+1))
        answer = self.flows[id] / SYNACK
        # log.debug('prepared answer:\n' + answer.show(dump=True))

        # RST first handshake to simulate firewall behaviour
        if self.act_as_firewall:
            print('ACT AS FIREWALL')
            # TODO: basically do what the firewall does with the RST messages for testing
            # TODO: not really needed yet, because the firewall behaves as it should
            # TODO: if we implement it, then we have to redo, the above!


        # ack all received data (or just listen if client is bad)
        if self.client_is_bad:
            # finish handshake
            data_pkt = srp1(answer, timeout=3, verbose=0)
            log.debug('GOT {} with ack={}, seq={}'.format(tcp_flags(data_pkt), data_pkt.ack, data_pkt.seq))
            seq = seq + 1
            tcp = data_pkt.getlayer(TCP)
            ACK = TCP(sport=sport, dport=dport, flags = 'A', seq=seq, ack=(tcp.seq+1))
            answer = self.flows[id] / ACK
            sendp(answer, verbose=0)
            log.debug('Just listen now...')
            sniff(iface=self.interface, prn=lambda x: self.listen_to_syns(x))
        else:
            while True:
                log.debug('SEND {} with ack={}, seq={}'.format(tcp_flags(answer), answer.ack, answer.seq))
                data_pkt = srp1(answer, timeout=3, verbose=0)
                # data_pkt.show()
                seq = seq + 1

                try:
                    tcp = data_pkt.getlayer(TCP)
                    log.debug('GOT {} with ack={}, seq={}'.format(tcp_flags(data_pkt), data_pkt.ack, data_pkt.seq))
                except:
                    break
                print(tcp.payload)
                # print(tcp.seq)
                ACK = TCP(sport=sport, dport=dport, flags = 'A', seq=seq, ack=(tcp.seq+1))
                answer = self.flows[id] / ACK
                time.sleep(1) # waits a second to ack the data packet

        print('CONNECTION TO {} TERMINATED'.format(id))


    # SERVER RUN
    def run(self):
        log.debug('wait for SYN on interface ' + self.interface)
        sniff(iface=self.interface, prn=lambda x: self.answer_syn(x), count=1)

        print('WE ARE DONE HERE')

# MAIN
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--server', type=str, required=False, default='ser', help='server NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')
    parser.add_argument('--bad', action='store_true', required=False, help='If we expect a bad client, just print, what you get after handshake')

    # other args
    parser.add_argument('--firewall', action='store_true', required=False, help='[NOT IMPLEMENTED] Flag to set if server should act like the firewall and send RST after first handshake')
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
        exit(0)
    else:
        server = Server(args.server, args.firewall, args.bad)
        server.run()
