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
SYNACK_FLAG=0x12
FIN_FLAG=1
FINACK_FLAG=0x10

# COLORS for nicer printing
def red(str):
    return _col(str, 91)
def green(str):
    return _col(str, 92)
def yellow(str):
    return _col(str, 93)
def blue(str):
    return _col(str, 94)
def _col(s, code):
    return '\033[{}m'.format(code) + str(s) + '\033[0m'

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

# copied (and modified for our purpose)
# from: https://gist.github.com/tintinweb/8523a9a43a2fb61a6770 handle_recv
def tcp_flags(pkt):
    if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[TCP].flags & 2 != 0:
            return 'SYN'
        elif pkt[TCP].flags & 0x3f == 0x12:   # SYN+ACK
            # log.debug("RCV: SYN+ACK")
            return 'SYNACK'
        elif  pkt[TCP].flags & 4 != 0:      # RST
            # log.debug("RCV: RST")
            return 'RST'
        elif pkt[TCP].flags & 16 != 0:      # ACK
            return 'ACK'
        elif pkt[TCP].flags & 0x1 == 1:     # FIN
            # log.debug("RCV: FIN")
            return 'FIN'
        elif pkt[TCP].flags & 0x3f == 0x10: # FIN+ACK
            # log.debug("RCV: FIN+ACK")
            return 'FINACK'
    return 'UNKNOWN'

# sends SYN, waits for SYNACK and preparses tcp ACK
def handshake_part1(eth, ip, sport, dport, seq):
    SYN=TCP(sport=sport, dport=dport, flags="S", seq=seq)
    pkt = eth/ip/SYN
    log.debug('SEND {} with ack={}, seq={}'.format(tcp_flags(pkt), pkt.ack, pkt.seq))
    SYNACK=srp1(pkt, verbose=0, timeout=3) # sends packet and waits for corresponding response
    try:
        log.debug('GOT {} with ack={}, seq={}'.format(tcp_flags(SYNACK), SYNACK.ack, SYNACK.seq))
    except Exception:
        print(red('WAITING FOR **SYNACK** TIMED OUT. TRY AGAIN...\n(PS: is server.py running? or restart server.py as well!)'))
        exit(1)
    seq = seq + 1
    # log.debug('Is new seq == other.ack? ' + str(seq == SYNACK.ack))
    ACK=TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=(SYNACK.seq+1))
    return [ACK, seq]

# not truly the second part of the handshake... Now we could send data already according
# to 'normal' TCP, but we check first if firewall might not reset the connection and
# send therefore another ACK. If we get an ACK again, it was from the server, else
# try again (then now the firewall has hopefully allowed us to access server)
def handshake_part2(eth, ip, sport, dport, ACK, seq):
    pkt = eth/ip/ACK
    log.debug('SEND {} with ack={}, seq={}'.format(tcp_flags(pkt), pkt.ack, pkt.seq))
    response = srp1(pkt, verbose=0, timeout=3)
    try:
        log.debug('GOT {} with ack={}, seq={}'.format(tcp_flags(response), response.ack, response.seq))
    except Exception:
        print(red('WAITING FOR **ACK** TIMED OUT. WE EXPECT THIS TO COME FROM THE SERVER HERE!\n'
            + 'Is the server running in the appropriate state? Maybe restart server first and then this again!\n'
            + 'ALSO: if the client is validated from the server, the synflooder might interfere with this test,\n'
            + 'because he spoofs this address the server will SYNACK the wrong packet, that this script does '
            + 'not understand. So maybe disable the synflooder or adapt variable START_IP there and '
            + 'change from 0 to 2...'))
        exit(1)
    type = tcp_flags(response)
    if type == 'ACK':
        seq = seq + 1
        ACK=TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=(response.seq+1))
        return [ACK, seq, True]
    else:
        return [None, 100, False]

def client_tcp_start(src, dst, packets, sleep, i_am_bad):
    log.debug('TCP handshake and {} data packets with {}'.format(packets, dst))
    src_ip = get_host_ip(src)
    dst_ip = get_host_ip(dst)
    iface = get_if()

    ether_src = get_if_hwaddr(iface)
    # log.debug("ether_src={}".format(ether_src))

    ether_dst = topo.get_host_mac(dst)
    # log.debug("ether_dst={}".format(ether_dst))

    # info before actionss
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
    connection_established = False
    while not connection_established:
        ACK, seq = handshake_part1(eth, ip, sport, dport, seq)
        sleepy_time = 1
        print('sleep for {} seconds'.format(sleepy_time))
        time.sleep(sleepy_time)
        ACK, seq, connection_established = handshake_part2(eth, ip, sport, dport, ACK, seq)
        log.debug('Connection established? ' + str(connection_established))
        if not connection_established:
            print(green('Connection not yet established, because did not get ACK after my ACK of SYNACK.\n'
                + 'Firewall has probably sent RST. So let\'s try again with a new handshake!'))
        time.sleep(2.0) # sleep a little before next try or continuation

    # send data or only SYNs
    if i_am_bad:
        for _ in range(packets):
            SYN=TCP(sport=RandShort(), dport=dport, flags="S", seq=RandShort())
            attack = eth/ip/SYN
            log.debug('SEND ' + tcp_flags(attack) + ' with ack={}, seq={}'.format(attack.ack, attack.seq))
            sendp(attack, verbose=0)
            time.sleep(0.1)
        log.debug('sent all SYNs')
    else:
        count = 1
        while count <= packets:
            data = eth/ip/ACK/'This is the {}. line!'.format(count)
            log.debug('SEND ' + tcp_flags(data) + ' with data and ack={}, seq={}'.format(data.ack, data.seq))
            response = srp1(data, verbose=0, timeout=3)
            seq = seq + 1
            log.debug('GOT ' + tcp_flags(response))
            ACK=TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=(response.seq+1))
            time.sleep(sleep)
            count = count + 1
        log.debug('sent all data')


    # TODO: terminate session? maybe make optional?


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
    parser.add_argument('--bad', action='store_true', required=False, help='Bad client that only sends SYNs after a successful handshake')

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
        exit(0)
    else:
        # load globals
        script_path = os.path.split(os.path.abspath(__file__))[0]
        topo = Topology(db=script_path+'/../topology.db')

        # start
        client_tcp_start(args.src, args.dst, args.packets, args.sleep, args.bad)
# END MAIN
