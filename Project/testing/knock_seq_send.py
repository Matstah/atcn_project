#!/usr/bin/env python
import os
import argparse
import sys
import socket
import random
import struct
import logging as log
import threading

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

# get mac address for ethernet header based on dst and an option
def get_mac(host, option=None):
    if option == 'broadcast':
        return 'ff:ff:ff:ff:ff:ff'
    else:
        return topo.get_host_mac(host)

def send(dst, knock_seq,secret_port, showPacket=False):
    log.debug('Sending knocks to port {}'.format(knock_seq))
    ip_addr = get_host_ip(dst)
    iface = get_if()

    ether_src = get_if_hwaddr(iface)
    log.debug("ether_src={}".format(ether_src))

    ether_dst = get_mac(dst)
    log.debug("ether_dst={}".format(ether_dst))

    # info before actions
    log.info("sending on interface %s to %s" % (iface, str(ip_addr)))

    sport = random.randint(1025,49151)
    send_knock_timeout(knock_seq, ether_src, ether_dst, iface, ip_addr, sport, secret_port)
    time.sleep(3)

    sport = random.randint(1025,49151)
    send_wrong_knock(knock_seq, ether_src, ether_dst, iface, ip_addr, sport, secret_port)
    time.sleep(3)

    send_knock_under_noise(knock_seq, ether_src, ether_dst, iface, ip_addr, secret_port)



def send_knock_timeout(knock_seq, ether_src, ether_dst, iface, ip_addr, sport, secret_port):
    print"-----------------send knock with timeout-------------------"
    count = 1
    timeout = 6
    for port in knock_seq:
        pkt = Ether(src=ether_src, dst=ether_dst)
        #build layers: ether / IP / UDP / app
        pkt = pkt / IP(dst=ip_addr) / UDP(dport=int(port), sport=sport) / "Hello {}. knock#{}".format(ip_addr, count)
        sendp(pkt, iface=iface, verbose=False)
        log.info("knock %s send to port %s" % (count, int(port)))
        if count == 2:
            log.warning("sleep %s sec to create timeout in knock sequence" % (timeout))
            time.sleep(timeout)
        count += 1
        time.sleep(1)
        #if False:
        #    print('The following packet was sent:')
        #    pkt.show()
        #    print('-'*20)
    log.info("correct k_seq send, due to timeout no access granted-> check tcpdump behind firewall")
    num_packet=1
    send_tcp_traffic(sport, ip_addr, num_packet, secret_port, ether_dst, ether_src, iface)

def send_wrong_knock(knock_seq, ether_src, ether_dst, iface, ip_addr, sport, secret_port):
    print"-------------send wrong knock, then correct-----------------"
    count = 1
    timeout = 3

    for port in knock_seq:
        pkt = Ether(src=ether_src, dst=ether_dst)
        #build layers: ether / IP / UDP / app
        if count == 2:
            log.warning("wrong knock is send:")
            port = 555
        pkt = pkt / IP(dst=ip_addr) / UDP(dport=int(port), sport=sport) / "Hello {}. knock#{}".format(ip_addr, count)
        sendp(pkt, iface=iface, verbose=False)
        log.info("knock %s send to port %s" % (count, int(port)))
        count += 1
        time.sleep(1)
    print"------->correct knock:"
    time.sleep(3)
    for port in knock_seq:
        pkt = Ether(src=ether_src, dst=ether_dst)
        #build layers: ether / IP / UDP / app
        pkt = pkt / IP(dst=ip_addr) / UDP(dport=int(port), sport=sport) / "Hello {}. knock#{}".format(ip_addr, count)
        sendp(pkt, iface=iface, verbose=False)
        log.info("knock %s send to port %s" % (count, int(port)))
        count += 1
        time.sleep(1)

    num_packet=1
    send_tcp_traffic(sport, ip_addr, num_packet, secret_port, ether_dst, ether_src, iface)


def send_knock_under_noise(knock_seq, ether_src, ether_dst, iface, ip_addr, secret_port):
    noise_stop = threading.Event()
    log.critical("noise thread running:")
    noise_thread = threading.Thread(target=udp_noise, args=(1, noise_stop, ip_addr, ether_src, ether_dst, iface))
    noise_thread.start()
    knockers = []
    time.sleep(1)
    for k in range(3):
        t = threading.Thread(target=correct_port_knocker, args=(k, knock_seq, ether_src, ether_dst, iface, ip_addr, secret_port))
        t.start()
        knockers.append(t)
    for t in knockers: # hack to wait till all threads are done.
        t.join() #waits till thread has finished
    noise_stop.set()
    log.critical("All knocks are done. Noise thread stoped")


def send_tcp_traffic(sport, ip_addr, num_packet, secret_port, ether_dst, ether_src, iface):
    log.info('Sending {} tcp packets to secret port {}'.format(num_packet, secret_port))
    time.sleep(1)
    count = 1
    for _ in range(num_packet):
        pkt = Ether(src=ether_src, dst=ether_dst)
        pkt = pkt / IP(dst=ip_addr) / TCP(dport=secret_port, sport=sport) / "Hello {}:{} #{}".format(ip_addr,secret_port, count)
        sendp(pkt, iface=iface, verbose=False)
        count += 1


def correct_port_knocker(arg1, knock_seq, ether_src, ether_dst, iface, ip_addr, secret_port):
    print"-----------------send correct knock, sender {}--------------------".format(arg1)
    count = 1
    sport = random.randint(1025,49151)
    for port in knock_seq:
        t_next = random.randint(0,35)/10
        time.sleep(t_next)
        pkt = Ether(src=ether_src, dst=ether_dst)
        #build layers: ether / IP / UDP / app
        pkt = pkt / IP(dst=ip_addr) / UDP(dport=int(port), sport=sport) / "Hello {}. knock#{}".format(ip_addr, count)
        sendp(pkt, iface=iface, verbose=False)
        log.info("Sender %s knock %s send to port %s" % (arg1,count, int(port)))
        count += 1

    log.info("k_seq send from port %s" % (sport))
    num_packet=1
    send_tcp_traffic(sport, ip_addr, num_packet, secret_port, ether_dst, ether_src, iface)


def udp_noise(arg1, stop_event, ip_addr,ether_src, ether_dst, iface):
    print("...........udp noise thread started..........")
    counter =1
    while not stop_event.isSet():
        time.sleep(0.01)
        counter += 1
        sport = random.randint(1, 65534)
        dport = random.randint(1,50000)
        src_ip = RandIP()
        pkt = Ether(src=ether_src, dst=ether_dst)
        #build layers: ether / IP / UDP / app
        pkt = pkt / IP(dst=ip_addr,src=src_ip) / UDP(dport=dport, sport=sport) / "Hello {}. knock#{}".format(ip_addr, counter)
        sendp(pkt, iface=iface, verbose=False)
        #print"--> packet send from {} port {} to port{}".format(src_ip,sport,dport)
    print" {} udp packets send to ip_addr {}".format(counter, ip_addr)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #COMMAND:
    #sudo python testing/knock_seq_send.py --local --src he2 --dst hi2 -k 100 101 102 103

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--src', type=str, required=False, help='Source host NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')

    # args for actual functionality
    parser.add_argument('-d', '--dst',     type=str, required=True, help='Destination NAME or IPv4')
    parser.add_argument('-k','--knock_seq', default = [], required=False, nargs ='+', help='dst ports to knock on')

    #parser.add_argument('--sleep', type=float, required=False, default=0.0, help='Sleep time between packets')
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
        # TODO: open receive terminals first
        #if(args.receive):
        #    os.system("xterm -e 'bash -c \"sudo apt-get update; exec bash\"'")

        # call script on host with same params, plus on_remote flag to avoid loop
        from subprocess import call
        cmd = ["mx", args.src, 'python'] + sys.argv + ['--on_remote']
        log.debug("Run the following command:\n{}".format(cmd))
        call(cmd)
    else:
        # load globals
        topo = Topology(db="/home/p4/atcn-project/Project/topology.db")
        secret_port = 3141
        send(args.dst, args.knock_seq, secret_port , showPacket=args.show)
# END MAIN
