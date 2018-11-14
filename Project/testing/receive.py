#!/usr/bin/env python
import sys
import os
import argparse
import logging as log

from scapy.all import sniff, get_if_list, Ether, get_if_hwaddr, IP, TCP, Raw, Packet, BitField, bind_layers

LAYER_MAP = {
    'ethernet': Ether,
    'ip': IP,
    'tcp': TCP
}

def get_if():
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def isNotOutgoing(my_mac):
    my_mac = my_mac
    def _isNotOutgoing(pkt):
        return pkt[Ether].src != my_mac

    return _isNotOutgoing

def handle_pkt(pkt, layers):
    for layer in layers:
        print(layer, pkt.getlayer(LAYER_MAP[layer]))
    print


def receive(layers):
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()

    my_filter = isNotOutgoing(get_if_hwaddr(get_if()))

    sniff(iface=iface, prn=lambda x: handle_pkt(x, layers), lfilter=my_filter)
    #sniff(filter="ether proto 0x7777", iface = iface, prn = lambda x: handle_pkt(x), lfilter=my_filter)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--host', type=str, required=False, help='host NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')

    # args for actual functionality
    parser.add_argument('--layers', '-l', type=str, required=False, help='Filter header layers with space delimited list')

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
        cmd = ["mx", args.host, 'python'] + sys.argv + ['--on_remote']
        log.debug("Run the following command:\n{}".format(cmd))
        call(cmd)
    else:
        if(args.layers):
            layers = [str(item).lower() for item in args.layers.split(' ')]
        else:
            layers = ['ethernet', 'tcp', 'ip']
        receive(layers)
