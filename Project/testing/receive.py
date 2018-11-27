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

# global
count = 0

def increment_count():
    global count
    count = count + 1
    return count

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

def pretty_print_layer(layer, content):
    splits = repr(content).split()
    layer_name = splits.pop(0)
    if layer_name != 'None':
        print("{} - Received layer: {}".format(layer.upper(), layer_name))
    else:
        print("No '{}' layer".format(layer))
        return

    splits.pop() # remove last element
    indent = 2
    for x in splits:
        vals = x.split("=")
        if len(vals) < 2:
            indent = indent + 2
        print("{}{}".format(' '*indent, vals))

def handle_pkt(pkt, layers):
    print('Packet {}'.format(increment_count()))
    for layer in layers:
            pretty_print_layer(layer, pkt.getlayer(LAYER_MAP[layer]))
    print '-'*10


def receive(layers, num_packets):
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    print("Available interfaces: {}".format(ifaces))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()

    sniff(iface=iface, prn=lambda x: handle_pkt(x, layers), count=num_packets)

    #my_filter = isNotOutgoing(get_if_hwaddr(get_if()))
    #sniff(iface=iface, prn=lambda x: handle_pkt(x, layers), lfilter=my_filter, count=num_packets)

    #sniff(filter="ether proto 0x7777", iface = iface, prn = lambda x: handle_pkt(x), lfilter=my_filter)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # args for local execution
    parser.add_argument('--local', action='store_true', required=False, help='If script should run from local prompt')
    parser.add_argument('--host', type=str, required=False, help='host NAME in case of a local call')
    parser.add_argument('--on_remote', action='store_true', required=False, help='Do not set this flag yourself!!')
    parser.add_argument('--num_packets', type=int, required=False, default=9999, help='number of packets to receive before abortion (optional)')

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
        receive(layers, args.num_packets)
