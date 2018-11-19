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

    # SERVER HELPER
    def get_info(self, node, info):
        if hasattr(self, info):
            return getattr(self, info)
        elif not hasattr(self.node_infos, node):
            self.node_infos[node] = self.helper.node_info(node)
        return self.node_infos[node][info]

    # SERVER FUNCS
    def send(dst):
        ## TODO:
        a = 1

    # SERVER RUN
    def run(self):
        # TODO:
        print(self.node_infos)
        print(self.interface)
        while True:
            print('Server is running')
            time.sleep(3.0)

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
