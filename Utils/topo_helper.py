#!/usr/bin/env python

"""
Requires matplotlib:
    python -m pip install -U matplotlib --user
"""
from __future__ import print_function
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
import networkx as nx
import matplotlib.pyplot as plt
import re

# CONSTANTS
EXTERN_X = -1
FIREWALL_X = 0
INTERNAL_X = 1
SERVER_X = 0.5
HORIZONTAL_SEPARATION = 1
VERTICAL_SEPARATION = 1

class TopoHelper(object):
    def __init__(self, topo_db):
        self.topo = Topology(db=topo_db)
        self.components = {
            'external_hosts': [],
            'internal_hosts': [],
            'servers': [],
            'firewalls': []
        }
        self.positions = {}
        self.labels = {}
        self.init()

    def init(self):
        self.re_to_component = {
            r"fir": 'firewalls',
            r"hi": 'internal_hosts',
            r"he": 'external_hosts',
            r"ser": 'servers'
        }
        self.prepare()
        self.position_nodes()

    def sort_component(self, switch):
        for regex, component in self.re_to_component.items():
            if (re.match(regex, switch)):
                self.components[component].append(switch)


    # gets all components and seperates them into external, internal, server and firewall
    def prepare(self):
        for switch in self.topo.get_p4switches().keys():
            self.sort_component(switch)
            for host in self.topo.get_hosts_connected_to(switch):
                self.sort_component(host)

    # place nodes vertically at position x, and label it
    def place_nodes(self, nodes, x_pos, additional_vertical_shift=0):
        shift = (len(nodes)//2)*VERTICAL_SEPARATION + additional_vertical_shift
        it = 0
        for node in nodes:
            self.positions[node] = (HORIZONTAL_SEPARATION*x_pos, shift-it)
            self.labels[node] = node
            it = it + 1

    # positions nodes according to their type
    def position_nodes(self):
        for type, components in self.components.items():
            if type == 'external_hosts':
                self.place_nodes(components, EXTERN_X)
            elif type == 'internal_hosts':
                self.place_nodes(components, INTERNAL_X)
            elif type == 'servers':
                self.place_nodes(components, SERVER_X, additional_vertical_shift=0.2)
            elif type == 'firewalls':
                self.place_nodes(components, FIREWALL_X)


    def draw(self):
        print('Drawing...', end='')
        """ DEBUG """
        # print(self.components)
        # print(self.topo.network_graph.nodes())
        # print(self.positions)
        """ END DEBUG """

        nx.draw(self.topo.network_graph, pos=self.positions, labels=self.labels)
        plt.show()
        print('done!')


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--topo', type=str, default='topology.db', help='Topology database file')
    parser.add_argument('-d', '--draw', action='store_true', required=False, help='Flag: draw topology')
    args = parser.parse_args()

    if args.draw:
        helper = TopoHelper(args.topo).draw()
    else:
        print('Nothing to do! Choose an option! [help with -h]')
