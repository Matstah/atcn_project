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
INDENT = '   '
HORIZONTAL_SEPARATION = 1
VERTICAL_SEPARATION = 1
STANDARD_NODE_SIZE = 650
RE_TO_COMPONENT = {
    r"fir": 'firewalls',
    r"hi": 'internal_hosts',
    r"he": 'external_hosts',
    r"ser": 'servers'
}
COMPONENT_TO_PARAMS = {
    'external_hosts': {
        'x': -1,
        'shape': 's',
        'color': 'b',
        'size': STANDARD_NODE_SIZE
    },
    'internal_hosts': {
        'x': 1,
        'shape': 's',
        'color': 'g',
        'size': STANDARD_NODE_SIZE
    },
    'servers': {
        'x': 1,
        'shape': 's',
        'color': 'y',
        'size': 800
    },
    'firewalls': {
        'x': 0,
        'shape': 'd',
        'color': 'r',
        'size': STANDARD_NODE_SIZE
    }
}

# HELPERS
def is_internal_type(type):
    return (type == 'internal_hosts' or type == 'servers')

def other_internal_type(type):
    if type == 'internal_hosts':
        return 'servers'
    else:
        return 'internal_hosts'

class TopoHelper(object):
    def __init__(self, topo_db):
        self.topo = Topology(db=topo_db)
        self.components = dict((type, []) for type in COMPONENT_TO_PARAMS.keys())
        self.positions = {}
        self.labels = {}
        self.init()

    def init(self):
        self.get_components()
        self.set_component_params()

    def sort_component(self, switch):
        for regex, component in RE_TO_COMPONENT.items():
            if (re.match(regex, switch)):
                self.components[component].append(switch)

    # gets all components and seperates them into external, internal, server and firewall
    def get_components(self):
        for switch in self.topo.get_p4switches().keys():
            self.sort_component(switch)
            for host in self.topo.get_hosts_connected_to(switch):
                self.sort_component(host)

    # place nodes vertically at position x, and label it
    def set_node_params(self, nodes, type):
        p = COMPONENT_TO_PARAMS[type]
        it = 0

        # special case: position severs and internal nodes above each other
        if is_internal_type(type):
            other_type = other_internal_type(type)
            other_internals = self.components[other_type]
            combined_length = len(nodes + other_internals)
            shift = (combined_length//2)*VERTICAL_SEPARATION
            if self.components[other_type][0] in self.positions:
                # other internal type already seen
                it = it + len(other_internals)
        else:
            shift = (len(nodes)//2)*VERTICAL_SEPARATION

        for node in nodes:
            self.positions[node] = (HORIZONTAL_SEPARATION*p['x'], shift-it)
            self.labels[node] = node
            it = it + 1

    # position nodes according to their type
    def set_component_params(self):
        for type, components in self.components.items():
            self.set_node_params(components, type)

    def draw(self):
        G = self.topo.network_graph
        print('Drawing...', end='')
        """ DEBUG """
        # print(self.components)
        # print(self.topo.network_graph.nodes())
        # print(self.positions)
        """ END DEBUG """

        # draw network nodes with their params
        for type, components in self.components.items():
            params = COMPONENT_TO_PARAMS[type]
            nx.draw_networkx_nodes(G, self.positions,
                node_shape = params['shape'],
                node_color = params['color'],
                nodelist = components,
                node_size = params['size']
            )

        # draw all edges
        nx.draw_networkx_edges(G, self.positions,
            edge_list = G.edges()
        )

        # label the nodes
        nx.draw_networkx_labels(G, self.positions,
            labels = self.labels
        )

        # label the edges
        edge_labels = {}
        for edge in G.edges():
            edge_labels[edge] = edge # TODO:

        nx.draw_networkx_edge_labels(G, self.positions,
            edge_labels = edge_labels,
            label_pos = 0.5,
        )

        # show the plot
        plt.show()
        print('done!')


    def subinfo(self, type, info_function, node, indent):
        i = indent*INDENT
        try:
            print("{}{}: {}".format(i, type, info_function(node)))
        except Exception as e:
            pass
            #print(e)
            #print("{}{}: {}".format(i, type, 'None'))

    # print information of general interest about the topology
    def info(self, choice):
        if choice == "all":
            types = self.components.keys()
        elif choice == "external":
            types = ["external_hosts"]
        elif choice == "internal":
            types = ["internal_hosts", "servers"]
        elif choice == "switches":
            types = ["firewalls"]
        else:
            print("Choice not recognized")
            return

        for type in types:
            print(type.upper())
            for node in reversed(self.components[type]):
                print("{}{}".format(INDENT, node))
                self.subinfo('IP', self.topo.get_host_ip, node, 2)
                self.subinfo('MAC', self.topo.get_host_mac, node, 2)
                self.subinfo('thrift_port', self.topo.get_thrift_port, node, 2)
                self.subinfo('interfaces', self.topo.get_interfaces_to_node, node, 2)
                self.subinfo('connected hosts', self.topo.get_hosts_connected_to, node,2)

    # print details for a single node
    def details(self, node):
        print("DETAILS of {}".format(node))
        if node in self.topo.get_p4switches().keys():
            #print('Is a P4 switch')
            self.subinfo('thrift_port', self.topo.get_thrift_port, node, 1)
            self.subinfo('connected hosts', self.topo.get_hosts_connected_to, node, 1)
            self.subinfo('MAC', self.topo.get_host_mac, node, 1)
        else:
            #print('Is a host')
            self.subinfo('IP', self.topo.get_host_ip, node, 1)
            self.subinfo('MAC', self.topo.get_host_mac, node, 1)

# TODO: add the following information
# node_to_node_port_num(node1, node2): returns the port index of node1 facing node2. This index can be used to populate your forwarding table entries.
# node_to_node_mac(node1, node2): returns the mac address of the interface from node1 that connects with node2. This can be used to get next hop destination mac addresses.
# get_shortest_paths_between_nodes(node1, node2): returns a list of the shortest paths between two nodes. The list includes the src and the destination and multiple equal cost paths if found. For example, get_shortest_paths_between_nodes('s1', 's2') would return [('s1', 's4', 's2'), ('s1', 's5', 's2')] if two equal cost paths are found using s4 and s5 as next hops.
# node_to_node_interface_ip(node1, node2): returns the IP address of the interface from node1 connecting with node2. Note that the ip address includes the prefix len at the end /x.
# get_interfaces_to_node(sw_name): returns a dictionary of all the interfaces as keys and the node they connect to as value. For example {'s1-eth1': 'h1', 's1-eth2': 's2'}.
# interface_to_port(node, intf_name): returns the interface index of intf_name for node.



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--topo', type=str, default='topology.db', help='Topology database file')
    parser.add_argument('-d', '--draw', action='store_true', required=False, help='Flag: draw topology')
    parser.add_argument('-i', '--info', action='store_true', required=False, help='Flag: get info of topo')
    parser.add_argument('-t', '--type', type=str, default='all', help='With INFO: show only for one of [external, internal, switches]')
    parser.add_argument('-n', '--node', type=str, required=False, help='With INFO: get detailed info for this node')
    args = parser.parse_args()

    if not (args.draw or args.info):
        print('Nothing to do! Choose an option! [help with -h]')

    helper = TopoHelper(args.topo)
    if args.info:
        if args.node:
            helper.details(args.node)
        else:
            helper.info(args.type)
    if args.draw:
        helper.draw()
