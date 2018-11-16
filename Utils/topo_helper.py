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
import pprint as pp

# CONSTANTS
INDENT_DEPTH = 2
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

def yellow(str):
    return _col(str, 93)

def blue(str):
    return _col(str, 94)

def green(str):
    return _col(str, 92)

def red(str):
    return _col(str, 91)

def _col(str, code):
    return '\033[{}m'.format(code) + str + '\033[0m'


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

    def sort_component(self, node):
        for regex, component in RE_TO_COMPONENT.items():
            if (re.match(regex, node)):
                self.components[component].append(node)

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

    # print info of simple return values
    def subinfo(self, type, info_function, args, level):
        try:
            print("{}{}: {}".format(level*INDENT_DEPTH*' ', blue(type), info_function(*args)))
        except Exception as e:
            #print(e)
            #print("{}{}: {}".format(i, type, 'None'))
            pass

    # prints details of dictionaries in a pretty format
    def subdetails(self, type, info_function, args, level):
        try:
            detailed_info = info_function(*args)
            print("{}{}:".format(level*INDENT_DEPTH*' ', blue(type)), end=' ')
            pp.pprint(detailed_info, indent=level*INDENT_DEPTH)
        except Exception as e:
            pass

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
            print(yellow(type.upper()))
            for node in reversed(self.components[type]):
                self.node_info(node, 1)

    def node_info(self, node, level):
        infos = {
            'IP': self.topo.get_host_ip,
            'MAC': self.topo.get_host_mac,
            'thrift_port': self.topo.get_thrift_port,
            'interfaces': self.topo.get_interfaces_to_node,
            'connected hosts': self.topo.get_hosts_connected_to
        }
        print(green("{}{}".format(INDENT_DEPTH*level*' ', node)))
        for info, func in infos.items():
            self.subinfo(info, func, [node], level)

    def pair_info(self, src, dst, level):
        infos = {
            'port': self.topo.node_to_node_port_num
        }
        details = {
            'MAC': self.topo.node_to_node_mac,
            'Shortest paths': self.topo.get_shortest_paths_between_nodes,
            'Interface': self.topo.node_to_node_interface_ip
        }
        print(green("{}Details towards {}".format(INDENT_DEPTH*level*' ', dst)))
        for info, func in infos.items():
            self.subinfo(info, func, [src, dst], level)
        for detail, func in details.items():
            self.subdetails(detail, func, [src, dst], level)

    # print details for a single node
    def details(self, src, dst):
        print('-'*10)
        print(yellow("DETAILS of {} ".format(src)))
        self.node_info(src, 1)

        if dst:
            if dst == 'all':
                dsts = [node for nodes in self.components.values() for node in nodes]
            else:
                dsts = [dst]
            for dst in dsts:
                if src == dst:
                    continue
                self.pair_info(src, dst, 2)
        else:
            print(red("Note: to get even more details, use same cmd with --dst"))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--topo', type=str, default='../Project/topology.db', help='Topology database file')
    parser.add_argument('-d', '--draw', action='store_true', required=False, help='Flag: draw topology')
    parser.add_argument('-i', '--info', action='store_true', required=False, help='Flag: get info of topo')
    parser.add_argument('-t', '--type', type=str, default='all', help='With INFO: show only for one of [external, internal, switches]')
    parser.add_argument('--src', type=str, required=False, help='With INFO: get detailed info for this node as being the source')
    parser.add_argument('--dst', type=str, required=False, help='With INFO and SRC: get even more details towards this node as destination. Can also be "all"')
    args = parser.parse_args()

    if not (args.draw or args.info):
        print('Nothing to do! Choose an option! [help with -h]')

    helper = TopoHelper(args.topo)
    if args.info:
        if args.src:
            helper.details(args.src, args.dst)
        else:
            helper.info(args.type)
    if args.draw:
        helper.draw()
    print('-'*10)
