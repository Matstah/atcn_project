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
VERTICAL_SEPARATION = 2
STANDARD_NODE_SIZE = 650
SWITCH_NODE_SIZE_FACTOR = 1.5
HOST_NODE_SIZE_FACTOR = 1.0
RE_TO_COMPONENT = {
    r"fir": 'firewalls',
    r"hi": 'internal_hosts',
    r"he": 'external_hosts',
    r"ser": 'servers',
    r"ge": 'external_gateways',
    r"gi": 'internal_gateways',
    r"ext": 'extern_switch',
    r"int": 'intern_switch'
}
COMPONENT_TO_PARAMS = {
    'external_hosts': {
        'x': -3,
        'shape': 's',
        'color': 'b',
        'size': STANDARD_NODE_SIZE*HOST_NODE_SIZE_FACTOR
    },
    'internal_hosts': {
        'x': 3,
        'shape': 's',
        'color': 'g',
        'size': STANDARD_NODE_SIZE*HOST_NODE_SIZE_FACTOR
    },
    'external_gateways': {
        'x': -2,
        'shape': 'd',
        'color': 'b',
        'size': STANDARD_NODE_SIZE*SWITCH_NODE_SIZE_FACTOR
    },
    'internal_gateways' : {
        'x': 2,
        'shape': 'd',
        'color': 'b',
        'size': STANDARD_NODE_SIZE*SWITCH_NODE_SIZE_FACTOR
    },
    'servers': {
        'x': 3,
        'shape': 's',
        'color': 'y',
        'size': 800
    },
    'firewalls': {
        'x': 0,
        'shape': 'd',
        'color': 'r',
        'size': STANDARD_NODE_SIZE*SWITCH_NODE_SIZE_FACTOR
    },
    'intern_switch' : {
        'x': 1,
        'shape': 'd',
        'color': 'b',
        'size': STANDARD_NODE_SIZE*SWITCH_NODE_SIZE_FACTOR
    },
    'extern_switch' : {
        'x': -1,
        'shape': 'd',
        'color': 'b',
        'size': STANDARD_NODE_SIZE*SWITCH_NODE_SIZE_FACTOR
    },
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
    def __init__(self, topo_db, disable_print=False):
        self.topo = Topology(db=topo_db)
        self.components = dict((type, []) for type in COMPONENT_TO_PARAMS.keys())
        self.positions = {}
        self.labels = {}
        self.print = not disable_print
        self.init()

    def init(self):
        self.init_func_dicts()
        self.get_components()
        self.set_component_params()

    def init_func_dicts(self):
        self.NODE_INFO_FUNCS = {
            'IP': self.topo.get_host_ip,
            'MAC': self.topo.get_host_mac,
            'thrift_port': self.topo.get_thrift_port,
            'interfaces': self.topo.get_interfaces_to_node,
            'connected hosts': self.topo.get_hosts_connected_to
        }
        self.PAIR_INFO_FUNCS = {
            'port': self.topo.node_to_node_port_num
        }
        self.PAIR_DETAILS_FUNCS = {
            'MAC': self.topo.node_to_node_mac,
            'Shortest paths': self.topo.get_shortest_paths_between_nodes,
            'Interface': self.topo.node_to_node_interface_ip
        }

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

    # gets the label of the provided type for an edge
    def get_edge_label(self, edge, type):
        if type == 'port':
            port0 = self.PAIR_INFO_FUNCS['port'](edge[0], edge[1])
            port1 = self.PAIR_INFO_FUNCS['port'](edge[1], edge[0])
            return "{}-port={}\n{}-port={}".format(edge[0], port0, edge[1], port1)

        elif type == 'ip':
            ip=None
            for i in range(2):
                try:
                    ip = self.NODE_INFO_FUNCS['IP'](edge[i])
                    if ip: return "host ip: {}".format(ip)
                except:
                    continue
            return ""

        elif type == 'mac':
            mac0 = self.PAIR_DETAILS_FUNCS['MAC'](edge[0], edge[1])
            mac1 = self.PAIR_DETAILS_FUNCS['MAC'](edge[1], edge[0])
            return "{}-mac={}\n{}-mac={}".format(edge[0], mac0, edge[1], mac1)

        else:
            return "Unrecognized edge label type"


    def draw(self, edge_label_type=None):
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
        if edge_label_type:
            edge_labels = {}
            for edge in G.edges():
                edge_labels[edge] = self.get_edge_label(edge, edge_label_type)

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
            infos = info_function(*args)
            if self.print: print("{}{}: {}".format(level*INDENT_DEPTH*' ', blue(type), infos))
            return infos
        except Exception as e:
            #print(e)
            #print("{}{}: {}".format(i, type, 'None'))
            return ''

    # prints details of dictionaries in a pretty format
    def subdetails(self, type, info_function, args, level):
        try:
            detailed_info = info_function(*args)
            if self.print:
                print("{}{}:".format(level*INDENT_DEPTH*' ', blue(type)), end=' ')
                pp.pprint(detailed_info, indent=level*INDENT_DEPTH)
            return detailed_info
        except Exception as e:
            return {}

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

    def node_info(self, node, level=0):
        result = {}
        if self.print: print(green("{}{}".format(INDENT_DEPTH*level*' ', node)))
        for info, func in self.NODE_INFO_FUNCS.items():
            result[info] = self.subinfo(info, func, [node], level)
        return result

    def pair_info(self, src, dst, level=0):
        result = {}
        if self.print: print(green("{}Details towards {}".format(INDENT_DEPTH*level*' ', dst)))
        for info, func in self.PAIR_INFO_FUNCS.items():
            result[info] = self.subinfo(info, func, [src, dst], level)
        for detail, func in self.PAIR_DETAILS_FUNCS.items():
            result[detail] = self.subdetails(detail, func, [src, dst], level)
        return result

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
