import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path
import traceback
import time
import sys

# Default actions to set for all tables
TABLE_DEFAULT_ACTIONS = {
    'whitelist_tcp_dst_port': 'drop',
    'blacklist_src_ip': 'NoAction',
    'blacklist_dst_ip': 'NoAction',
    'knocking_rules': 'out_of_order_knock',
    'secret_entries': 'NoAction',
    'source_accepted': 'NoAction'
}

# Register names
INGRESS_NAME = 'MyIngress'
REGISTERS = {
    'dpi' : 'inspection_probability'
}

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


class Controller(object):

    def __init__(self):
        self.script_path = path.split(path.abspath(__file__))[0]
        # self.topo = Topology(db=self.script_path + "/../topology.db") Not needed: things are hardcoded below
        self.sw_name = 'fir'
        self.thrift_port = 9090 # self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port =  8 # self.topo.get_cpu_port_index(self.sw_name)

    def set_register(self, name, index, value):
        register = REGISTERS[name]
        self.controller.register_write('{}.{}'.format(INGRESS_NAME, register), index, value)
        print('{}: {} - {}'.format(green(name.upper()), register, green(value)))

    # ARGUMENT SWITCHING
    def do_things(self, a):
        # Filter
        if a.filter_defaults:
            self.set_table_defaults()
            self.set_whitelist_tcp_port()
            self.set_blacklist_srcIP()
            self.set_blacklist_dstIP()

        # DPI
        if a.dpi_prob >= 0:
            self.set_register('dpi', 0, a.dpi_prob)

        # Knocking
        if a.knock:
            self.set_table_knocking_rules(a.knock_sequence, a.knock_timeout*1000000)
        else:
            if a.knock_sequence or a.knock_port or a.knock_timeout:
                print(red('You have set knocking attributes, but did not activate it with -k flag'))


    # Filters lists
    ###############
    def _file_to_table(self, rel_path, table, action, need_prio=False):
        print('Fill table {} with data from {}'.format(green(table), green(rel_path)))
        with open(self.script_path + rel_path, 'r') as file:
             data = file.readlines()
             randomPrio = 1
             for d in data:
                 if need_prio:
                     self.controller.table_add(table, action, [str(d)], [], str(randomPrio))
                     randomPrio += 1
                 else:
                     self.controller.table_add(table, action, [str(d)])

    def set_table_defaults(self):
        for table, action in TABLE_DEFAULT_ACTIONS.items():
            print('Set table default for {} to {}'.format(green(table), green(action)))
            self.controller.table_set_default(table, action, [])

    def set_whitelist_tcp_port(self):
        self._file_to_table(
            "/../filters/ext2in_whitelist_tcp_dst_ports.txt",
            'whitelist_tcp_dst_port',
            'NoAction'
        )

    def set_blacklist_srcIP(self):
        self._file_to_table(
            "/../filters/ext2in_blacklist_srcIP.txt",
            'blacklist_src_ip',
            'drop',
            need_prio=True
        )

    def set_blacklist_dstIP(self):
        self._file_to_table(
            "/../filters/in2ext_blacklist_dstIP.txt",
            'blacklist_dst_ip',
            'drop',
            need_prio=True
        )

    # knocking
    ##########
    def set_table_knocking_rules(self, sequence, timeout):
        # TODO: reset table first to insert the new rule from scratch?
        #set table knocking sequence
        counter = 1
        info = green('Knocking') + ' rule: {port} {counter}/' + str(len(sequence))
        for port in sequence:
            print(info.format(port=green(port), counter=green(counter)))
            # print('table_add knocking_rules port_rule {0} --> {1} {2} {3}'.format(port, timeout, counter, len(sequence)))
            self.controller.table_add("knocking_rules", "port_rule", [str(port)], [str(timeout), str(counter), str(len(sequence))])
            counter += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(red('Nothing to do! --help for list of options'))
        exit(0)

    import argparse
    parser = argparse.ArgumentParser()

    # TODO: defaults argument that takes reasonable values
    # Reset
    parser.add_argument('--reset', '-r', action='store_true', required=False, help='Reset all tables and registers')
    # parser.add_argument('--reset_todo') # TODO: reset single stuff

    # DPI
    parser.add_argument('--dpi_prob', '-dp', type=int, required=False, default=-1, help="Set inspection probability [percent] [0 for disabling]")

    # Knocking TODO: deactivate when 0 # TODO: remember to translate knock timeout *1000000
    parser.add_argument('--knock', '-k', action='store_true', required=False, help='Flag to tell script it should set knocking stuff')
    parser.add_argument('--knock_sequence', '-ks', required=False, nargs ='+', help='define port knocking sequence [0 for disabling]')
    parser.add_argument('--knock_port', '-kp', required = False, type=int, help='set knock secret port' )
    parser.add_argument('--knock_timeout', '-kt', required = False, type=int, help='set timeout [s] between knocks')

    # Filters
    parser.add_argument('--filter_defaults', '-fd', action='store_true', required=False, help='sets filter stuff from default files')
    # TODO: and other files (that have to be written in other controller every time table_add is called)

    # get all options
    args = parser.parse_args()

    try:
        controller = Controller()
        controller.do_things(args)
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
    else:
        print(blue('DONE'))
