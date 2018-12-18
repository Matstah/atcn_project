import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path, remove
import traceback
import time
import sys

# Default values
DPI_DEFAULT = 100
KNOCK_SEQUENCE_DEFAULT=[100,101,102,103]
ALL_FILTERS=['wp', 'bs', 'bd']

TIMEOUT_CONVERSION=1000000

# Default actions to set for all tables
TABLE_DEFAULT_ACTIONS = {
    'whitelist_tcp_dst_port': 'drop',
    'blacklist_src_ip': 'NoAction',
    'blacklist_dst_ip': 'NoAction',
    'knocking_rules': 'out_of_order_knock',
    'secret_entries': 'NoAction',
    'source_accepted': 'NoAction'
}

# containing arguments to _file_to_table() and 'table' is needed for _clear_tables()
FILTERS = {
    'wp':   {
        'table' : 'whitelist_tcp_dst_port',
        'rel_path': '/../filters/ext2in_whitelist_tcp_dst_ports.txt',
        'action': 'NoAction',
        'need_prio': False
    },
    'bs':   {
        'table' : 'blacklist_src_ip',
        'rel_path': '/../filters/ext2in_blacklist_srcIP.txt',
        'action': 'drop',
        'need_prio': True
    },
    'bd':   {
        'table' : 'blacklist_dst_ip',
        'rel_path': '/../filters/in2ext_blacklist_dstIP.txt',
        'action': 'drop',
        'need_prio': True
    }
}

# other tables that are not filters, used for _clear_tables()
TABLES = {
    'knock': 'secret_entries',
    'syndef': 'source_accepted'
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

    # The topo object is commented and an the ports hardcoded,
    # because we do not change the topology
    def __init__(self):
        self.script_path = path.split(path.abspath(__file__))[0]
        # self.topo = Topology(db=self.script_path + "/../topology.db")
        self.sw_name = 'fir'
        self.thrift_port = 9090 # self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port = 8 # self.topo.get_cpu_port_index(self.sw_name)

    # set register of functionality 'name' to 'value' at 'index'
    def set_register(self, name, index, value):
        register = REGISTERS[name]
        self.controller.register_write('{}.{}'.format(INGRESS_NAME, register), index, value)
        print('{}: {} - {}'.format(green(name.upper()), register, green(value)))

    # ARGUMENT SWITCHING

    # a = args namespace object
    # default = bool if script started with default stuff (meaning no arguments)
    # All functionalities are either reset, set to default, or specified value is applied
    def do_things(self, a, default):
        # Filter
        if a.no_filter:
            self._clear_tables([FILTERS[k]['table'] for k in ALL_FILTERS])
        elif default:
            self._clear_tables([FILTERS[k]['table'] for k in ALL_FILTERS])
            self.set_table_defaults()
            for f in ALL_FILTERS:
                 self._file_to_table(**FILTERS[f])
        else:
            if a.filter_clear[0] != -1:
                self._clear_tables([FILTERS[k]['table'] for k in a.filter_clear])
            if a.filter_set[0] != -1:
                for f in a.filter_set:
                    self._file_to_table(**FILTERS[f])

        # DPI
        if a.no_dpi:
            self.set_register('dpi', 0, 0)
        elif default:
            self.set_register('dpi', 0, DPI_DEFAULT)
        elif a.dpi_prob != -1:
            self.set_register('dpi', 0, a.dpi_prob)

        # Knocking
        if a.no_knock:
            self._clear_tables([TABLES['knock']])
            self.set_table_knocking_rules([0], 0)
        elif default:
            self.set_table_knocking_rules(KNOCK_SEQUENCE_DEFAULT, a.knock_timeout*TIMEOUT_CONVERSION)
        elif a.knock_sequence[0] != -1:
            self.set_table_knocking_rules(a.knock_sequence, a.knock_timeout*TIMEOUT_CONVERSION)

        # Tables
        if a.table_clear[0] != -1:
            self._clear_tables([TABLES[t] for t in a.table_clear])

            # also delete syndef file, where possible allowed entries are saved
            if 'syndef' in a.table_clear:
                file = self.script_path + '/table_files/source_accepted.pkl'
                try:
                    remove(file)
                except:
                    if path.isfile(file):
                        print('Entries file not removed.. Do manually! File: ' + file)

    ### END OF do_things

    # Filters lists
    ###############

    # Reads file and fills table according to content
    # rel_path = relative path from this script to the file
    # table = name of the table to set
    # action = the action the parameters from the file are assigned to
    # need_prio = some actions need a priority for tiebreaking on the firewall.
    #               We just set an arbitrary priority because it does not affect
    #               our desired behaviour
    def _file_to_table(self, rel_path='None', table='None', action='None', need_prio=False):
        if rel_path == 'None':
            print(red('_file_to_table needs params'))
            return

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

    # clears all tables (does not affect default action)
    def _clear_tables(self, tables):
        for table in tables:
            self.controller.table_clear(table)
            print('table ' + green(table + ' cleared'))

    # sets all default actions for all our tables
    def set_table_defaults(self):
        for table, action in TABLE_DEFAULT_ACTIONS.items():
            print('Set table default for {} to {}'.format(green(table), green(action)))
            self.controller.table_set_default(table, action, [])

    # knocking
    ##########

    # installs the required knocking sequence on the firewall that is needed for entrance
    # the timeout specifies the time the knocker can take in between knocks
    def set_table_knocking_rules(self, sequence, timeout):
        # reset table first to insert the new rule from scratch
        self._clear_tables(['knocking_rules'])
        if sequence[0] == 0:
            print(green('Knocking disabled'))
            return

        # set table knocking sequence
        counter = 1
        info = green('Knocking') + ' rule: {port} {counter}/' + str(len(sequence))
        for port in sequence:
            print(info.format(port=green(port), counter=green(counter)))
            # print('table_add knocking_rules port_rule {0} --> {1} {2} {3}'.format(port, timeout, counter, len(sequence)))
            self.controller.table_add("knocking_rules", "port_rule", [str(port)], [str(timeout), str(counter), str(len(sequence))])
            counter += 1

### MAIN
if __name__ == "__main__":
    only_defaults=False
    if len(sys.argv) < 2:
        only_defaults=True
        print(blue('Will use all default values'))

    import argparse
    parser = argparse.ArgumentParser()

    # DPI
    parser.add_argument('--no_dpi', action='store_true', help='Deactivate dpi')
    parser.add_argument('--dpi_prob', '-dp', type=int, required=False, default=-1, help="Set inspection probability [percent]")

    # Knocking
    parser.add_argument('--no_knock', action='store_true', help='deactivate knock')
    parser.add_argument('--knock_sequence', '-ks', nargs='+', default=[-1], help='define port knocking sequence')
    parser.add_argument('--knock_timeout', '-kt', type=int, default=5, help='set timeout [s] between knocks')

    # Filters
    parser.add_argument('--no_filter', action='store_true', help='Deactive filling of tables with file values')
    parser.add_argument('--filter_clear', '-fc', nargs='+', default=[-1], help='clear specified filter from [wp,bs,bd]')
    parser.add_argument('--filter_set', '-fs', nargs='+', default=[-1], help='set only specified filter form [wp,bs,bd]')

    # Tables
    parser.add_argument('--table_clear', '-tc', nargs='+', default=[-1], help='clear tables that allow entries from [knock,syndef]')

    # get all options
    args = parser.parse_args()

    try:
        controller = Controller()
        controller.do_things(args, only_defaults)
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
    else:
        print(blue('DONE'))
