import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path, makedirs
import traceback
from time import time
import Dpi

# DPI logging stuff
DPI_FOLDER='dpi_log'
DPI_BASE_FILENAME='dpi_'

# Controller
###########
class Controller(object):

    def __init__(self, sw_name, inspection_probability, debug):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.inspection_probability = inspection_probability
        self.debug = debug
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.init()

    def init(self):
        self.dpi_counter = 0
        self.create_file()
        self.add_mirror(100) # DPI: mirror_id = 100

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def set_probability(self, index, prob):
        self.controller.register_write('MyIngress.inspection_probability', index, prob)
        print('Wrote register inspection_probability at index={} with value={}'.format(index, prob))

    def create_file(self):
        # TODO: make this relative to the place of the scripts location!
        if not path.exists(DPI_FOLDER):
            makedirs(DPI_FOLDER)
        self.file_name = '{}/{}{}'.format(DPI_FOLDER, DPI_BASE_FILENAME, int(time()))
        self.file_handler = open(self.file_name, 'a')
        print('created and opened file: ' + self.file_name)

    def close_file(self):
        if not self.file_handler.closed:
            self.file_handler.close()
        print(self.file_name + ' is closed')

    # append the content to the file
    def log_dpi(self, content):
        self.file_handler.write(content)

    def recv_msg_dpi(self, pkt):
        self.dpi_counter = self.dpi_counter + 1
        res = Dpi.handle_dpi(pkt, self.dpi_counter)
        if self.debug:
            print(res)
        if bool(self.inspection_probability):
            self.log_dpi(res)

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # set inspection_probability
        self.set_probability(0, self.inspection_probability)
        self.set_probability(1, int(self.debug))

        # DPI
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start DPI on cpu_port_intf={}'.format(script, cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_dpi)

# MAIN
######
def red(str):
    code = 91
    return '\033[{}m'.format(code) + str + '\033[0m'

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', type=str, required=False, default="fir", help='firewall name [default fir]')
    parser.add_argument('-p', '--probability', type=int, required=False, default=0, help='probability for a flow to get inspected and written to a file [default: 0 = no inspection]')
    parser.add_argument('-d', '--debug', action='store_true', help='If activated, each packet gets sent to the controller and is printed by the script')
    args = parser.parse_args()

    try:
        controller = Controller(args.sw, args.probability, args.debug)
        controller.run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
    else:
        # TODO: make that this is always executed, because it is not at the moment
        # Reset the probability to zero to disable DPI and debugging
        controller.set_probability(0, 0)
        controller.set_probability(1, 0)
        controller.close_file()
        print('CONTROLLER REACHED THE END')
        # TODO: print different info depending on set params
