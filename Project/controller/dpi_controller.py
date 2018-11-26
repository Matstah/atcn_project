import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path
import traceback
import time
import Dpi

def red(str):
    code = 91
    return '\033[{}m'.format(code) + str + '\033[0m'

class Controller(object):

    def __init__(self, sw_name, inspection_probability):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.inspection_probability = inspection_probability
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.init()

    def init(self):
        self.dpi_counter = 0
        self.add_mirror(100) # DPI: mirror_id = 100

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def recv_msg_dpi(self, pkt):
        self.dpi_counter = self.dpi_counter + 1
        Dpi.handle_dpi(pkt, self.dpi_counter)

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # set inspection_probability
        self.controller.register_write('MyIngress.inspection_probability', 0, self.inspection_probability)

        # DPI
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start DPI on cpu_port_intf={}'.format(script, cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_dpi)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', type=str, required=False, default="fir")
    parser.add_argument('-p', '--probability', type=int, required=False, default=100)
    args = parser.parse_args()

    try:
        controller = Controller(args.sw, args.probability).run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
    else:
        print('CONTROLLER REACHED THE END')
