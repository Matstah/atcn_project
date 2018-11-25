import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path
import time
import Dpi

class Controller(object):

    def __init__(self, sw_name):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.init()

    def init(self):
        self.controller.reset_state()
        self.add_mirror(100) # DPI: mirror_id = 100

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)

    def recv_msg_dpi(self, pkt):
        print('recv_msg_dpi')
        packet = Ether(str(pkt))
        print(packet)
        if packet.type == 0x4321:
            print('sdfjskdf')

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # DPI
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start DPI on cpu_port_intf={}'.format(script, cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_dpi)

        ## TODO: other things
        # WE DO NOT REACH THE CODE HERE BECAUSE sniff LOOPS LIKE IT SEEMS --> threads?, different controller?
        print('{}: do other things'.format(script))

        # while True:
        #     print('{} is running'.format(script))
        #     time.sleep(5)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', type=str, required=False, default="fir")
    args = parser.parse_args()

    controller = Controller(args.sw).run()
