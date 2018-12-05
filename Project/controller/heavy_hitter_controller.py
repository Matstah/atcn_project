import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path
import traceback
import time

SLEEP_TIME = 5

def red(str):
    code = 91
    return '\033[{}m'.format(code) + str + '\033[0m'

class Controller(object):

    def __init__(self, sw_name):
        self.script_path = path.split(path.abspath(__file__))[0]
        self.topo = Topology(db=self.script_path + "/../topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)


    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))
        while True:
            time.sleep(SLEEP_TIME)
            print("\nReseting Bloom Filter\n")
            self.controller.register_reset('MyIngress.bloom_filter')
        # Knocking
        # cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        # print('{}: Start Knocking listening on cpu_port_intf={}'.format(script, cpu_port_intf))
        # sniff(iface=cpu_port_intf, prn=self.recv_msg_knock) #prn says to send pack to function


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', type=str, required=False, default="fir")
    args = parser.parse_args()

    try:
        controller = Controller(args.sw).run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
    else:
        print('CONTROLLER REACHED THE END')
