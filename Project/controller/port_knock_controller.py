import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField, UDP
from os import path, makedirs
import traceback
from time import time
import Dpi


# Controller
###########
class Controller(object):

    def __init__(self, sw_name,):

        self.topo = Topology(db=path.split(path.abspath(__file__))[0] + "/../topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.init()

    def init(self):
        self.knock_counter = 0
        secret_port =  3141
        #self.create_log_folder()
        self.add_mirror(100) # DPI: mirror_id = 100

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def allow_entrance(self,pkt):
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['UDP'].sport
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        self.controller.table_add("secret_entries", "go_trough_secret_port", [str(dstIP),str(srcIP),str(3141),str(srcPort)], [])


    def recv_msg_dpi(self, pkt):

        if pkt['UDP'].dport == 0:
            print ('-------knock received-------')
            self.allow_entrance(pkt)

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # set functionality on firewall
        #self.activate_dpi()
        #self.activate_debug()

        # knock loop
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start Knock_Accepter on cpu_port_intf={}'.format(script, cpu_port_intf))
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

    controller = None
    do_cleanup = 1
    # NOTE: this try-except-else stuff could be handled better, but whatever...
    # NOTE: also the opening and closing of files is not optimal...
    try:
        controller = Controller(args.sw)
        controller.run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
        if do_cleanup:

            do_cleanup =0
        print('CONTROLLER REACHED THE END')
    # TODO: change file permissions.. should be deletable
