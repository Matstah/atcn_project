import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
from os import path
import traceback
import time

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
        self.init()

    def init(self):
        self.knock_counter = 0
        self.add_mirror(100) # DPI: mirror_id = 100 TODO: use other mirror ID for knocking?

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port) #with the mirror id, we can set a specific port for cloning
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def recv_msg_knock(self, pkt):
        self.knock_counter = self.knock_counter + 1
        print('Received knock packet number {}'.format(self.knock_counter))
        pkt.show() #prints packet to cli
        print'New packet arrived+ {}'.format(self.knock_counter)
        value = self.deparse_pack(pkt)
        if value == 3:
            print'---------------src is validated and accepted to access server----------------------'
            self.allow_entrance(pkt)

    def deparse_pack(self, pkt):
        # Handeling of packet
        LAYER_ORDER = ['ethernet', 'ip', 'tcp', 'udp']
        LAYER_MAP = {
            'ethernet': Ether,
            'ip': IP,
            'tcp': TCP,
            'udp': UDP
        }
        payload = None
        for layer in LAYER_ORDER:
            layer_content = pkt.getlayer(LAYER_MAP[layer])
            if (layer_content):
                payload = layer_content.payload
        dpiHeader = DpiHeader(payload)
        dpiHeader.show()
        print 'header value: {}'.format(dpiHeader.dpi_payload)
        return dpiHeader.dpi_payload

    def allow_entrance(self,pkt):
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['TCP'].sport
        dstPort = pkt['TCP'].dport
        print'secret entry is set'
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        self.controller.table_add("secret_entries", "go_trough_secret_port", [str(dstIP),str(srcIP),str(dstPort),str(srcPort)], [])

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # listen for src validated packets
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        # print('{}: Start Knocking listening on cpu_port_intf={}'.format(script, cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_knock) #prn says to send pack to function

# Packet description
class DpiHeader(Packet):
    name = 'DpiHeader'
    fields_desc = [
        BitField('dpi_payload',0,32)
    ]


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
