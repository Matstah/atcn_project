import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
from os import path, makedirs
import traceback
from time import time
import logging as log


# Controller
###########
class Controller(object):

    def __init__(self, sw_name,port_sequence, secret_port, timeout):

        self.topo = Topology(db=path.split(path.abspath(__file__))[0] + "/../topology.db")
        self.sw_name = sw_name
        self.secret_port = secret_port
        self.knocking_sequence = port_sequence
        self.delta_time = timeout
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.init()

    def init(self):
        self.knock_counter = 0
        self.set_table_defaults()
        self.set_table_knocking_rules()
        self.add_mirror(100)

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def set_table_defaults(self):
        self.controller.table_set_default("knocking_rules", "out_of_order_knock", [])
        self.controller.table_set_default("secret_entries","NoAction",[])

    def set_table_knocking_rules(self):
        #set knocking sequence to table
        # TODO: reset table first to insert new rule after a restart?
        counter = 1
        for port in self.knocking_sequence:
            self.controller.table_add("knocking_rules", "port_rule", [str(port)], [str(self.delta_time), str(counter), str(len(self.knocking_sequence))])
            #print 'table_add knocking_rules port_rule {0} --> {1} {2} {3}'.format(port, self.delta_time, counter, len(self.knocking_sequence))
            counter += 1

    def allow_entrance(self,pkt):
        #set table entry to allow access through secret port
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['UDP'].sport
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        self.controller.table_add("secret_entries", "go_trough_secret_port", [str(dstIP),str(srcIP),str(self.secret_port),str(srcPort)], [])
        # TODO: typo in go_trough_secret_port --> through [!must also change in p4]

    def deparse_pack(self, pkt):
        # handler for packet parsing
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
        controlHeader = ControlHeader(payload)
        controlHeader.show()
        #print 'header value: {}'.format(controlHeader.control_payload)
        return controlHeader.control_payload


    def recv_msg(self, pkt):
        print ('-------control packet received-------')
        value = self.deparse_pack(pkt)
        if value == 2:
            log.info("install secret access rule")
            self.allow_entrance(pkt)

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # knock loop
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start Knock_Accepter on cpu_port_intf={}'.format(script, cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg)

# Packet description
class ControlHeader(Packet):
    name = 'ControlHeader'
    fields_desc = [
        BitField('control_payload',0,32)
    ]


# MAIN
######
def red(str):
    code = 91
    return '\033[{}m'.format(code) + str + '\033[0m'

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    # sudo testing/port_knock_controller.py -ps 100 101 102 103 -s 3143 -t 5000000
    parser.add_argument('--sw', type=str, required=False, default="fir", help='firewall name [default fir]')
    parser.add_argument('--port_sequence', '-ps', required=False, nargs ='+', default = [100,101,102,103], help='define port knocking sequence')
    parser.add_argument('--secret_port', '-s', required = False, default = 3141, type=int, help='set secret port' )
    parser.add_argument('--timeout', '-t', required = False, default = 5000000, type=int, help='set timeout between knocks')
    args = parser.parse_args()

    controller = None
    do_cleanup = 1
    # NOTE: this try-except-else stuff could be handled better, but whatever...
    # NOTE: also the opening and closing of files is not optimal...
    try:
        log.basicConfig(stream=sys.stderr, level=log.INFO)
        controller = Controller(args.sw, args.port_sequence, args.secret_port, args.timeout)
        controller.run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
        if do_cleanup:

            do_cleanup =0
        print('CONTROLLER REACHED THE END')
