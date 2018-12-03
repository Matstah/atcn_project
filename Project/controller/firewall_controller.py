import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path
import traceback
import time

def red(str):
    code = 91
    return '\033[{}m'.format(code) + str + '\033[0m'

class Controller(object):

    def __init__(self, sw_name):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.init()

    def init(self):
        self.knock_counter = 0
        self.add_mirror(100) # DPI: mirror_id = 100 TODO: use other mirror ID for knocking?
        filter = Filter(self.controller, self.sw_name)

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port) #with the mirror id, we can set a specific port for cloning
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def recv_msg_knock(self, pkt):
        self.knock_counter = self.knock_counter + 1
        print('Received knock packet number {}'.format(self.knock_counter))
        pkt.show() #prints packet to cli



    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # Knocking
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start Knocking listening on cpu_port_intf={}'.format(script, cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_knock) #prn says to send pack to function


class Filter:
    #mstaehli
    def __init__(self, controller,sw_name):
        self.sw_name = sw_name
        self.controller = controller
        self.set_table_defaults()
        self.set_whitelist_tcp_port()
        self.set_blacklist_srcIP()
        self.set_blacklist_dstIP()

    def set_table_defaults(self):
        #print '*************controller values fir:', self.sw_name
        self.controller.table_set_default("whitelist_tcp_dst_port", "drop", [])
        #print "set table defaults whitelist"
        self.controller.table_set_default("blacklist_src_ip","NoAction",[])
        #print "set table defaults black src"
        self.controller.table_set_default("blacklist_dst_ip","NoAction",[])
        #print "set table defaults black dst"

    def set_whitelist_tcp_port(self):
        #read in txt with ports
        file_path = path.relpath("filters/ext2in_whitelist_tcp_dst_ports.txt")
        with open(file_path,'r') as wPorts_f:
            wPorts_l = wPorts_f.readlines()
            #set all ports to no action..
            for port in wPorts_l:
                self.controller.table_add("whitelist_tcp_dst_port", "NoAction", [str(port)])
                #print 'port {} added to white list'.format(port.replace('\n',''))

    def set_blacklist_srcIP(self):
        #read blacklist file
        file_path = path.relpath("filters/ext2in_blacklist_srcIP.txt")
        with open(file_path,'r') as bIP_f:
            bIP_l = bIP_f.readlines()
            randomPrio = 1
            for ip in bIP_l:
                #self.controller.table_add("blacklist_src_ip", "drop", [str(ip)])
                self.controller.table_add("blacklist_src_ip", "drop", [str(ip)],[],str(randomPrio))
                randomPrio += 1
                #print 'ip {} added to black list ex2in'.format(ip.replace('\n',''))

    def set_blacklist_dstIP(self):
        #read blacklist file
        file_path = path.relpath("filters/in2ext_blacklist_dstIP.txt")
        with open(file_path,'r') as bIP_f:
            bIP_l = bIP_f.readlines()
            randomPrio = 1
            for ip in bIP_l:
                #self.controller.table_add("blacklist_dst_ip", "drop", [str(ip)])
                self.controller.table_add("blacklist_dst_ip", "drop", [str(ip)],[],str(randomPrio))
                randomPrio += 1
                #print 'ip {} added to black list in2ex'.format(ip.replace('\n',''))


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
