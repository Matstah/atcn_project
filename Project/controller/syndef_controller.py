import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
from os import path
import traceback
import time
import pickle

def red(str):
    code = 91
    return '\033[{}m'.format(code) + str + '\033[0m'

# entrace key is based on src and dst IP
def get_entrance_key(pkt):
    return '{}-{}'.format(pkt['IP'].src, pkt['IP'].dst)

class Controller(object):

    def __init__(self, sw_name):
        self.script_path = path.split(path.abspath(__file__))[0]
        self.topo = Topology(db=self.script_path + "/../topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        # self.allowed_entrances = {}
        self.entrance_file = self.script_path + '/table_files/source_accepted.pkl'
        self.init()

    def init(self):
        self.knock_counter = 0
        self.add_mirror(100)
        self.set_table_defaults()

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def set_table_defaults(self):
        self.controller.table_set_default("source_accepted","NoAction",[])

    def save_entrances(self):
        # if there are no entries: delete file if it exists
        if not self.allowed_entrances:
            print('No entries to save in file')
            try:
                os.remove(self.entrance_file)
            except:
                if os.path.isfile(self.entrance_file):
                    print('Entries file not removed.. Do manually! File: ' + self.entrance_file)
            return

        # safe dict in file
        if not os.path.exists(self.script_path + '/table_files'):
            os.makedirs(self.script_path + '/table_files')
        with open(self.entrance_file, 'w+b') as f:
            pickle.dump(self.allowed_entrances, f, pickle.HIGHEST_PROTOCOL)

    def read_entrances(self):
        if os.path.exists(self.entrance_file):
            with open(self.entrance_file, 'rb') as f:
                self.allowed_entrances = pickle.load(f)
        else:
            print('No allowed entrance file')

    def recv_msg_knock(self, pkt):
        self.knock_counter = self.knock_counter + 1
        print('Received knock packet number {}'.format(self.knock_counter))
        #pkt.show() #prints packet to cli
        print'New packet arrived+ {}'.format(self.knock_counter)
        value = self.deparse_pack(pkt)
        if value == 3:
            print'---------------src is validated and accepted to access server----------------------'
            self.allow_entrance(pkt)
        if value == 4:
            print('---------------src is getting blacklisted------------------')
            self.controller.table_add("blacklist_src_ip", "drop", ['{0}->{0}'.format(pkt['IP'].src)],[],'1337') # Because this src IP can't be blacklisted (or it wouldn't have gotten this far) we can use a random prio for it
            print('---------------src is no longer allowed to access server------------------')
            self.forbid_entrace(pkt)

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
        val = self.controller.table_add("source_accepted", "NoAction", [str(srcIP),str(dstIP),str(dstPort)], [])
        self.allowed_entrances[get_entrance_key(pkt)] = val


    def forbid_entrace(self, pkt):
        k = get_entrance_key(pkt)
        if k in self.allowed_entrances:
            id = self.allowed_entrances.pop(k)
            self.controller.table_delete('source_accepted', id)
        else:
            print(red('Could not read ID from dict with key ' + k))

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
        controller = Controller(args.sw)
        controller.read_entrances()
        controller.run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        controller.save_entrances()
        traceback.print_exc()
    else:
        controller.save_entrances()
        print('CONTROLLER REACHED THE END')
