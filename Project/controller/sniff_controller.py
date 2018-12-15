import nnpy
import struct
import subprocess
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
import os
from os import path, makedirs, chmod, chown
import traceback
from time import time
import Dpi

# DPI logging stuff
DPI_FOLDER_NAME='dpi_log'
DPI_BASE_FILENAME='dpi_'

# KNOCKING
SECRET_PORT = 3141 # TODO: do not hardcode

# SYNDEF
# entrace key is based on src and dst IP
def get_entrance_key(pkt):
    return '{}-{}'.format(pkt['IP'].src, pkt['IP'].dst)

# Types of cloned packets
DPI_PKT = 1
KNOCK_PKT = 2
SRC_VALIDATION_SUCCESS_PKT = 3
SRC_VALIDATION_MALICIOUS_PKT = 4

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

# Controller
###########
class Controller(object):

    def __init__(self, name):
        print(green('init controller'))
        # general controller requirements
        self.script_path = path.split(path.abspath(__file__))[0]
        self.topo = Topology(db=self.script_path + "/../topology.db")
        self.sw_name = name
        self.thrift_port = self.topo.get_thrift_port(self.sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

        # dpi requirements
        self.dpi_path = self.get_dpi_path()
        self.dpi_files = {}
        self.uid = int(subprocess.check_output(['id', '-u', 'p4']))
        self.gid = int(subprocess.check_output(['id', '-g', 'p4']))

        # knock requirements
        # TODO maybe add knock secret port here

        # syndef requirements
        self.allowed_entrances = {}
        self.entrance_file = self.script_path + '/table_files/source_accepted.pkl'

        # initialize some other things
        self.init()

    def init(self):
        self.pkt_counter = 0
        self.create_dpi_folder()
        self.add_mirror(100)

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    ### DPI
    def get_dpi_path(self):
        return '{}/{}'.format(path.split(path.abspath(__file__))[0], DPI_FOLDER_NAME)

    def create_dpi_folder(self):
        if not path.exists(self.dpi_path):
            makedirs(self.dpi_path, 0o777)
            chown(self.dpi_path, self.uid, self.gid)

    # d = dict with content of dpi parsing
    # file format: dpi_<time>_<ip1>and<ip2>-flow<id>
    def get_dpi_file(self, d): # TODO: more comments
        flow = d['flow_id']
        is_new = d['new_flow']
        create = False
        if flow not in self.dpi_files:
            count = 1
            file_name = '{path}/{base}{time}_{ip1}and{ip2}-flow{id}_{count}'.format(
                path=self.dpi_path,
                base=DPI_BASE_FILENAME,
                ip1=d['src'],
                ip2=d['dst'],
                id=flow,
                time=int(time()),
                count=count
            )
            self.dpi_files[flow] = [[file_name, count]]
            create = True
        else:
            # flow_id already seen once
            if is_new:
                # flow is new, so append to array with new name (old count +1)
                count = self.dpi_files[flow][-1][1] + 1
                file_name = '{path}/{base}{time}_{ip1}and{ip2}-flow{id}_{count}'.format(
                    path=self.dpi_path,
                    base=DPI_BASE_FILENAME,
                    ip1=d['src'],
                    ip2=d['dst'],
                    id=flow,
                    time=int(time()),
                    count=count
                )
                self.dpi_files[flow].append([file_name, count])
                create = True

        if create:
            # first time: create file and change ownership and permissions
            with open(self.dpi_files[flow][-1][0], 'w+') as log:
                log.close()
            chown(self.dpi_files[flow][-1][0], self.uid, self.gid)
            chmod(self.dpi_files[flow][-1][0], 0o666)

        # return the last file name (might have been created just now)
        return self.dpi_files[flow][-1][0]

    # TODO: comment
    def log_dpi(self, content, d):
        file = self.get_flow_file(d)
        with open(file, 'a+') as log:
            log.write(content)
            log.close() # TODO: maybe move this to the end of the script?

    ### KNOCKING
    def allow_entrance_knocking(self,pkt):
        #set table entry to allow access through secret port
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['UDP'].sport
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        self.controller.table_add("secret_entries", "go_trough_secret_port", [str(dstIP),str(srcIP),str(SECRET_PORT),str(srcPort)], [])
        # TODO: typo in go_trough_secret_port --> through [!must also change in p4]

    ### SYNDEF
    # TODO: comment
    def allow_entrance_valid_source(self,pkt):
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['TCP'].sport
        dstPort = pkt['TCP'].dport
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        id = self.controller.table_add("source_accepted", "NoAction", [str(srcIP),str(dstIP),str(dstPort)], [])
        print('{src} validation successful. dst={dst}, sport={sport}, dport={dport}'.format(src=green(srcIP), dst=dstIP, sport=srcPort, dport=dstPort))
        self.allowed_entrances[get_entrance_key(pkt)] = id

    # TODO: comment
    def forbid_entrance_valid_source(self, pkt):
        k = get_entrance_key(pkt)
        if k in self.allowed_entrances:
            id = self.allowed_entrances.pop(k)
            self.controller.table_delete('source_accepted', id)
            print('src-dst combination {} invalidated'.format(green(id)))
        else:
            print(red('Could not read ID from dict with key ' + k))

    # TODO: comment
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

    # TODO: comment
    def read_entrances(self):
        if os.path.exists(self.entrance_file):
            with open(self.entrance_file, 'rb') as f:
                self.allowed_entrances = pickle.load(f)
        else:
            print('No allowed entrance file')

    ### RUN
    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # listen for all cloned packets
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print(green('Start sniffing on ' + cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg)

    def recv_msg(self, pkt):
        self.pkt_counter = self.pkt_counter + 1
        print('Cloned packet {}'.format(self.pkt_counter))
        [clone_type, rest] = deparse_pack(pkt)
        print('Received packet type: ' + str(clone_type))

        if clone_type == DPI_PKT:
            text = 'DPI Packet - Packet Count = {}\n'.format(self.pkt_counter)
            text = text + pkt.show(dump=True) + '\n'
            try:
                dpi = DpiHeader(rest)
                dpi_dict = Dpi.parse(dpi)
                text = '{t}{c}{b}{l}{b}'.format(t=text, c=stringify(dpi_dict), b='\n', l='-'*10)
                self.log_dpi(text, dpi_dict)
            except:
                print(red('Could not extract DPI information'))
        elif clone_type == KNOCK_PKT:
            self.allow_entrance_knocking(pkt)
        elif clone_type == SRC_VALIDATION_SUCCESS_PKT:
            self.allow_entrance_valid_source(pkt)
        elif clone_type == SRC_VALIDATION_MALICIOUS_PKT:
            self.forbid_entrance_valid_source(pkt)
            srcIP = pkt['IP'].src
            self.controller.table_add("blacklist_src_ip", "drop", ['{0}->{0}'.format(srcIP)],[],'1337')
            # Because this src IP can't be blacklisted (or it wouldn't have gotten this far) we can use a random prio for it
            print('{} is now blacklisted'.format(green(srcIP)))
        else:
            print(red('Unknown clone type number:s ' + str(clone_type)))

### CLASS: ControlHeader
# For scapy: Contains packet id such that controller knows what content the packet holds
class ControlHeader(Packet):
    name = 'ControlHeader'
    fields_desc = [
        BitField('control_id',0,32)
    ]

### CLASS: DpiHeader
# DPI Packets contain an additional header with some information (whether useful or not... for demonstration at least)
# Here we could potentially send other information about the state of the firewall
# that cannot simply be read from registers, etc (for which the SimpleSwitchAPI could be used)
class DpiHeader(Packet):
    name = 'DpiHeader'
    fields_desc = [
        BitField('srcIpAddr',0,32),
        BitField('dstIpAddr',0,32),
        BitField('ingress_port',0,16),
        BitField('flow_id',0,32),
        BitField('debug',0,1),
        BitField('inspect',0,1),
        BitField('new_flow',0,1),
        BitField('unused',0,5)
    ]

### Packet Deparser
def deparse_pack(pkt):
    # get payload from last layer, which is the ControlHeader (with ID)
    # plus potential rest of packet (DPI)
    payload = None
    for layer in [Ether, IP, TCP, UDP]:
        layer_content = pkt.getlayer(layer)
        if (layer_content):
            payload = layer_content.payload
    ch = ControlHeader(payload)
    # print 'header value: {}'.format(ch.control_id)
    return [ch.control_id, ch.payload]

### MAIN
if __name__ == "__main__":
    try:
        controller = Controller('fir')
        controller.read_entrances()
        controller.run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
        try:
            controller.save_entrances()
        except:
            print(red('Controller not initialized'))
    else:
        controller.save_entrances()
        print(green('CONTROLLER REACHED THE END'))
