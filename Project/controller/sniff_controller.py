import nnpy
import struct
import subprocess
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
import os
from os import path, makedirs, chmod, chown
import traceback
import pickle
from time import time
import Dpi

# KNOCKING
SECRET_PORT = 3141 # TODO: do not hardcode

# DPI
DPI_FOLDER_NAME='dpi_log'
DPI_BASE_FILENAME='dpi_'
# create dpi file name based on params
def dpi_file_name(path, src, dst, id, count):
    return '{path}/{base}{ip1}and{ip2}-flow{id}_num{count}'.format(
        path=path,
        base=DPI_BASE_FILENAME,
        ip1=src,
        ip2=dst,
        id=id,
        count=count
    )

# SYNDEF
# entrace key is based on src and dst IP
def get_entrance_key(pkt):
    return '{}-{}'.format(pkt['IP'].src, pkt['IP'].dst)

# TYPES of cloned packets
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
    # returns path to dpi log folder
    def get_dpi_path(self):
        return '{}/{}'.format(path.split(path.abspath(__file__))[0], DPI_FOLDER_NAME)

    # creates the dpi folder if it does not exits and gives permissions to be deleted.
    def create_dpi_folder(self):
        if not path.exists(self.dpi_path):
            makedirs(self.dpi_path, 0o777)
            chown(self.dpi_path, self.uid, self.gid)

    # For a given flow, the path to the file is returned
    # If the file did not exist yet, or the flow timed out, a new file is created
    # The mode and owner of the files are changed to the p4 user.
    # This is because if the script is run with 'sudo',
    # the file could not conveniently be removed by the user
    def get_dpi_file(self, d): # d = dict with content of dpi parsing
        flow = d['flow_id']
        is_new = d['new_flow']
        create = False
        if flow not in self.dpi_files:
            count = 1
            file_name = dpi_file_name(self.dpi_path, d['src'], d['dst'], flow, count)
            self.dpi_files[flow] = [[file_name, count]]
            create = True
        else:
            # flow_id already seen once
            if is_new:
                # flow is new (after a timeout), so append to array with new name (old count +1)
                count = self.dpi_files[flow][-1][1] + 1
                file_name = dpi_file_name(self.dpi_path, d['src'], d['dst'], flow, count)
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

    # The content (prepared beforehand) is written to the correct dpi log file
    def log_dpi(self, content, d):
        file = self.get_dpi_file(d)
        with open(file, 'a+') as log:
            log.write(content)
            log.close()

    ### KNOCKING
    # set client to allowed list as reported by firewall
    def allow_entrance_knocking(self,pkt):
        #set table entry to allow access through secret port
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['UDP'].sport
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        self.controller.table_add("secret_entries", "go_trough_secret_port", [str(dstIP),str(srcIP),str(SECRET_PORT),str(srcPort)], [])
        # TODO: typo in go_trough_secret_port --> through [!must also change in p4]

    ### SYNDEF
    # set client to allowed list as reported by firewall
    def allow_entrance_valid_source(self,pkt):
        srcIP = pkt['IP'].src
        dstIP = pkt['IP'].dst
        srcPort = pkt['TCP'].sport
        dstPort = pkt['TCP'].dport
        #hdr.ipv4.dstAddr : exact; hdr.ipv4.srcAddr : exact; hdr.tcp.dstPort(secret Port) : exact; hdr.tcp.srcPort : exact;
        id = self.controller.table_add("source_accepted", "NoAction", [str(srcIP),str(dstIP),str(dstPort)], [])
        print('{src} validation successful. dst={dst}, sport={sport}, dport={dport}'.format(src=green(srcIP), dst=dstIP, sport=srcPort, dport=dstPort))
        self.allowed_entrances[get_entrance_key(pkt)] = id

    # remove client to allowed list as reported by firewall
    # (gets also blacklisted but not here!)
    def forbid_entrance_valid_source(self, pkt):
        k = get_entrance_key(pkt)
        if k in self.allowed_entrances:
            id = self.allowed_entrances.pop(k)
            self.controller.table_delete('source_accepted', id)
            print('src-dst combination {} invalidated'.format(green(k)))
        else:
            print(red('Could not read ID from dict with key ' + k))

    # If the controller has set clients to the valid source list and terminates
    # he remembers the clients in a pickle file
    def save_entrances(self):
        # if there are no entries: delete file if it exists
        if not self.allowed_entrances:
            print('No entries to save in file, because there is no src marked as valid.')
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

    # If the controller got restarted there might be a pickle file with Entries
    # of supposedly valid sources. They are read into the dictionary againg,
    # because the entry ID might be needed in the case of a malicious source
    def read_entrances(self):
        try:
            if os.path.exists(self.entrance_file):
                with open(self.entrance_file, 'rb') as f:
                    self.allowed_entrances = pickle.load(f)
            else:
                print('No "allowed entrance file" to read. Start with empty dict.')
        except Exception:
            print(red('There was a problem when trying reading "allowed entrance file". Continue with empty dict!'))

    ### RUN
    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # listen for all cloned packets
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print(green('Start sniffing on ' + cpu_port_intf))
        sniff(iface=cpu_port_intf, prn=self.recv_msg)

    ### RECV_MSG: handle packet according to clone type
    def recv_msg(self, pkt):
        self.pkt_counter = self.pkt_counter + 1
        print('Cloned packet {}'.format(self.pkt_counter))
        [clone_type, rest] = deparse_pack(pkt)

        ### DPI ###
        if clone_type == DPI_PKT:
            print('Received packet type: ' + green('DPI'))
            text = 'DPI Packet - Packet Count = {}\n'.format(self.pkt_counter)
            text = text + pkt.show(dump=True) + '\n'
            try:
                dpi = DpiHeader(rest)
                print(blue(dpi.show(dump=True))) # TODO comment
                dpi_dict = Dpi.parse(dpi)
                text = '{t}{c}{b}{l}{b}'.format(t=text, c=Dpi.stringify(dpi_dict), b='\n', l='-'*10)
                self.log_dpi(text, dpi_dict)
            except:
                print(red('Could not extract or log DPI information'))
                traceback.print_exc()

        ### KNOCK ###
        elif clone_type == KNOCK_PKT:
            print('Received packet type: ' + green('KNOCK'))
            self.allow_entrance_knocking(pkt)

        ### SYNDEF: Entry ###
        elif clone_type == SRC_VALIDATION_SUCCESS_PKT:
            print('Received packet type: ' + green('SRC VALIDATED'))
            self.allow_entrance_valid_source(pkt)

        ### SYNDEF: Deny ###
        elif clone_type == SRC_VALIDATION_MALICIOUS_PKT:
            print('Received packet type: ' + green('SRC MALICIOUS'))
            self.forbid_entrance_valid_source(pkt)
            srcIP = pkt['IP'].src
            self.controller.table_add("blacklist_src_ip", "drop", ['{0}->{0}'.format(srcIP)],[],'1337')
            # Because this src IP can't be blacklisted (or it wouldn't have gotten this far) we can use a random prio for it
            print('{} is now blacklisted'.format(green(srcIP)))
        else:
            print(red('Unknown clone type number: ' + str(clone_type)))
    ### END OF RECV_MSG

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
        BitField('new_flow',0,8),
    ]

### Packet Deparser
# get payload from last layer, which is the ControlHeader (with ID)
# plus potential rest of packet (DPI)
def deparse_pack(pkt):
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
