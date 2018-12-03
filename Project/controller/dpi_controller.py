import nnpy
import struct
import subprocess
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path, makedirs, chmod, chown
import traceback
from time import time
import Dpi

# DPI logging stuff
DPI_FOLDER_NAME='dpi_log'
DPI_BASE_FILENAME='dpi_'

# Register names
INGRESS_NAME = 'MyIngress'
PROB_REGISTER = 'inspection_probability'
DEBUG_REGISTER = 'options'
PROB_INDEX = 0
DEBUG_INDEX = 0

# Controller
###########
class Controller(object):

    def __init__(self, sw_name, inspection_probability, debug):

        self.topo = Topology(db=path.split(path.abspath(__file__))[0] + "/../topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.inspection_probability = inspection_probability
        self.file_path = self.get_log_path()
        self.log_files = {}
        self.debug = debug
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.uid = int(subprocess.check_output(['id', '-u', 'p4']))
        self.gid = int(subprocess.check_output(['id', '-g', 'p4']))
        #print('user p4: user id={}, group id={}'.format(self.uid, self.gid))
        self.init()

    def init(self):
        self.dpi_counter = 0
        self.create_log_folder()
        self.add_mirror(100) # DPI: mirror_id = 100

    def add_mirror(self, mirror_id):
        if self.cpu_port:
            self.controller.mirroring_add(mirror_id, self.cpu_port)
            print('mirror_id={} added to cpu_port={}'.format(mirror_id, self.cpu_port))

    def create_log_folder(self):
        if not path.exists(self.file_path):
            makedirs(self.file_path, 0o777)
            chown(self.file_path, self.uid, self.gid)

    def _set_register(self, register, index, value):
        self.controller.register_write('{}.{}'.format(INGRESS_NAME, register), index, value)
        print('Wrote register {} at index={} with value={}'.format(register, index, value))

    def activate_dpi(self):
        if self.inspection_probability > 0:
            self._set_register(PROB_REGISTER, PROB_INDEX, self.inspection_probability)

    def deactivate_dpi(self):
        self._set_register(PROB_REGISTER, PROB_INDEX, 0)

    def activate_debug(self):
        if self.debug:
            self._set_register(DEBUG_REGISTER, DEBUG_INDEX, 1)

    def deactivate_debug(self):
        self._set_register(DEBUG_REGISTER, DEBUG_INDEX, 0)

    def get_log_path(self):
        return '{}/{}'.format(path.split(path.abspath(__file__))[0], DPI_FOLDER_NAME)

    # d = dict with content of dpi parsing
    # file format: dpi_<time>_<ip1>and<ip2>-flow<id>
    def get_flow_file(self, d):
        flow = d['flow_id']
        if flow not in self.log_files:
            self.log_files[flow] = '{path}/{base}{time}_{ip1}and{ip2}-flow{id}'.format(
                path=self.file_path,
                base=DPI_BASE_FILENAME,
                ip1=d['src'],
                ip2=d['dst'],
                id=flow,
                time=int(time())
            )
            # first time: create file and change ownership and permissions
            with open(self.log_files[flow], 'w+') as log:
                log.close()
            chown(self.log_files[flow], self.uid, self.gid)
            chmod(self.log_files[flow], 0o666)

        return self.log_files[flow]

    # append the content to the file of the specified flow
    def log_dpi(self, content, d):
        file = self.get_flow_file(d)
        with open(file, 'a+') as log:
            log.write(content)
            log.close() # TODO: maybe move this to the end of the script?

    def recv_msg_dpi(self, pkt):
        self.dpi_counter = self.dpi_counter + 1
        res, d = Dpi.handle_dpi(pkt, self.dpi_counter)
        if self.debug and d['debug']:
            print(res)
        if bool(self.inspection_probability) and d['inspect']:
            self.log_dpi(res, d)

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))

        # set functionality on firewall
        self.activate_dpi()
        self.activate_debug()

        # DPI loop
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        print('{}: Start DPI on cpu_port_intf={}'.format(script, cpu_port_intf))
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
        controller = Controller(args.sw, args.probability, args.debug)
        controller.run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
        if do_cleanup:
            controller.deactivate_dpi()
            controller.deactivate_debug()
            do_cleanup = 0
    else:
        if do_cleanup:
            controller.deactivate_dpi()
            controller.deactivate_debug()
        print('CONTROLLER REACHED THE END')
    # TODO: change file permissions.. should be deletable
