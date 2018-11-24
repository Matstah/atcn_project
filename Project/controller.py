import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from os import path

# TODO: UNUSED at the moment
class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]

class L2Controller(object):

    def __init__(self, sw_name):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.init()

    def init(self):

        self.controller.reset_state()
        self.add_boadcast_groups()
        filters = Filters(self.controller, self.sw_name);

    def add_boadcast_groups(self):

        interfaces_to_port = self.topo[self.sw_name]["interfaces_to_port"].copy()
        #filter lo and cpu port
        interfaces_to_port.pop('lo', None)
        interfaces_to_port.pop(self.topo.get_cpu_port_intf(self.sw_name), None)

        mc_grp_id = 1
        rid = 0
        for ingress_port in interfaces_to_port.values():

            port_list = interfaces_to_port.values()[:]
            del(port_list[port_list.index(ingress_port)])

            #add multicast group
            self.controller.mc_mgrp_create(mc_grp_id)

            #add multicast node group
            handle = self.controller.mc_node_create(rid, port_list)

            #associate with mc grp
            self.controller.mc_node_associate(mc_grp_id, handle)

            #fill broadcast table
            self.controller.table_add("broadcast", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])

            mc_grp_id +=1
            rid +=1

    def learn(self, learning_data):
        for mac_addr, ingress_port in  learning_data:
            #print "mac: %012X ingress_port: %s " % (mac_addr, ingress_port)
            self.controller.table_add("smac", "NoAction", [str(mac_addr)])
            self.controller.table_add("dmac", "forward", [str(mac_addr)], [str(ingress_port)])

    def unpack_digest(self, msg, num_samples):

        digest = []
        print len(msg), num_samples
        starting_index = 32
        for sample in range(num_samples):
            mac0, mac1, ingress_port = struct.unpack(">LHH", msg[starting_index:starting_index+8])
            starting_index +=8
            mac_addr = (mac0 << 16) + mac1
            digest.append((mac_addr, ingress_port))

        return digest

    def recv_msg_digest(self, msg):

        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        digest = self.unpack_digest(msg, num)
        self.learn(digest)

        #Acknowledge digest
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)


    def run_digest_loop(self):

        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)

class Filters:

    def __init__(self, controller,sw_name):
        self.sw_name = sw_name
        self.controller = controller
        self.set_table_defaults()
        self.set_blacklist_srcIP()
        self.set_blacklist_dstIP()


    #mstaehli
    def set_table_defaults(self):
        print '*************controller values fir:', self.sw_name
        self.controller.table_set_default("whitelist_tcp_dst_port", "drop", [])
        print "set table defaults whitelist"
        self.controller.table_set_default("blacklist_src_ip","NoAction",[])
        print "set table defaults black src"
        self.controller.table_set_default("blacklist_dst_ip","NoAction",[])
        print "set table defaults black dst"

    def set_whitelist_tcp_port(self):
        #read in txt with ports
        file_path = path.relpath("Filters/ext2in_whitelist_tcp_dst_ports.txt")
        with open(file_path,'r') as wPorts_f:
            wPorts_l = wPorts_f.readlines()
            #set all ports to no action..
            for port in wPorts_l:
                self.controller.table_add("whitelist_tcp_dst_port", "NoAction", [str(port)])
                #print 'port {} added to white list'.format(port.replace('\n',''))

    def set_blacklist_srcIP(self):
        #read blacklist file
        file_path = path.relpath("Filters/ext2in_blacklist_srcIP.txt")
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
        file_path = path.relpath("Filters/in2ext_blacklist_dstIP.txt")
        with open(file_path,'r') as bIP_f:
            bIP_l = bIP_f.readlines()
            randomPrio = 1
            for ip in bIP_l:
                #self.controller.table_add("blacklist_dst_ip", "drop", [str(ip)])
                self.controller.table_add("blacklist_dst_ip", "drop", [str(ip)],[],str(randomPrio))
                randomPrio += 1
                #print 'ip {} added to black list in2ex'.format(ip.replace('\n',''))

class RoutingController(object):

    def __init__(self):
        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def set_table_defaults(self):
	    a = 1 # TODO:

    def main(self):
        a = 1 # TODO:

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', type=str, required=False, default="fir")
    args = parser.parse_args()


    # INFO:
    # Routing controller (not used at the moment)
    # connects to all switches by default at the moment
    # but L2Controller only connects to the provided switches

    #controller = RoutingController().main()
    controller = L2Controller(args.sw).run_digest_loop() #arg.sw = switch name
