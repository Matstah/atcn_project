from scapy.all import Ether, IP, TCP, Packet, BitField
class DpiPacket(Packet):
    name = 'DpiPacket'
    fields_desc = [BitField('srcIpAddr',0,32), BitField('ingress_port',0,16)]

def print_dpi(data):
    print('DPI: src={}, port={}'.format(data.srcIpAddr, data.ingress_port))
    # for ip_src_addr, ingress_port in data:
    #     print "mac: %012X ingress_port: %s " % (ip_src_addr, ingress_port)
