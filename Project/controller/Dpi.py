from scapy.all import Ether, IP, TCP, Packet, BitField
class DpiPacket(Packet):
    name = 'DpiPacket'
    fields_desc = [BitField('srcIpAddr',0,32), BitField('ingress_port',0,16)]
