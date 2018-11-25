from scapy.all import Ether, Packet, BitField
class Dpi(Packet):
    name = 'DpiPacket'
    fields_desc = [BitField('srcIpAddr',0,32), BitField('ingress_port',0,16)]
