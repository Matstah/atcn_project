from scapy.all import Ether, IP, TCP, Packet, BitField
import socket, struct

# Packet description
class DpiHeader(Packet):
    name = 'DpiHeader'
    fields_desc = [BitField('srcIpAddr',0,32), BitField('dstIpAddr',0,32), BitField('ingress_port',0,16), BitField('flow_id',0,32)]

# stringify DPI content
# d = dict from parse_dpi
def stringify_dpi(d):
    s = """
DPI:
src={src}
dst={dst}
port={port}
flow_id={flow_id}

PAYLOAD:
{payload}
""".format(**d)
    return s

def parse_dpi(dpi):
    return {
        'src': socket.inet_ntoa(struct.pack('!L', dpi.srcIpAddr)),
        'dst': socket.inet_ntoa(struct.pack('!L', dpi.dstIpAddr)),
        'port': dpi.ingress_port,
        'flow_id': dpi.flow_id,
        'payload': dpi.payload
    }

# Handeling of packet
LAYER_ORDER = ['ethernet', 'ip', 'tcp']
LAYER_MAP = {
    'ethernet': Ether,
    'ip': IP,
    'tcp': TCP,
    'dpi': DpiHeader
}

# prepares a string of the packet inluding the dpi content
# this can then be used to log or print
# also returns parsed dict of the dpi
def handle_dpi(pkt, count):
    text = 'Received DPI packet number {}\n'.format(count)

    # show packet
    text = text + pkt.show(dump=True) + '\n'

    # get payload from last layer, which is the dpi_header plus payload
    payload = None
    for layer in LAYER_ORDER:
        layer_content = pkt.getlayer(LAYER_MAP[layer])
        if (layer_content):
            payload = layer_content.payload

    # the last layer's payload contains the dpi_header
    dpi_dict = {
        'src': '0.0.0.0',
        'dst': '0.0.0.0',
        'port': -1,
        'flow_id': -1,
        'payload': ''
    }
    if(payload):
        dpi = DpiHeader(payload)
        dpi_dict = parse_dpi(dpi)
        text = text + stringify_dpi(dpi_dict) + '\n'
    else:
        text = text + 'Could not extract DPI information and payload!\n'
    text = text + '-'*10 + '\n'

    return [text, dpi_dict]
