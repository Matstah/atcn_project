from scapy.all import Ether, IP, TCP, UDP, ICMP, Packet, BitField
import socket, struct

# Packet description
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

# stringify DPI content
# d = dict from parse_dpi
def stringify_dpi(d):
    s = """
DPI:
{info}
src={src}
dst={dst}
port={port}
flow_id={flow_id}
debug={debug}
inspect={inspect}

PAYLOAD:
{payload}
""".format(**d)
    return s

def parse_dpi(dpi):
    if(dpi.new_flow):
        info = 'FLOW IS NEW'
    else:
        info = 'flow continues'

    return {
        'info': info,
        'src': socket.inet_ntoa(struct.pack('!L', dpi.srcIpAddr)),
        'dst': socket.inet_ntoa(struct.pack('!L', dpi.dstIpAddr)),
        'port': dpi.ingress_port,
        'flow_id': dpi.flow_id,
        'payload': dpi.payload,
        'debug': bool(dpi.debug),
        'inspect': bool(dpi.inspect)
    }

# Handeling of packet
LAYER_ORDER = ['ethernet', 'ip', 'tcp', 'udp']
LAYER_MAP = {
    'ethernet': Ether,
    'ip': IP,
    'tcp': TCP,
    'udp': UDP,
    'ICMP': ICMP
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
        'info': 'no special info',
        'src': '0.0.0.0',
        'dst': '0.0.0.0',
        'port': -1,
        'flow_id': -1,
        'payload': '',
        'debug': None,
        'inspect': None
    }
    try:
        dpi = DpiHeader(payload)
        dpi_dict = parse_dpi(dpi)
        text = text + stringify_dpi(dpi_dict) + '\n'
    except:
        text = text + 'Could not extract DPI information and payload!\n'
    text = text + '-'*10 + '\n'

    return [text, dpi_dict]
