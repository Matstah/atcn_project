from scapy.all import Ether, IP, TCP, Packet, BitField
import socket, struct
class DpiPacket(Packet):
    name = 'DpiPacket'
    fields_desc = [BitField('srcIpAddr',0,32), BitField('ingress_port',0,16)]

LAYER_ORDER = ['ethernet', 'ip', 'tcp']
LAYER_MAP = {
    'ethernet': Ether,
    'tcp': TCP,
    'ip': IP
}

def handle_dpi(pkt, count):
    print('Received DPI packet number {}'.format(count))
    payload = None

    # print other layers first
    for layer in LAYER_ORDER:
            layer_content = pkt.getlayer(LAYER_MAP[layer])
            pretty_print_layer(layer, layer_content)
            if (layer_content):
                payload = layer_content.payload

    # the last layer's payload contains the dpi_header
    dpi_header = DpiPacket(payload)
    print('DPI: src={}, port={}'.format(
        socket.inet_ntoa(struct.pack('!L', dpi_header.srcIpAddr)),
        dpi_header.ingress_port
    ))
    print '-'*10

def pretty_print_layer(layer, content):
    # check if layer content is valid
    splits = repr(content).split()
    layer_name = splits.pop(0)
    if layer_name != 'None':
        print("{} - Received layer: {}".format(layer.upper(), layer_name))
    else:
        print("No '{}' layer".format(layer))
        return

    # print content
    splits.pop() # remove last element
    indent = 2
    for x in splits:
        vals = x.split("=")
        if len(vals) < 2:
            indent = indent + 2
        print("{}{}".format(' '*indent, vals))
