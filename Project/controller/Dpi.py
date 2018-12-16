import socket
import struct

# stringify DPI content
# d = dict from parse()
def stringify(d):
    s = """
DPI:
{info}
src={src}
dst={dst}
port={port}
flow_id={flow_id}
new_flow={new_flow}

PAYLOAD:
{payload}
""".format(**d)
    return s

# extracted dpi info is parsed into a dict
def parse(dpi):
    new = bool(dpi.new_flow)
    info = 'FLOW IS NEW' if new else 'flow continues'
    return {
        'info': info,
        'src': socket.inet_ntoa(struct.pack('!L', dpi.srcIpAddr)),
        'dst': socket.inet_ntoa(struct.pack('!L', dpi.dstIpAddr)),
        'port': dpi.ingress_port,
        'flow_id': dpi.flow_id,
        'payload': dpi.payload,
        'new_flow': new
    }
