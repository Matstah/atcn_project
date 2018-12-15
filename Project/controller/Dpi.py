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
debug={debug}
inspect={inspect}
new_flow={new_flow}

PAYLOAD:
{payload}
""".format(**d)
    return s

def parse(dpi):
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
        'inspect': bool(dpi.inspect),
        'new_flow': dpi.new_flow
    }
