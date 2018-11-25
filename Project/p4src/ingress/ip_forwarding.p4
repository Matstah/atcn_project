// tables and actions
action forward_internal(port_t port, macAddr_t src, macAddr_t dst){
    standard_metadata.egress_spec = port;
    hdr.ethernet.srcAddr = src;
    hdr.ethernet.dstAddr = dst;
}

action forward_external(port_t port) {
    standard_metadata.egress_spec = port;
}

table ip_forwarding {
    key = {
        hdr.ipv4.dstAddr: lpm;
    }
    actions = {
        forward_internal;
        forward_external;
        drop;
    }
    size = 7;
    default_action = drop;
}
