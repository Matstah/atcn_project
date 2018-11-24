// tables and actions

action forward(){
    // If input port is 1 => output port 2
    // this is towards the network, so we do not care about the MAC addresses
    if (standard_metadata.ingress_port == 1){
        standard_metadata.egress_spec = 2;
    }

    // If input port is 2 => output port 1
    // This is towards the host, so we have to change the mac addresses
    else if (standard_metadata.ingress_port == 2){
        standard_metadata.egress_spec = 1;
    }

}

action set_mac(macAddr_t src, macAddr_t dst){
    repeat();
    hdr.ethernet.srcAddr = src;
    hdr.ethernet.dstAddr = dst;
}

table ip_forwarding {
    key = {
        hdr.ipv4.dstAddr: lpm;
    }
    actions = {
        internal_forward;
    }
    size = 4;
    default_action = drop;
}
