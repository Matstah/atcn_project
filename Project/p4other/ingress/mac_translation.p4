// tables and actions

action repeat(){
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

table mac_translation {
    key = {
        standard_metadata.ingress_port: exact;
    }
    actions = {
        repeat();
        set_mac();
    }
    size = 2;
    default_action = repeat;
}
