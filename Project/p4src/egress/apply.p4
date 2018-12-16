// egress apply

// handle clones
if(standard_metadata.instance_type == 1){
    //control header is used to tell the controller what to do with that packet. It is added at the end of the clone.
    hdr.controller.setValid();
    hdr.controller.type = (bit<32>)meta.clone_id;
    if (meta.clone_id == 1){
        // DPI
        hdr.dpi.setValid();
        hdr.dpi.srcAddr = hdr.ipv4.srcAddr;
        hdr.dpi.dstAddr = hdr.ipv4.dstAddr;
        hdr.dpi.ingress_port = (bit<16>) meta.ingress_port;
        hdr.dpi.flow_id = (bit<32>) meta.flow_id;
        hdr.dpi.new_flow = meta.flow_is_new;
    }
    else if (meta.clone_id == 2){
        //KNOCKER, tell controller to allow access on secret entry.
        hdr.udp.udp_length =12;
        truncate((bit<32>)46); //14 ether +20 ip+ 8 udp + 4 control_h = 46
    }
    else if (meta.clone_id == 3){
        //SYN-source validation: tell controller to accept this src as verified.
        hdr.ipv4.totalLen = 44;
        truncate((bit<32>)58);
    }
    else if (meta.clone_id == 4){
        // validated source malicious
        hdr.tcp.setInvalid();
        hdr.ipv4.totalLen = 24; // 20 Bytes of IPv4 header and 4 Bytes of clone_id (32 bits)
        hdr.ipv4.protocol = 150;
        truncate((bit<32>)38); // 14 Bytes of Ethernet header, 20 Bytes of IPv4 header and 4 Bytes of clone_id
    }
}
