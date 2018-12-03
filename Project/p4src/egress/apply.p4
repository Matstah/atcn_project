// egress apply

// DPI
if(standard_metadata.instance_type == 1){
    if (meta.clone_id == 1){
        // DPI
        hdr.dpi.setValid();
        hdr.dpi.srcAddr = hdr.ipv4.srcAddr;
        hdr.dpi.dstAddr = hdr.ipv4.dstAddr;
        hdr.dpi.ingress_port = (bit<16>) meta.ingress_port;
        hdr.dpi.flow_id = (bit<32>) meta.flow_id;
        hdr.dpi.debug = meta.debugging;
        hdr.dpi.inspect = meta.dpi_activated;
        hdr.dpi.new_flow = meta.flow_is_new;
        hdr.dpi.unused = (bit<5>) 0;
    }
    if (meta.clone_id == 2){
        //KNOCKER
        hdr.udp.dstPort = 0; //used as id to tell controller it is a pnock acceter..
        hdr.udp.udp_length =0;
        truncate((bit<32>)42); //14 ether +20 ip+ 8 udp= 42
    }
    if (meta.clone_id == 3){
        //syn_defender: tell controller to accept this src.

    }
}
