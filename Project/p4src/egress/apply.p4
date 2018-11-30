// egress apply

// DPI
if(standard_metadata.instance_type == 1){
    if (meta.clone_id == 1){
        //DPI
        // TODO: add DPI here
        hdr.dpi.setValid();
        hdr.dpi.srcAddr = hdr.ipv4.srcAddr;
        hdr.dpi.dstAddr = hdr.ipv4.dstAddr;
        hdr.dpi.ingress_port = (bit<16>)meta.ingress_port;
        hdr.dpi.flow_id = (bit<32>) 777; // TODO: use meta.flow_id
    }
    if (meta.clone_id == 2){
        //KNOCKER
        hdr.udp.dstPort = 0; //used as id to tell controller it is a pnock acceter..
        hdr.udp.udp_length =0;
        truncate((bit<32>)42); //14 ether +20 ip+ 8 udp= 42
    }
}
