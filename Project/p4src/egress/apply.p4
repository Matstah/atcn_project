// egress apply

// DPI
if (standard_metadata.instance_type == 1){
    hdr.dpi.setValid();
    hdr.dpi.srcAddr = hdr.ipv4.srcAddr;
    hdr.dpi.ingress_port = (bit<16>)meta.ingress_port;
    hdr.ethernet.etherType = DPI_TYPE;
    truncate((bit<32>)60); // 14 + 6 + 20 + 20
}

if(standard_metadata.instance_type == 1){
    if (meta.clone_reason == 1){
        // TODO: add DPI here
    }
    if (meta.clone_reason == 2){
        hdr.knocker.setValid();
        hdr.knocker.srcAddr = hdr.ipv4.srcAddr;
        hdr.knocker.dstAddr = hdr.ipv4.dstAddr;
        hdr.knocker.srcPort = meta.knock_srcPort;
        hdr.knocker.protocol = hdr.ipv4.protocol;
        hdr.ethernet.etherType = KNOCK_TYPE;
        hdr.ipv4.setInvalid(); //removes header
        truncate((bit<32>)25); //14 + 11 =25
    }
}
