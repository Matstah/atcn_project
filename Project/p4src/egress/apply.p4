// egress apply

// DPI
if(standard_metadata.instance_type == 1){
    if (meta.clone_reason == 1){
        // DPI
        hdr.dpi.setValid();
        hdr.dpi.srcAddr = hdr.ipv4.srcAddr;
        hdr.dpi.dstAddr = hdr.ipv4.dstAddr;
        hdr.dpi.ingress_port = (bit<16>) meta.ingress_port;
        hdr.dpi.flow_id = (bit<32>) meta.flow_id;
        hdr.dpi.debug = meta.debugging;
        hdr.dpi.inspect = meta.dpi_activated;
        hdr.dpi.unused = (bit<6>) 0;
    }
    else if (meta.clone_reason == 2){
        // Port Knocking
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
