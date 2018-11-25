// egress apply

// DPI
if (standard_metadata.instance_type == 1){
    hdr.dpi.setValid();
    hdr.dpi.srcAddr = hdr.ipv4.srcAddr;
    hdr.dpi.ingress_port = (bit<16>)meta.ingress_port;
    hdr.ethernet.etherType = DPI_TYPE;
    truncate((bit<32>)60); // 14 + 6 + 20 + 20
}
