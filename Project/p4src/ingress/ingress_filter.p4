//static filters used for traffic from extern 2 intern


table blacklist_src_ip {
    key = {
        hdr.ipv4.srcAddr: range;
    }
    actions = {
        drop;
        NoAction;
    }
    size = 65536; //2^16 = #ports
}

//tcp port white list
table whitelist_tcp_dst_port{
    key = {
        hdr.tcp.dstPort: exact;
    }
    actions = {
        drop;
        NoAction;
    }
    size = 255; //16bit for ports.., but only a few to allow
}
