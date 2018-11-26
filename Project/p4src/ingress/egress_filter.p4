//Filters used from intern 2 extern

table blacklist_dst_ip {
    key = {
        hdr.ipv4.dstAddr: range;
    }
    actions = {
        drop;
        NoAction;
    }
    size = 65536; //2^16
}
