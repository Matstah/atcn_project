//BLACK and WHITE lists
    //blacklist to block ip
    table blacklist_src_ip {
        key = {
            hdr.ipv4.srcAddr: range;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 65536; //2^16
    }

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

    //port white list
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
//END BLACK and WHITE lists
