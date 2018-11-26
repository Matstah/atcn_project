// ingress apply

// DPI
bit<7> prob = 0;
inspection_probability.read(prob, 0);
bit<7> rand;
random(rand,(bit<7>) 0, (bit<7>) 100);
if (rand < prob) {
    dpi();
}


//extern 2 intern
if (
    standard_metadata.ingress_port == 1 ||
    standard_metadata.ingress_port == 2 ||
    standard_metadata.ingress_port == 3
    ){
        //ingress_filter
        if(hdr.ipv4.isValid()){

            if(hdr.tcp.isValid()){

                if(whitelist_tcp_dst_port.apply().hit){
                    // drop tcp packets based on blacklisted port
                    return;
                }
            }else if(hdr.udp.isValid()){

            }

            if(blacklist_src_ip.apply().hit){
                //drop ingoing packet: blacklisted ip, not allow to access server
                return;
            }
        }
    }

//intern 2 extern
else if (
    standard_metadata.ingress_port == 4 ||
    standard_metadata.ingress_port == 5 ||
    standard_metadata.ingress_port == 6 ||
    standard_metadata.ingress_port == 7
    ){
        //egress_filter
        if(hdr.ipv4.isValid()){
            if(blacklist_dst_ip.apply().hit){
                //drop outgoing packet: blacklisted dstAddr
                return;
            }
            if(hdr.tcp.isValid()){

            }else if(hdr.udp.isValid()){

            }
        }
    }

// Forwarding
ip_forwarding.apply();
