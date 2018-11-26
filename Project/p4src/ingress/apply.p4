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
                if(secret_entries.apply().hit){
                    //TODO mstaehli: go to forwarding directly
                }
                switch(knocking_rules.apply().action_run){
                    out_of_order_knock: {
                        if(meta.knock_slot == hdr.ipv4.srcAddr){
                            delete_knock_state();
                        }
                    }
                    port_rule: {
                        //check slot status
                        if(0 == meta.knock_slot){ // slot is free
                            if(1 == meta.sequence_number){ // src knocks on first port
                                start_knock_state();
                            }else{}//do nothing, src knocked on wrong port and does not own a slot

                        }else if(meta.knock_slot == hdr.ipv4.srcAddr){ // slot is occupied by this src
                            if(1 == meta.sequence_number){
                                start_knock_state();

                            }else if(meta.sequence_number == meta.knock_next){
                                //knocking sequence is korrect
                                bit<48> time_diff = standard_metadata.ingress_global_timestamp - meta.knock_timestamp;
                                if(time_diff < meta.delta_time){
                                    //knock in expected time range
                                    if(meta.sequence_number < meta.total_knocks){
                                        //not final port, expect next node
                                        set2next_knock_state();
                                    }else{
                                        //knocked final port-> tell controller to activate vpn
                                        send_controller_open_sesame();
                                        delete_knock_state();
                                    }
                                }else{
                                    //knock timeout
                                    delete_knock_state();
                                }
                            }else{
                                //knocking sequense is false
                                delete_knock_state();
                            }
                        }else{ //(meta.knock_slot != srcIP) slot is occupied by other source
                            //check if other slot has timed out.
                            bit<48> time_diff = standard_metadata.ingress_global_timestamp - meta.knock_timestamp;
                            if(time_diff < meta.delta_time){
                                if(1 == meta.sequence_number){
                                    //src takes over state
                                    start_knock_state();
                                }else{
                                    delete_knock_state();
                                }
                            }else{} //do Nothing, state is occupied by valid other src
                        }
                    }
                }
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
