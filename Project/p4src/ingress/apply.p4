// ingress apply

meta.accept = 0;
//extern 2 intern
if (
    standard_metadata.ingress_port == 1 ||
    standard_metadata.ingress_port == 2 ||
    standard_metadata.ingress_port == 3
    ){
        //ingress_filter
        if(hdr.ipv4.isValid()){

            if(hdr.tcp.isValid()){
                if(secret_entries.apply().hit){
                    //hit action sets meta.accept=1
                }
                if(source_accepted.apply().hit){
                    //TODO mstaehli: source port checked for heavy hitting
                    if(hdr.tcp.syn == 1){
                        update_bloom_filter();
                        if(meta.counter_one > PACKET_THRESHOLD && meta.counter_two > PACKET_THRESHOLD) {
                            // TODO: write to blacklist if this is the case
                            meta.clone_id = 4;
                            clone3(CloneType.I2E, 100, meta);
                            drop();
                            return;
                        }
                        else {
                            meta.accept = 1;
                        }
                    } else {
                        meta.accept = 1;
                    }
                }
                if(meta.accept == 0){
                    hash_extern_tcp_packet();
                    known_flows.read(meta.flow_is_known, meta.flow_id);
                    time_stamps.read(meta.max_time, meta.flow_id);

                    if (meta.flow_is_known != 1){
                        // unknown/new flow from ext2int
                        if(!whitelist_tcp_dst_port.apply().hit){
                            // packet droped based on white list hit
                            return;
                            //next: check ip on src blacklist
                        }
                    }
                    else {
                        // flow is known
                        if(meta.max_time < standard_metadata.ingress_global_timestamp){
                            // flow timed out
                            known_flows.write(meta.flow_id, 0);
                            time_stamps.write(meta.flow_id, 0);

                            // also forget flow for DPI
                            bit<1> flow_was_inspected;
                            inspected_flows.read(flow_was_inspected, meta.flow_id);
                            if (flow_was_inspected == 1) {
                                deselect_for_dpi();
                            }

                            // drop
                            drop(); return;
                        }
                        else {
                            //pass packet
                            time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_TCP);
                            meta.accept = 1;
                        }
                    }
                }
            }else if(hdr.udp.isValid()){
                if(meta.accept == 0){
                    //PORT KNOCKER
                    switch(knocking_rules.apply().action_run){
                        out_of_order_knock: {
                            if(meta.knock_srcIP == hdr.ipv4.srcAddr){
                                if(meta.knock_srcPort == hdr.udp.srcPort){
                                    if(meta.knock_dstIP == hdr.ipv4.dstAddr){
                                        delete_knock_state();
                                    }
                                }
                            }
                        }
                        port_rule: {
                            //check slot status
                            if(0 == meta.knock_srcIP){ // slot is free
                                if(1 == meta.sequence_number){ // src knocks on first port
                                    start_knock_state();
                                }else{}//do nothing, src knocked on wrong port and does not own a slot

                            }else if(meta.knock_srcIP == hdr.ipv4.srcAddr){
                                if(meta.knock_srcPort == hdr.udp.srcPort){
                                    if(meta.knock_dstIP == hdr.ipv4.dstAddr){
                                        // slot is occupied by this src
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
                                    }
                                }
                            }else{ //(meta.knock_srcIP != srcIP) slot is occupied by other source
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

                    //statefull firewall
                    hash_extern_udp_packet();
                    known_flows.read(meta.flow_is_known, meta.flow_id);
                    time_stamps.read(meta.max_time, meta.flow_id);
                    if (meta.flow_is_known != 1) {
                        // new/unknown udp flow from ext2int
                        drop();
                        return;
                        //TODO: port whitelist for udp!
                    }
                    else {
                        // flow is known
                        if(meta.max_time < standard_metadata.ingress_global_timestamp) {
                            // flow timed out
                            known_flows.write(meta.flow_id, 0);
                            time_stamps.write(meta.flow_id, 0);

                            // also forget flow for DPI
                            bit<1> flow_was_inspected;
                            inspected_flows.read(flow_was_inspected, meta.flow_id);
                            if (flow_was_inspected == 1) {
                                deselect_for_dpi();
                            }

                            // drop
                            drop(); return;
                        } else {
                            //let packet pass
                            time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_UDP);
                            meta.accept = 1;
                        }
                    }
                }
            }
        if(meta.accept == 0){ // TODO: second time that meta.accept is checked ?? Why?--> because of new filters applied..
            if(blacklist_src_ip.apply().hit){
                //drop ingoing packet: blacklisted ip, not allow to access server
                return;
            }
            //here packet passed ip src blacklist, port whitelist, is not a known flow and does not have secret port:
            //let it access our server.
            if(hdr.tcp.isValid()){

                //SYN COOKIES SYN-DEFENSE
                if(hdr.tcp.syn == 1){
                    //test clone to check number
                    //test end
                    //clone3(CloneType.I2E, 100, meta);
                    set_cookie_in_ack_number();
                    swaps_to_reply();
                }else{
                    compute_cookie_hash();
                    bit<32> ack = hdr.tcp.ackNo-1;
                    if(ack == meta.syn_hash){
                        //source is valid- not spoofed.. tell controller to put grand access
                        //reply with RST = 1
                        meta.clone_id = 3; //TODO, but don't know how..
                        clone3(CloneType.I2E, 100, meta);
                        reply_rst();
                    }else{
                        //we received some ack that is not okey.. or has timed out.
                       reply_rst();
                       //drop();
                       //return;
                    }
                }
            }
        }
    }
}
//intern 2 extern
// traffic generated internally is assumed to be "well-behaved" to some extent
// TODO: internally started traffic is not inspected
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
                hash_intern_tcp_packet();
                if (hdr.tcp.syn == 1){
                    //first time traffic gets from inside to outside.. opens/ sets flow_is_known to 1, such that flow can enter from outside in.
                    time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_TCP);
                    known_flows.write(meta.flow_id, 1);
                    random_select_for_dpi();
                } else if (hdr.tcp.fin == 1){
                    known_flows.write(meta.flow_id, 0);
                    time_stamps.write(meta.flow_id, 0);
                }
            }else if(hdr.udp.isValid()){
                hash_intern_udp_packet();
                // only save UDP flow if the packet is not a one-off (if source Port is not 0) and thus awaits a response
                if(hdr.udp.srcPort != 0){
                    known_flows.write(meta.flow_id, 1);
                    time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_UDP);
                    random_select_for_dpi();
                }
            }
        }


}

// Forwarding
if(hdr.ipv4.isValid()) {

    // Clone packet if requested for DPI
    inspected_flows.read(meta.dpi_activated, meta.flow_id);
    if (meta.dpi_activated > 0) {
        clone_for_dpi();
    }

    // Forwarding
    ip_forwarding.apply();
}
