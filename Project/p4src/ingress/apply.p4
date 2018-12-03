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
                    //TODO mstaehli: go to forwarding
                    //setting meta.accept=1 on hit
                }
                if(meta.accept == 0){
                    hash_extern_tcp_packet();
                    known_flows.read(meta.flow_is_known, meta.flow_id);
                    time_stamps.read(meta.max_time, meta.flow_id);

                    if (meta.flow_is_known != 1){
                        // new flow
                        if(whitelist_tcp_dst_port.apply().hit){
                            // drop tcp packets based on blacklisted port
                            return;
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

                    //statefull firewall
                    hash_extern_udp_packet();
                    known_flows.read(meta.flow_is_known, meta.flow_id);
                    time_stamps.read(meta.max_time, meta.flow_id);
                    if (meta.flow_is_known != 1) {
                        // flow unknown
                        drop();
                        return;
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

            if(meta.accept == 0){ // TODO: second time that meta.accept is checked ?? Why?
                if(blacklist_src_ip.apply().hit){
                    //drop ingoing packet: blacklisted ip, not allow to access server
                    return;
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

// Clone packet if necessairy TODO: does this interfere with Knocking?
// TODO: provide debugging possibility here?
if(hdr.ipv4.isValid()) {
    inspected_flows.read(meta.dpi_activated, meta.flow_id);
    if (meta.dpi_activated > 0) {
        clone_for_dpi();
    }


    // Forwarding
    ip_forwarding.apply();
}
