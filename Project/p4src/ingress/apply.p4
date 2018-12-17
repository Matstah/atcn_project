// ingress apply

meta.accept = 0;
meta.flow_is_new = 0; // default for DPI

// extern 2 intern: ports 1,2,3 are towards external network
if (
    standard_metadata.ingress_port == 1 ||
    standard_metadata.ingress_port == 2 ||
    standard_metadata.ingress_port == 3
    ){
        if(hdr.ipv4.isValid()){
            // *** TCP ***
            if(hdr.tcp.isValid()){

                // Can the source enter, because it knocked correctly?
                if(secret_entries.apply().hit){
                    //hit action sets meta.accept=1
                }

                // Is the source validated? (from syndef mechanism)
                if(source_accepted.apply().hit){
                    //TODO mstaehli: source port checked for heavy hitting

                    // Count syn packets to verify that valid source performs
                    //   no syn flood attack
                    if(hdr.tcp.syn == 1 && hdr.tcp.ack != 1){
                        update_bloom_filter();
                        if(meta.counter_one > PACKET_THRESHOLD &&
                            meta.counter_two > PACKET_THRESHOLD) {
                            // source has sent too many syns
                            // controller removes entry and blacklists source
                            meta.clone_id = 4;
                            clone3(CloneType.I2E, 100, meta);

                            // firewall drops packet to protect server even
                            // before controller has finished
                            drop();
                            return;
                        }
                        else {
                            // source is still allowed to send syns
                            meta.accept = 1;
                        }
                    } else {
                        // other traffic than syn is allowed
                        meta.accept = 1;
                    }
                }

                // The source was not validated by knock or syndef mechanism
                // continue with stateful awareness of flows
                if(meta.accept == 0){
                    // hash packet values to recognize flow
                    hash_extern_tcp_packet();
                    known_flows.read(meta.flow_is_known, meta.flow_id);
                    time_stamps.read(meta.max_time, meta.flow_id);

                    // unknown/new tcp flow from ext2int
                    if (meta.flow_is_known != 1){
                        // new traffic is only allowed if dst port is whitelisted
                        // if there is a hit, NoAction is applied,
                        // else the action is drop!
                        if(!whitelist_tcp_dst_port.apply().hit){
                            // packet not ok because not on our whitelist
                            // we do net get here, because on 'not hit' the pkt
                            // is dropped // TODO: correct statement? is the return then needed?
                            return;
                            //next: check ip on src blacklist // TODO: is this missing???
                        }
                    }

                    // flow is known
                    else {
                        // flow timed out
                        if(meta.max_time < standard_metadata.ingress_global_timestamp){
                            // forget flow
                            known_flows.write(meta.flow_id, 0);
                            time_stamps.write(meta.flow_id, 0);

                            // also forget flow for DPI
                            // (if it was inspected in the first place)
                            bit<1> flow_was_inspected;
                            inspected_flows.read(flow_was_inspected, meta.flow_id);
                            if (flow_was_inspected == 1) {
                                deselect_for_dpi();
                            }

                            // drop the timed out packet
                            // a new flow should be initiated internally
                            drop();
                            return;
                        }

                        // flow is ok!
                        else {
                            time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_TCP);
                            meta.accept = 1;
                        }
                    }
                }
            } // end tcp

            // *** UDP ***
            else if(hdr.udp.isValid()){
                // There are no 'pre-filters' for UDP

                if(meta.accept == 0){
                    // PORT KNOCKER
                    // Run packet through knocking state machine
                    // if successful, the controller gets a msg to allow entry
                    // for future traffic
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
                                            // knocking sequence is correct
                                            bit<48> time_diff = standard_metadata.ingress_global_timestamp - meta.knock_timestamp;
                                            if(time_diff < meta.delta_time){
                                            // knock in expected time range
                                                if(meta.sequence_number < meta.total_knocks){
                                                    // not final port, expect next node
                                                    set2next_knock_state();
                                                }else{
                                                    // knocked final port-> tell controller to activate vpn
                                                    send_controller_open_sesame();
                                                    delete_knock_state();
                                                }
                                            }else{
                                                // knock timeout
                                                delete_knock_state();
                                            }
                                        }else{
                                            // knocking sequense is false
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
                    // END of port knocker

                    // STATEFUL FIREWALL
                    // hash packet values to recognize flow
                    hash_extern_udp_packet();
                    known_flows.read(meta.flow_is_known, meta.flow_id);
                    time_stamps.read(meta.max_time, meta.flow_id);

                    // unknown/new udp flow from ext2int
                    if (meta.flow_is_known != 1) {
                        // there is no externally established udp allowed
                        drop();
                        return;
                        //TODO: port whitelist for udp!
                    }

                    // flow is known
                    else {
                        // flow timed out
                        if(meta.max_time < standard_metadata.ingress_global_timestamp) {
                            // forget flow
                            known_flows.write(meta.flow_id, 0);
                            time_stamps.write(meta.flow_id, 0);

                            // also forget flow for DPI
                            // (if it was inspected in the first place)
                            bit<1> flow_was_inspected;
                            inspected_flows.read(flow_was_inspected, meta.flow_id);
                            if (flow_was_inspected == 1) {
                                deselect_for_dpi();
                            }

                            // drop the timed out packet
                            // a new flow should be initiated internally
                            drop();
                            return;
                        }

                        // flow is ok!
                        else {
                            time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_UDP);
                            meta.accept = 1;
                        }
                    }
                }
            } // end udp

            // If no of the measures above accepted or denied the packet yet,
            // go into 'second phase'
            if(meta.accept == 0){
                // check blacklist: stop here if hit
                if(blacklist_src_ip.apply().hit){
                    return;
                }

                // here packet:
                //  - passed ip src blacklist
                //  - port whitelist
                //  - is not a known flow
                //  - does not have secret port
                // --> let it access our server.
                if(hdr.tcp.isValid()){

                    //SYN COOKIES SYN-DEFENSE
                    if(hdr.tcp.syn == 1){
                        //Debugging: test clone to check number
                        //clone3(CloneType.I2E, 100, meta);

                        // Perform handshake with client
                        set_cookie_in_ack_number();
                        swaps_to_reply();
                    }
                    else {
                        // Check if client replies to our SYNACK
                        // by recomputing cookie hash
                        compute_cookie_hash();
                        bit<32> ack = hdr.tcp.ackNo-1;

                        //source is valid- not spoofed..
                        // tell controller to put grand access
                        // reply with RST = 1: client has to start another
                        // handshake, which will then be done with server
                        if(ack == meta.syn_hash){
                            meta.clone_id = 3;
                            clone3(CloneType.I2E, 100, meta);
                            reply_rst();
                        }

                        //we received some ack that is not okey.. or has timed out.
                        else{
                            reply_rst();
                        }
                    } // end of syn-defense
                }
            } // end 'second phase'
        } // end of valid IPv4
} // end of extern 2 intern

// intern 2 extern: ports 4,5,6,7 are towards internal network
// traffic generated internally is assumed to be "well-behaved" to some extent
else if (
    standard_metadata.ingress_port == 4 ||
    standard_metadata.ingress_port == 5 ||
    standard_metadata.ingress_port == 6 ||
    standard_metadata.ingress_port == 7
    ){
        if(hdr.ipv4.isValid()){

            // drop outgoing packet if blacklisted dstAddr
            if(blacklist_dst_ip.apply().hit){
                return;
            }

            // *** TCP ***
            if(hdr.tcp.isValid()){
                // crate flow id
                hash_intern_tcp_packet();

                // we establish a connection with an external dst
                if (hdr.tcp.syn == 1 && hdr.tcp.ack != 1) {
                    // select flow (randomly) for dpi, but perform action if we
                    // have not already started inspecting it
                    bit<1> flow_was_inspected;
                    inspected_flows.read(flow_was_inspected, meta.flow_id);
                    if (flow_was_inspected != 1) {
                        random_select_for_dpi();
                    }

                    // first time traffic gets from inside to outside.
                    // opens/sets flow_is_known to 1,
                    // such that flow can enter from outside in.
                    time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_TCP);
                    known_flows.write(meta.flow_id, 1);
                }
                // we termiante a tcp connection
                else if (hdr.tcp.fin == 1) {
                    // forget flow
                    known_flows.write(meta.flow_id, 0);
                    time_stamps.write(meta.flow_id, 0);

                    // also forget flow for DPI
                    // (if it was inspected in the first place)
                    bit<1> flow_was_inspected;
                    inspected_flows.read(flow_was_inspected, meta.flow_id);
                    if (flow_was_inspected == 1) {
                        deselect_for_dpi();
                    }
                }
            } // end of tcp

            // *** UDP ***
            else if(hdr.udp.isValid()) {
                // get flow id
                hash_intern_udp_packet();

                // only save UDP flow if the packet is not a one-off
                // (if source Port is not 0) and thus awaits a response
                if(hdr.udp.srcPort != 0){
                    // select flow (randomly) for dpi, but perform action if we
                    // have not already started inspecting it
                    bit<1> flow_was_inspected;
                    inspected_flows.read(flow_was_inspected, meta.flow_id);
                    if (flow_was_inspected != 1) {
                        random_select_for_dpi();
                    }

                    // save flow
                    known_flows.write(meta.flow_id, 1);
                    time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_UDP);
                }
            } // end of udp
        } // end of valid IPv4
} // end of intern 2 extern

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
