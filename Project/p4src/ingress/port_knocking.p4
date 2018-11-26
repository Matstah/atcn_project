
register<bit<32>>(KNOCK_SLOTS) reg_knocking_srcIP;
register<bit<SIZE_KNOCK_SEQ>>(KNOCK_SLOTS) reg_next_knock;
register<bit<48>>(KNOCK_SLOTS) reg_knock_timeout;

//actions port knocking
action read_knock_slot(){
    reg_knocking_srcIP.read(meta.knock_slot, (bit<32>)meta.knock_id);
    reg_next_knock.read(meta.knock_next, (bit<32>)meta.knock_id);
    reg_knock_timeout.read(meta.knock_timestamp, (bit<32>)meta.knock_id);
}

action start_knock_state(){
    reg_knocking_srcIP.write((bit<32>)meta.knock_id, hdr.ipv4.srcAddr);
    reg_next_knock.write((bit<32>)meta.knock_id, 2);
    reg_knock_timeout.write((bit<32>)meta.knock_id, standard_metadata.ingress_global_timestamp);
}

action set2next_knock_state(){
    reg_next_knock.write((bit<32>)meta.knock_id, meta.knock_next + 1);
    reg_knock_timeout.write((bit<32>)meta.knock_id, standard_metadata.ingress_global_timestamp);
}

action delete_knock_state(){
    reg_knocking_srcIP.write((bit<32>)meta.knock_id,  0); //sets slot to open
    reg_next_knock.write((bit<32>)meta.knock_id, (bit<SIZE_KNOCK_SEQ>)1);
    reg_knock_timeout.write((bit<32>)meta.knock_id, (bit<48>)0); //time.now-time.then <delta_t ok..
}

action send_controller_open_sesame(){
    meta.clone_reason = 2;
    meta.knock_srcPort = hdr.udp.srcPort;
    clone3(CloneType.I2E, 100, meta);
}

action get_knock_id(){
        hash(meta.knock_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort},
            (bit<SIZE_KNOCK_ID>)KNOCK_SLOTS);
}

action port_rule(bit<48> delta_time, bit<SIZE_KNOCK_SEQ> sequence_number, bit<SIZE_KNOCK_SEQ> total_knocks){ //seq = 0,1,2,3
    get_knock_id();

    //read register to get state values from knock_id
    read_knock_slot();

    //set variables to meta
    meta.delta_time = delta_time;
    meta.sequence_number = sequence_number;
    meta.total_knocks = total_knocks;
}

action out_of_order_knock(){
    get_knock_id();
    reg_knocking_srcIP.read(meta.knock_slot, (bit<32>)meta.knock_id);
}

action go_trough_secret_port(){

}

//table port knocking
table knocking_rules {
    key = {
        hdr.udp.dstPort: exact;
    }
    actions = {
        NoAction;
        out_of_order_knock;
        port_rule;
    }
}

table secret_entries{
    key = {
        hdr.ipv4.dstAddr : exact;
        hdr.ipv4.srcAddr : exact;
        hdr.tcp.dstPort : exact;
        hdr.tcp.srcPort : exact;
    }
    actions = {
        NoAction;
        go_trough_secret_port;
    }
    size = 255;
}
