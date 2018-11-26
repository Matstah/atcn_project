//port knocking_rules


//LIMIT RANGE OF PORT knock
//NEED ONE WAY HASH FUNCTION

#define KNOCK_SLOTS 256
#define SIZE_KNOCK_ID 10
#define SIZE_KNOCK_SEQ 4



//typedef bit<8> SIZE_KNOCK_ID;
//typedef bit<4> SIZE_KNOCK_SEQ;
//define FLOWLET_TIMEOUT 48w10000000 //10sec

register<bit<32>>(KNOCK_SLOTS) reg_knocking_srcIP;
register<bit<SIZE_KNOCK_SEQ>>(KNOCK_SLOTS) reg_next_knock;
register<bit<48>>(KNOCK_SLOTS) reg_knock_timeout;

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
    //open port for srcIP
    //tell controller
}

action get_knock_id(){
        hash(meta.knock_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort},
            (bit<SIZE_KNOCK_ID>)KNOCK_SLOTS);
}

//problem: easy DOS by spoofing source and just sending to random port..
action port_rule(bit<48> delta_time, bit<SIZE_KNOCK_SEQ> sequence_number, bit<SIZE_KNOCK_SEQ> total_knocks){ //seq = 0,1,2,3
    get_knock_id();

    //read register to get state values from knock_id
    read_knock_slot();

    //set variables to meta
    meta.delta_time = delta_time;
    meta.sequence_number = sequence_number;
    meta.total_knocks = total_knocks;

//INFO: i took this out because action does not take conditions..


    //check slot status
//    if(0 == meta.knock_slot){ // slot is free
//        if(1 == sequence_number){ // src knocks on first port
//            start_knock_state();
//        }else{}//do nothing, src knocked on wrong port and does not own a slot
//
//    }else if(meta.knock_slot == hdr.ipv4.srcAddr){ // slot is occupied by this src
//        if(1 == sequence_number){
//            start_knock_state();
//
//        }else if(sequence_number == meta.knock_next){
//            //knocking sequence is korrect
//            bit<48> time_diff = standard_metadata.ingress_global_timestamp - meta.knock_timestamp;
//            if(time_diff < delta_time){
//                //knock in expected time range
//                if(sequence_number < total_knocks){
//                    //not final port, expect next node
//                    set2next_knock_state();
//                }else{
//                    //knocked final port-> tell controller to activate vpn
//                    //let_knocker_pass();
//                    delete_knock_state();
//                }
//            }else{
//                //knock timeout
//                delete_knock_state();
//            }
//        }else{
//            //knocking sequense is false
//            delete_knock_state();
//        }
//    }else{ //(meta.knock_slot != srcIP) slot is occupied by other source
//        //check if other slot has timed out.
//        bit<48> time_diff = standard_metadata.ingress_global_timestamp - meta.knock_timestamp;
//        if(time_diff < delta_time){
//            if(1 == sequence_number){
//                //src takes over state
//                start_knock_state();
//            }else{
//                delete_knock_state();
//            }
//        }else{} //do Nothing, state is occupied by valid other src
//    }
}

action out_of_order_knock(){
    get_knock_id();
    reg_knocking_srcIP.read(meta.knock_slot, (bit<32>)meta.knock_id);
//    if(meta.knock_slot == hdr.ipv4.srcAddr){
//        delete_knock_state();
//    }else{} //don't care, as srcIP does not have a slot(not knocking..)
}


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
