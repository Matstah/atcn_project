/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"


#define FLOWLET_TIMEOUT 48w10000000 //10sec


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    register<bit<1>>(4096) known_flows;

    action drop() {
        mark_to_drop();
    }

#include "include/filters.p4" //black and white list filters
#include "include/port_knocking.p4" //port knocking stuff

    // L2 LEARNING
    action mac_learn(){
        meta.learn.srcAddr = hdr.ethernet.srcAddr;
        meta.learn.ingress_port = standard_metadata.ingress_port;
        digest(1, meta.learn);
    }

    // learn from source address
    table smac {

        key = {
            hdr.ethernet.srcAddr: exact;
        }

        actions = {
            mac_learn;
            NoAction;
        }
        size = 256;
        default_action = mac_learn;
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    // forward to destination adress
    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    table broadcast {
        key = {
            standard_metadata.ingress_port: exact;
        }

        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }
    // END: L2 LEARNING

    apply {
         if (hdr.ipv4.isValid()){
             /* TODO ??
             // enable traffic with server for everybody for now
             // for testing should be reachable (at least for the moment)
             if (standard_metadata.ingress_port == 7) {
                 // simple routing behaviour..?
             }
             */
             if (
                 standard_metadata.ingress_port == 4 ||
                 standard_metadata.ingress_port == 5 ||
                 standard_metadata.ingress_port == 6 ||
                 standard_metadata.ingress_port == 7
                 ){
                 //in2ext TODO what about in2in
                 //dst ip blacklist filter
                 if(blacklist_dst_ip.apply().hit){
                     return; //why does it only block that way and not with drop??
                 }
                 //stateless firewall
                 if (hdr.tcp.isValid()){
                     hash(meta.flow_id,
             	         HashAlgorithm.crc16,
             	         (bit<1>)0,
             	         { hdr.ipv4.srcAddr,
             	           hdr.ipv4.dstAddr,
                            hdr.tcp.srcPort,
                            hdr.tcp.dstPort,
                            hdr.ipv4.protocol},
             	         (bit<16>)1024);
                     if (hdr.tcp.syn == 1){
                         known_flows.write(meta.flow_id, 1);
                     }
                 }
             }
             else if ( // TODO changed to else if
                 standard_metadata.ingress_port == 1 ||
                 standard_metadata.ingress_port == 2 ||
                 standard_metadata.ingress_port == 3
                 ){
                 //ext2in TODO not necessairily!! what about ext2ext?!
                 //port knocking
                 if(hdr.udp.isValid()){
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
                                             //let_knocker_pass();
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
                 //stateless firewall
                 else if (hdr.tcp.isValid()){
                     hash(meta.flow_id,
             	         HashAlgorithm.crc16,
             	         (bit<1>)0,
             	         { hdr.ipv4.dstAddr,
             	           hdr.ipv4.srcAddr,
                            hdr.tcp.dstPort,
                            hdr.tcp.srcPort,
                            hdr.ipv4.protocol},
             	         (bit<16>)1024);
                     known_flows.read(meta.flow_is_known, meta.flow_id);
                     if (meta.flow_is_known != 1){
                         //port filter, checks if traffic is for server
                         if(whitelist_tcp_dst_port.apply().hit){
                             return;
                         }
                         //TODO: what about UDP?
                     }
                }else{
                    //TODO: we receive non tcp/udp traffic.. drop
                    //TODO: what about pinging server? should this be possible?
                    //TODO: here we could do port knocking..
                    //drop();
                    //return;

                }
                //ip blacklist filter, checks if traffic comes from spam ip src
                if(blacklist_src_ip.apply().hit){
                    return;
                }
            }

            smac.apply();
            if (dmac.apply().hit){
            }
            else {
                broadcast.apply();
            }
        }
    }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {   }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
