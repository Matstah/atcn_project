/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define TIMESTAMP_WIDTH 48
#define TIMEOUT_TCP 3000
#define TIMEOUT_UDP 3000


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
    register<bit<TIMESTAMP_WIDTH>>(4096) time_stamps;

    action drop() {
        mark_to_drop();
    }

    action hash_packet() {
        hash(meta.flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
               hdr.udp.srcPort,
               hdr.udp.dstPort,
               hdr.ipv4.protocol},
            (bit<16>)1024);
    }

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

    apply {
        // TODO: calculate how big the chance for false positives is for the hashes (in slides) - need an explanation why size of register is used ("...want a fpr lower than 1%...")
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
                     hash_packet();
                     if (hdr.tcp.syn == 1){
                         time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_TCP);
                         known_flows.write(meta.flow_id, 1);
                     } else if (hdr.tcp.fin == 1){
                         known_flows.write(meta.flow_id, 0);
                         time_stamps.write(meta.flow_id, 0);
                     }
                 } else if(hdr.udp.isValid()){
                    hash_packet();
                    // only save UDP flow if the packet is not a one-off (if source Port is not 0) and thus awaits a response
                    if(hdr.udp.srcPort != 0){
                        known_flows.write(meta.flow_id, 1);
                        time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_UDP);
                    }
                 }
             }
             else if ( // TODO changed to else if
                 standard_metadata.ingress_port == 1 ||
                 standard_metadata.ingress_port == 2 ||
                 standard_metadata.ingress_port == 3
                 ){
                 //ext2in TODO not necessairily!! what about ext2ext?!
                 //stateless firewall
                 if (hdr.tcp.isValid()){
                     hash_packet();
                     known_flows.read(meta.flow_is_known, meta.flow_id);
                     time_stamps.read(meta.max_time, meta.flow_id;
                     if (meta.flow_is_known != 1){
                         //port filter, checks if traffic is for server
                         if(whitelist_tcp_dst_port.apply().hit){
                             return;
                         }
                         //TODO: what about UDP?
                     }
                     if(meta.max_time < standard_metadata.ingress_global_timestamp){
                         known_flows.write(meta.flow_id, 0);
                         time_stamps.write(meta.flow_id, 0);
                         drop(); return;
                     } else {
                         time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_TCP);
                     }
                } else if(hdr.udp.isValid()){
                   hash_packet();
                   known_flows.read(meta.flow_is_known, meta.flow_id);
                   time_stamps.read(meta.max_time, meta.flow_id);
                   if (meta.flow_is_known != 1) {
                       //TODO: whitelist?
                   }
                   if(meta.max_time < standard_metadata.ingress_global_timestamp) {
                       known_flows.write(meta.flow_id, 0);
                       time_stamps.write(meta.flow_id, 0);
                       drop(); return;
                   } else {
                       time_stamps.write(meta.flow_id, standard_metadata.ingress_global_timestamp + (bit<48>)TIMEOUT_UDP);
                   }
                }
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
