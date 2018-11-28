/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/definitions.p4"
#include "include/headers.p4"
#include "include/parsers.p4"

#define TIMESTAMP_WIDTH 48
#define TIMEOUT_TCP 3000
#define TIMEOUT_UDP 3000

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {

    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // DPI:
    // index = 0: prob. for a new flow to be inspected
    register<bit<7>>(1) inspection_probability;
    register<bit<1>>(4096) known_flows;
    register<bit<TIMESTAMP_WIDTH>>(4096) time_stamps;

    // Options:
    // index = 0: to be set if debugging should be activated (uses DPI)
    // TODO: add other options, e.g. enabling/disabling blacklisting, etc
    register<bit<1>>(1) options;

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

    #include "ingress/ip_forwarding.p4"
    #include "ingress/dpi.p4"
    #include "ingress/ingress_filter.p4"
    #include "ingress/egress_filter.p4"
    #include "ingress/port_knocking.p4"

    apply {
        #include "ingress/apply.p4"
    }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        #include "egress/apply.p4"
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {

     }
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
