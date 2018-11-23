/* -*- P4_16 -*- */

/*COPIED FROM EXERCISE 02-Repeater*/
/* and expanded to change ethernet header */

#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
const macAddr_t SWITCH_MAC = 0x00010a000201;
const macAddr_t HOST_MAC = 0x00000a000201;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

struct metadata {
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct headers {
    ethernet_t ethernet;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

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

    apply {

        // If input port is 1 => output port 2
        // this is towards the network, so we do not care about the MAC addresses
        if (standard_metadata.ingress_port == 1){
            standard_metadata.egress_spec = 2;
        }

        // If input port is 2 => output port 1
        // This is towards the host, so we have to change the mac addresses
        else if (standard_metadata.ingress_port == 2){
            standard_metadata.egress_spec = 1;
            hdr.ethernet.srcAddr = SWITCH_MAC;
            hdr.ethernet.dstAddr = HOST_MAC;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
