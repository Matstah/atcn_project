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
#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 32

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
    register<bit<1>>(4096) inspected_flows;
    register<bit<TIMESTAMP_WIDTH>>(4096) time_stamps;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;

    // Options:
    // index = 0: to be set if debugging should be activated (uses DPI)
    // TODO: add other options, e.g. enabling/disabling blacklisting, etc
    register<bit<1>>(1) options;

    action drop() {
        mark_to_drop();
    }

    action hash_bloom_tcp_packet_32() {
        hash(meta.hash_output_one,
            HashAlgorithm.crc32,
            (bit<1>)0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
               hdr.tcp.srcPort,
               hdr.tcp.dstPort,
               hdr.ipv4.protocol},
            (bit<16>)1024);
    }

    action hash_bloom_tcp_packet() {
        hash(meta.hash_output_two,
            HashAlgorithm.crc16,
            (bit<1>)0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
               hdr.tcp.srcPort,
               hdr.tcp.dstPort,
               hdr.ipv4.protocol},
            (bit<16>)1024);
    }

    action hash_intern_tcp_packet() {
        hash(meta.flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
               hdr.tcp.srcPort,
               hdr.tcp.dstPort,
               hdr.ipv4.protocol},
            (bit<16>)1024);
    }

    action hash_intern_udp_packet() {
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

    action hash_extern_tcp_packet() {
        hash(meta.flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            { hdr.ipv4.dstAddr,
              hdr.ipv4.srcAddr,
               hdr.tcp.dstPort,
               hdr.tcp.srcPort,
               hdr.ipv4.protocol},
            (bit<16>)1024);
    }

    action hash_extern_udp_packet() {
        hash(meta.flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            { hdr.ipv4.dstAddr,
              hdr.ipv4.srcAddr,
               hdr.udp.dstPort,
               hdr.udp.srcPort,
               hdr.ipv4.protocol},
            (bit<16>)1024);
    }

    action update_bloom_filter(){
        hash_bloom_tcp_packet_32();
        hash_bloom_tcp_packet();
        bloom_filter.read(meta.counter_one, meta.hash_output_one);
        bloom_filter.read(meta.counter_two, meta.hash_output_two);

        meta.counter_one = meta.counter_one + 1;
        meta.counter_two = meta.counter_two + 1;

        bloom_filter.write(meta.hash_output_one, meta.counter_one);
        bloom_filter.write(meta.hash_output_two, meta.counter_two);
    }

    #include "ingress/ip_forwarding.p4"
    #include "ingress/dpi.p4"
    #include "ingress/ingress_filter.p4"
    #include "ingress/egress_filter.p4"
    #include "ingress/port_knocking.p4"
    #include "ingress/syn_defense.p4"

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
         update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);

        update_checksum(
            hdr.tcp.isValid(),
            {hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.cwr,
                hdr.tcp.ece,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                hdr.tcp.urgentPtr},
                hdr.tcp.checksum,
                HashAlgorithm.csum16);

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
