/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
} // 14 Bytes

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen; //including header and data
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
} // 20 Bytes

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udp_length;
    bit<16> checksum;
} // 8 Bytes

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo; //12bytes
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin; //2
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr; //6
}//20

header dpi_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> ingress_port;
    bit<32> flow_id;
    bit<8> new_flow;
} // 15 Bytes

header controller_t{
    bit<32> type;
}//4 bytes

struct metadata {
    bit<8> clone_id; //1:DPI, 2:port knocking, 3:src valid, 4:src malicious
    bit<1> accept;

    // DPI
    bit<1> dpi_activated;
    bit<8> flow_is_new;
    port_t ingress_port; // because cloning resets all metadata
                         // and the ingress port might be of interest in DPI

    //port knocking part
    bit<8> knock_id;
    bit<32> knock_srcIP;
    bit<SIZE_KNOCK_SEQ> knock_next;
    bit<48> knock_timestamp;
    bit<48> delta_time;
    bit<SIZE_KNOCK_SEQ> sequence_number;
    bit<SIZE_KNOCK_SEQ> total_knocks;
    bit<16> knock_srcPort;
    bit<32> knock_dstIP;

    // stateless part
    bit<32> flow_id;
    bit<32> hash_output_one;
    bit<32> hash_output_two;
    bit<32> counter_one;
    bit<32> counter_two;
    bit<1> flow_is_known;
    bit<48> max_time;

    //syn defense
    bit<32> syn_hash;
    bit<48> syn_timestamp;
}

struct headers {
    // standard headers
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;

    // our headers
    controller_t controller;
    dpi_t        dpi;
}
