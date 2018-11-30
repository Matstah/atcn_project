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
    bit<16>   totalLen;
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
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct learn_t {

}

header dpi_t { // DPI
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> ingress_port;
    bit<32> flow_id;
} // 14 Bytes

header knocker_t{
    bit<16> knock_payload;
}//2 bytes

struct metadata {
    bit<8> clone_id; //1:DPI //2:port knocking
    bit<1> accept;
    // DPI
    bit<1> debugging;
    bit<1> dpi_activated;
    port_t ingress_port; // DPI, because cloning resets all metadata

    //port knocking part
    bit<8> knock_id;
    bit<32> knock_slot;
    bit<SIZE_KNOCK_SEQ> knock_next;
    bit<48> knock_timestamp;
    bit<48> delta_time;
    bit<SIZE_KNOCK_SEQ> sequence_number;
    bit<SIZE_KNOCK_SEQ> total_knocks;
    bit<16> knock_srcPort;

    // stateless part
    bit<32> flow_id; // TODO: check bit length // also used for DPI
    bit<1> flow_is_known;
    bit<48> max_time;
    learn_t learn;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;

    dpi_t        dpi; // DPI
    knocker_t    knocker;
}
