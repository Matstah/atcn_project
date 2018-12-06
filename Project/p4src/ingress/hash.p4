// all hash action that are needed and the update action for the bloom filter

action hash_bloom_tcp_packet_32() {
    hash(meta.hash_output_one,
        HashAlgorithm.crc32,
        (bit<1>)0,
        {hdr.ipv4.srcAddr},
        (bit<16>)1024);
}

action hash_bloom_tcp_packet() {
    hash(meta.hash_output_two,
        HashAlgorithm.crc16,
        (bit<1>)0,
        {hdr.ipv4.srcAddr},
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
