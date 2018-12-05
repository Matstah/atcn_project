action compute_cookie_hash(){
    // ack-1== meta.syn_hash.. then we got the thing back within 10 seconds.
    // cut of 1'000'000'000'000'000'000'000'000 bits 16mio 25 digits: it is like division by 2 power of 25..=16mio=16seconds slot..
    meta.syn_timestamp = standard_metadata.ingress_global_timestamp >> 25;
    //TODO: bit slicing might be way better!

    hash(meta.syn_hash,
        HashAlgorithm.crc32,
        (bit<1>)0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
           hdr.tcp.srcPort,
           hdr.tcp.dstPort,
           meta.syn_timestamp},
        (bit<32>)4294967295);
}

action set_cookie_in_ack_number(){
    //seqNo = 32 bit
    //timestamp %10 000 000: 10 seconds time to get same hash when comming back.
    compute_cookie_hash();
    //bit<32> hans = hdr.tcp.seqNo;
    hdr.tcp.ackNo = hdr.tcp.seqNo + 1; //tells the next i want
    hdr.tcp.seqNo = meta.syn_hash;
    hdr.tcp.ack = 1; //now syn and ack valid--> syn/ack
    hdr.ipv4.ttl = 64;
    //TODO: checksum for ipv4 and tcp
}


action swaps_to_reply(){
    //swap ports
    bit<16> srcPort = hdr.tcp.srcPort;
    hdr.tcp.srcPort = hdr.tcp.dstPort;
    hdr.tcp.dstPort = srcPort;
    //swap ip
    bit<32> srcIP =hdr.ipv4.srcAddr;
    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    hdr.ipv4.dstAddr = srcIP;
    //swap ethernet
    macAddr_t srcMac = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = srcMac;
}

action reply_rst(){
    swaps_to_reply();
    hdr.tcp.rst=1;
    hdr.tcp.syn=0;
    hdr.tcp.ack=1;
    bit<32> temp = hdr.tcp.ackNo;
    hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
    hdr.tcp.seqNo = temp;
    hdr.ipv4.ttl = 64;
}
