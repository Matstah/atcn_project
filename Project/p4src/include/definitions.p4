const bit<16> TYPE_IPV4 = 0x800;

#define KNOCK_SLOTS 256
#define SIZE_KNOCK_ID 10
#define SIZE_KNOCK_SEQ 4 // bit length for knock params

typedef bit<9> port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
