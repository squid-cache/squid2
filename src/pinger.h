typedef struct {
    struct in_addr to;
    unsigned char opcode;
    int psize;
    char payload[8192];
} pingerEchoData;

typedef struct {
    struct in_addr from;
    unsigned char opcode;
    double rtt;
    double hops;
    int psize;
    char payload[8192];
} pingerReplyData;
