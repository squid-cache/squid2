#ifndef _PINGER_H_
#define _PINGER_H_

typedef struct {
    struct in_addr to;
    unsigned char opcode;
    int psize;
    char payload[8192];
} pingerEchoData;

typedef struct {
    struct in_addr from;
    unsigned char opcode;
    int rtt;
    int hops;
    int psize;
    char payload[8192];
} pingerReplyData;

#endif /* _PINGER_H_ */
