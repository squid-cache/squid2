#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <memory.h>

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#define GRE_MAX_PKT_SZ 16384
static int gre_fd = -1;

struct _gre_hdr {
    unsigned short flags_and_version;
    unsigned short protocol_type;
    unsigned short checksum;
    unsigned short offset;
    unsigned int key;
    unsigned int sequence_number;
};

int
greInit(void)
{
    struct protoent *pe = getprotobyname("gre");
    int s = socket(PF_INET, SOCK_RAW, pe->p_proto);
    if (s < 0)
	return -1;
    return gre_fd = s;
}

ssize_t
greSend(struct sockaddr_in * S, char *buf, size_t sz)
{
    ssize_t x;
    x = sendto(gre_fd, buf, sz, 0, (struct sockaddr *) S, sizeof(*S));
    return x;
}

ssize_t
greRecv(char *buf, size_t sz)
{
    ssize_t x;
    ssize_t copy_sz;
    static char rcvbuf[GRE_MAX_PKT_SZ];
    char *p;
    struct _gre_hdr *hdr;
    x = recv(gre_fd, p = rcvbuf, GRE_MAX_PKT_SZ, 0);
    copy_sz = x;
    if (x < sizeof(struct ip)) {
	errno = EIO;
	return -1;
    }
    copy_sz -= x;
    p += x;
    hdr = (struct _gre_hdr *) p;
    if (ntohs(hdr->protocol_type) != ETHERTYPE_IP)
	return 0;
    copy_sz -= sizeof(*hdr);
    p += sizeof(*hdr);
    if (sz < copy_sz)
	copy_sz = sz;
    xmemcpy(buf, rcvbuf + sizeof(struct ip), copy_sz);
    return copy_sz;
}

ssize_t
grePack(const char *payload, size_t payloadsz, char *pkt, size_t pktsz)
{
    struct _gre_hdr hdr;
    if (pktsz < sizeof(hdr))
	return -1;
    memset(&hdr, '\0', sizeof(hdr));
    hdr.protocol_type = htons(ETHERTYPE_IP);
    xmemcpy(pkt, &hdr, sizeof(hdr));
    pktsz -= sizeof(hdr);
    pkt += sizeof(hdr);
    if (pktsz < payloadsz)
	return -1;
    xmemcpy(pkt, payload, payloadsz);
    return sizeof(hdr) + payloadsz;
}
