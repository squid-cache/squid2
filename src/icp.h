/* $Id$ */

#ifndef ICP_H
#define ICP_H

typedef enum {
    LOG_TAG_MIN,		/* 0 */
    LOG_TCP_HIT,		/* 1 */
    LOG_TCP_MISS,		/* 2 */
    LOG_TCP_EXPIRED,		/* 3 */
    LOG_TCP_USER_REFRESH,	/* 4 */
    LOG_TCP_IFMODSINCE,		/* 5 */
    LOG_TCP_SWAPIN_FAIL,	/* 6 */
    LOG_TCP_DENIED,		/* 7 */
    LOG_UDP_HIT,		/* 8 */
    LOG_UDP_MISS,		/* 9 */
    LOG_UDP_DENIED,		/* 10 */
    ERR_READ_TIMEOUT,		/* 11 */
    ERR_LIFETIME_EXP,		/* 12 */
    ERR_NO_CLIENTS_BIG_OBJ,	/* 13 */
    ERR_READ_ERROR,		/* 14 */
    ERR_CLIENT_ABORT,		/* 15 */
    ERR_CONNECT_FAIL,		/* 16 */
    ERR_INVALID_REQ,		/* 17 */
    ERR_INVALID_URL,		/* 18 */
    ERR_NO_FDS,			/* 19 */
    ERR_DNS_FAIL,		/* 20 */
    ERR_NOT_IMPLEMENTED,	/* 21 */
    ERR_CANNOT_FETCH,		/* 22 */
    ERR_NO_RELAY,		/* 23 */
    ERR_DISK_IO,		/* 24 */
    ERR_ZERO_SIZE_OBJECT	/* 25 */
} log_type;

#define ERR_MIN ERR_READ_TIMEOUT
#define ERR_MAX ERR_ZERO_SIZE_OBJECT

/* bitfields for the icpStateData 'flags' element */
#define		REQ_HTML	0x01
#define		REQ_NOCACHE	0x02
#define		REQ_IMS		0x04
#define		REQ_AUTH	0x08
#define		REQ_CACHABLE	0x10
#define 	REQ_ACCEL	0x20
#define 	REQ_HIERARCHICAL 0x40

typedef struct wwd {
    struct sockaddr_in address;
    char *msg;
    long len;
    struct wwd *next;
} icpUdpData;

extern char *icpWrite _PARAMS((int, char *, int, int, void (*handler) (), void *));
extern int icpUdpSend _PARAMS((int, char *, icp_common_t *, struct sockaddr_in *, icp_opcode));

extern int icpHandleUdp _PARAMS((int sock, void *data));
extern int asciiHandleConn _PARAMS((int sock, void *data));
extern void AppendUdp _PARAMS((icpUdpData *));

extern int neighbors_do_private_keys;
extern char *IcpOpcodeStr[];
extern int icpUdpReply _PARAMS((int fd, icpUdpData * queue));

#endif
