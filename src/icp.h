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
    LOG_TCP_BLOCK,		/* 7 */
    LOG_TCP_DENIED,		/* 8 */
    LOG_UDP_HIT,		/* 9 */
    LOG_UDP_MISS,		/* 10 */
    LOG_UDP_DENIED,		/* 11 */
    ERR_READ_TIMEOUT,		/* 12 */
    ERR_LIFETIME_EXP,		/* 13 */
    ERR_NO_CLIENTS_BIG_OBJ,	/* 14 */
    ERR_READ_ERROR,		/* 15 */
    ERR_CLIENT_ABORT,		/* 16 */
    ERR_CONNECT_FAIL,		/* 17 */
    ERR_INVALID_REQ,		/* 18 */
    ERR_INVALID_URL,		/* 19 */
    ERR_NO_FDS,			/* 20 */
    ERR_DNS_FAIL,		/* 21 */
    ERR_NOT_IMPLEMENTED,	/* 22 */
    ERR_CANNOT_FETCH,		/* 23 */
    ERR_NO_RELAY,		/* 24 */
    ERR_DISK_IO,		/* 25 */
    ERR_URL_BLOCKED,		/* 26 */
    ERR_ZERO_SIZE_OBJECT	/* 27 */
} log_type;

#define ERR_MIN ERR_READ_TIMEOUT
#define ERR_MAX ERR_ZERO_SIZE_OBJECT

/* bitfields for the icpStateData 'flags' element */
#define		REQ_HTML	0x01
#define		REQ_NOCACHE	0x02
#define		REQ_IMS		0x04
#define		REQ_AUTH	0x08
#define		REQ_PUBLIC	0x10

typedef struct wwd {
    struct sockaddr_in address;
    char *msg;
    long len;
    struct wwd *next;
} icpUdpData;

extern char *icpWrite _PARAMS((int, char *, int, int, void (*handler) (), void *));
extern int icpUdpSend _PARAMS((int, char *, icp_common_t *, struct sockaddr_in *, icp_opcode));

extern int icpHandleUdp _PARAMS((int sock, void * data));
extern int asciiHandleConn _PARAMS((int sock, void * data));

extern int neighbors_do_private_keys;
extern char *IcpOpcodeStr[];

#endif
