/* $Id$ */

#ifndef ICP_H
#define ICP_H

typedef enum {
    LOG_TAG_MIN,		/* 0 */
    LOG_TCP_HIT,		/* 1 */
    LOG_TCP_MISS,		/* 2 */
    LOG_TCP_EXPIRED,		/* 3 */
    LOG_TCP_USER_REFRESH,	/* 4 */
    LOG_TCP_SWAPIN_FAIL,	/* 5 */
    LOG_TCP_BLOCK,		/* 6 */
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
    ERR_INVALID_URL,		/* 17 */
    ERR_NO_FDS,			/* 18 */
    ERR_DNS_FAIL,		/* 19 */
    ERR_NOT_IMPLEMENTED,	/* 20 */
    ERR_CANNOT_FETCH,		/* 21 */
    ERR_NO_RELAY,		/* 22 */
    ERR_DISK_IO,		/* 23 */
    ERR_URL_BLOCKED,		/* 24 */
    ERR_ZERO_SIZE_OBJECT	/* 25 */
} log_type;

#define ERR_MIN ERR_READ_TIMEOUT
#define ERR_MAX ERR_URL_BLOCKED

extern int icpHandleUdp _PARAMS((int sock, caddr_t data));
extern int asciiHandleConn _PARAMS((int sock, caddr_t data));

typedef struct wwd {
    struct sockaddr_in address;
    char *msg;
    long len;
    struct wwd *next;
} icpUdpData;

extern char *icpWrite _PARAMS((int, char *, int, int, void (*handler) (), caddr_t));
extern int icpUdpSend _PARAMS((int, char *, icp_common_t *, struct sockaddr_in *, icp_opcode));

#endif
