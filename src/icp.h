/* $Id$ */

#ifndef ICP_H
#define ICP_H

typedef enum {
    LOG_TAG_MIN,		/* 0 */
    LOG_TCP_HIT,		/* 1 */
    LOG_TCP_MISS,		/* 2 */
    LOG_TCP_EXPIRED,		/* 3 */
    LOG_TCP_BLOCK,		/* 4 */
    LOG_TCP_DENIED,		/* 5 */
    LOG_UDP_HIT,		/* 6 */
    LOG_UDP_MISS,		/* 7 */
    LOG_UDP_DENIED,		/* 8 */
    ERR_READ_TIMEOUT,		/* 9 */
    ERR_LIFETIME_EXP,		/* 10 */
    ERR_NO_CLIENTS_BIG_OBJ,	/* 11 */
    ERR_READ_ERROR,		/* 12 */
    ERR_CLIENT_ABORT,		/* 13 */
    ERR_CONNECT_FAIL,		/* 14 */
    ERR_INVALID_URL,		/* 15 */
    ERR_NO_FDS,			/* 16 */
    ERR_DNS_FAIL,		/* 17 */
    ERR_NOT_IMPLEMENTED,	/* 18 */
    ERR_CANNOT_FETCH,		/* 19 */
    ERR_NO_RELAY,		/* 20 */
    ERR_DISK_IO,		/* 21 */
    ERR_URL_BLOCKED		/* 22 */
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
