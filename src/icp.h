/* $Id$ */

#ifndef ICP_H
#define ICP_H

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
