/*
 * $Id$
 *
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#ifndef _URL_HEADER_
#define _URL_HEADER_

#define MAX_URL  4096
#define MAX_LOGIN_SZ  128

enum {
    METHOD_NONE,		/* 000 */
    METHOD_GET,			/* 001 */
    METHOD_POST,		/* 010 */
    METHOD_PUT,			/* 011 */
    METHOD_HEAD,		/* 100 */
    METHOD_CONNECT		/* 101 */
};
typedef unsigned int method_t;

extern char *RequestMethodStr[];

typedef enum {
    PROTO_NONE,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_GOPHER,
    PROTO_WAIS,
    PROTO_CACHEOBJ,
    PROTO_MAX
} protocol_t;

extern char *ProtocolStr[];

struct _request {
    method_t method;
    protocol_t protocol;
    char login[MAX_LOGIN_SZ + 1];
    char host[SQUIDHOSTNAMELEN + 1];
    int port;
    char urlpath[MAX_URL + 1];
    int link_count;		/* free when zero */
    struct _hierarchyLogData hierarchy;
    int flags;
};

extern char *url_convert_hex __P((char *org_url, int allocate));
extern char *url_escape __P((char *url));
extern protocol_t urlParseProtocol __P((char *));
extern method_t urlParseMethod __P((char *));
extern int urlDefaultPort __P((protocol_t));
extern void urlInitialize __P((void));
extern request_t *urlParse __P((method_t, char *));
extern char *urlCanonical __P((request_t *, char *));
extern request_t *requestLink __P((request_t *));
extern void requestUnlink __P((request_t *));
extern int matchDomainName __P((char *d, char *h));
extern int urlCheckRequest __P((request_t *));

/* bitfields for the flags member */
#define		REQ_UNUSED1	0x01
#define		REQ_NOCACHE	0x02
#define		REQ_IMS		0x04
#define		REQ_AUTH	0x08
#define		REQ_CACHABLE	0x10
#define 	REQ_UNUSED2	0x20
#define 	REQ_HIERARCHICAL 0x40
#define 	REQ_LOOPDETECT  0x80

#endif /* _URL_HEADER_ */
