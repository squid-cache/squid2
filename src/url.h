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

typedef enum {
    METHOD_NONE,		/* 000 */
    METHOD_GET,			/* 001 */
    METHOD_POST,		/* 010 */
    METHOD_PUT,			/* 011 */
    METHOD_HEAD,		/* 100 */
    METHOD_CONNECT,		/* 101 */
} method_t;

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
};

extern char *url_convert_hex _PARAMS((char *org_url, int allocate));
extern char *url_escape _PARAMS((char *url));
extern protocol_t urlParseProtocol _PARAMS((char *));
extern method_t urlParseMethod _PARAMS((char *));
extern int urlDefaultPort _PARAMS((protocol_t));
extern void urlInitialize _PARAMS((void));
extern request_t *urlParse _PARAMS((method_t, char *));
extern char *urlCanonical _PARAMS((request_t *, char *));
extern request_t *requestLink _PARAMS((request_t *));
extern void requestUnlink _PARAMS((request_t *));
extern int matchDomainName _PARAMS((char *d, char *h));
extern int urlCheckRequest _PARAMS((request_t *));

#endif /* _URL_HEADER_ */
