/*  $Id$ */

#ifndef _URL_HEADER_
#define _URL_HEADER_

#define MAX_URL  4096

typedef enum {
    METHOD_NONE,
    METHOD_GET,
    METHOD_POST,
    METHOD_HEAD,
    METHOD_CONNECT
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

typedef struct _request {
    method_t method;
    protocol_t protocol;
    char host[SQUIDHOSTNAMELEN + 1];
    int port;
    char urlpath[MAX_URL + 1];
} request_t;

extern char *url_convert_hex _PARAMS((char *org_url, int allocate));
extern char *url_escape _PARAMS((char *url));
extern protocol_t urlParseProtocol _PARAMS((char *));
extern method_t urlParseMethod _PARAMS((char *));
extern int urlDefaultPort _PARAMS((protocol_t));
extern void urlInitialize _PARAMS((void));
extern request_t *urlParse _PARAMS((method_t, char *));
extern char *urlCanonical _PARAMS((request_t *, char *));

#endif /* _URL_HEADER_ */
