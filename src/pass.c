
/*
 * $Id$
 *
 * DEBUG: section 39    HTTP Passthrough
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
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

#include "squid.h"

typedef struct {
    char *url;
    char *host;			/* either request->host or proxy host */
    u_short port;
    request_t *request;
    char *buf;			/* stuff already read from client */
    int buflen;
    struct {
	int fd;
	int len;
	int offset;
	char *buf;
    } client, server;
    time_t timeout;
    int *size_ptr;		/* pointer to size for logging */
    int proxying;
    ConnectStateData connectState;
} PassStateData;

static void passLifetimeExpire _PARAMS((int fd, void *));
static void passReadTimeout _PARAMS((int fd, void *));
static void passReadServer _PARAMS((int fd, void *));
static void passReadClient _PARAMS((int fd, void *));
static void passWriteServer _PARAMS((int fd, void *));
static void passWriteClient _PARAMS((int fd, void *));
static void passConnected _PARAMS((int fd, void *));
static void passConnect _PARAMS((int fd, const ipcache_addrs *, void *));
static void passErrorComplete _PARAMS((int, char *, int, int, void *));
static void passClose _PARAMS((PassStateData * passState));
static void passClientClosed _PARAMS((int fd, void *));
static void passConnectDone _PARAMS((int fd, int status, void *data));
static void passStateFree _PARAMS((int fd, void *data));
static void passSelectNeighbor _PARAMS((int, const ipcache_addrs *, void *));
static int passParseHeaders _PARAMS((PassStateData * passState));

static char crlf[] = "\r\n";

static void
passClose(PassStateData * passState)
{
    if (passState->client.fd > -1) {
	/* remove the "unexpected" client close handler */
	comm_remove_close_handler(passState->client.fd,
	    passClientClosed,
	    (void *) passState);
	comm_close(passState->client.fd);
	passState->client.fd = -1;
    }
    if (passState->server.fd > -1) {
	comm_close(passState->server.fd);
    }
}

/* This is called only if the client connect closes unexpectedly,
 * ie from icpDetectClientClose() */
static void
passClientClosed(int fd, void *data)
{
    PassStateData *passState = data;
    debug(39, 3, "passClientClosed: FD %d\n", fd);
    /* we have been called from comm_close for the client side, so
     * just need to clean up the server side */
    protoUnregister(passState->server.fd,
	NULL,
	passState->request,
	no_addr);
    comm_close(passState->server.fd);
}

static void
passStateFree(int fd, void *data)
{
    PassStateData *passState = data;
    debug(39, 3, "passStateFree: FD %d, passState=%p\n", fd, passState);
    if (passState == NULL)
	return;
    if (fd != passState->server.fd)
	fatal_dump("passStateFree: FD mismatch!\n");
    commSetSelect(passState->client.fd,
	COMM_SELECT_READ,
	NULL,
	NULL, 0);
    safe_free(passState->server.buf);
    safe_free(passState->client.buf);
    xfree(passState->url);
    requestUnlink(passState->request);
    memset(passState, '\0', sizeof(PassStateData));
    safe_free(passState);
}

/* This will be called when the server lifetime is expired. */
static void
passLifetimeExpire(int fd, void *data)
{
    PassStateData *passState = data;
    debug(39, 4, "passLifeTimeExpire: FD %d: URL '%s'>\n",
	fd, passState->url);
    passClose(passState);
}

/* Read from server side and queue it for writing to the client */
static void
passReadServer(int fd, void *data)
{
    PassStateData *passState = data;
    int len;
    len = read(passState->server.fd, passState->server.buf, SQUID_TCP_SO_RCVBUF);
    debug(39, 5, "passReadServer FD %d, read %d bytes\n", fd, len);
    if (len < 0) {
	debug(50, 1, "passReadServer: FD %d: read failure: %s\n",
	    passState->server.fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(passState->server.fd,
		COMM_SELECT_READ,
		passReadServer,
		(void *) passState, 0);
	    commSetSelect(passState->server.fd,
		COMM_SELECT_TIMEOUT,
		passReadTimeout,
		(void *) passState,
		passState->timeout);
	} else {
	    passClose(passState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	passClose(passState);
    } else {
	passState->server.offset = 0;
	passState->server.len = len;
	commSetSelect(passState->client.fd,
	    COMM_SELECT_WRITE,
	    passWriteClient,
	    (void *) passState, 0);
    }
}

/* Read from client side and queue it for writing to the server */
static void
passReadClient(int fd, void *data)
{
    PassStateData *passState = data;
    int len;
    len = read(passState->client.fd, passState->client.buf, SQUID_TCP_SO_RCVBUF);
    debug(39, 5, "passReadClient FD %d, read %d bytes\n",
	passState->client.fd, len);
    if (len < 0) {
	debug(50, 1, "passReadClient: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(passState->client.fd,
		COMM_SELECT_READ,
		passReadClient,
		(void *) passState, 0);
	} else {
	    passClose(passState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	passClose(passState);
    } else {
	passState->client.offset = 0;
	passState->client.len = len;
	commSetSelect(passState->server.fd,
	    COMM_SELECT_WRITE,
	    passWriteServer,
	    (void *) passState, 0);
    }
}

/* Writes data from the client buffer to the server side */
static void
passWriteServer(int fd, void *data)
{
    PassStateData *passState = data;
    int len;
    len = write(passState->server.fd,
	passState->client.buf + passState->client.offset,
	passState->client.len - passState->client.offset);
    debug(39, 5, "passWriteServer FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	debug(50, 2, "passWriteServer: FD %d: write failure: %s.\n",
	    passState->server.fd, xstrerror());
	passClose(passState);
	return;
    }
    if ((passState->client.offset += len) >= passState->client.len) {
	/* Done writing, read more */
	commSetSelect(passState->client.fd,
	    COMM_SELECT_READ,
	    passReadClient,
	    (void *) passState, 0);
	commSetSelect(passState->server.fd,
	    COMM_SELECT_TIMEOUT,
	    passReadTimeout,
	    (void *) passState,
	    passState->timeout);
    } else {
	/* still have more to write */
	commSetSelect(passState->server.fd,
	    COMM_SELECT_WRITE,
	    passWriteServer,
	    (void *) passState, 0);
    }
}

/* Writes data from the server buffer to the client side */
static void
passWriteClient(int fd, void *data)
{
    PassStateData *passState = data;
    int len;
    debug(39, 5, "passWriteClient FD %d len=%d offset=%d\n",
	fd,
	passState->server.len,
	passState->server.offset);
    len = write(passState->client.fd,
	passState->server.buf + passState->server.offset,
	passState->server.len - passState->server.offset);
    debug(39, 5, "passWriteClient FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	debug(50, 2, "passWriteClient: FD %d: write failure: %s.\n",
	    passState->client.fd, xstrerror());
	passClose(passState);
	return;
    }
    if (passState->size_ptr)
	*passState->size_ptr += len;	/* increment total object size */
    if ((passState->server.offset += len) >= passState->server.len) {
	/* Done writing, read more */
	commSetSelect(passState->server.fd,
	    COMM_SELECT_READ,
	    passReadServer,
	    (void *) passState, 0);
    } else {
	/* still have more to write */
	commSetSelect(passState->client.fd,
	    COMM_SELECT_WRITE,
	    passWriteClient,
	    (void *) passState, 0);
    }
}

static void
passReadTimeout(int fd, void *data)
{
    PassStateData *passState = data;
    debug(39, 3, "passReadTimeout: FD %d\n", fd);
    passClose(passState);
}

static int
passParseHeaders(PassStateData * passState)
{
    char *ybuf = NULL;
    char *xbuf = NULL;
    char *viabuf = NULL;
    char *t = NULL;
    char *s = NULL;
    char *end;
    int l;
    int hdr_len = 0;
    int saw_host = 0;
    int content_length = 0;
    int buflen = SQUID_TCP_SO_RCVBUF >> 1;
    if ((end = mime_headers_end(passState->buf)) == NULL)
	return 0;
    xbuf = get_free_4k_page();
    for (t = passState->buf; t < end; t += strcspn(t, crlf), t += strspn(t, crlf)) {
	hdr_len = t - passState->buf;
	if (passState->buflen - hdr_len <= content_length)
	    break;
	if (strncasecmp(t, "Proxy-Connection:", 17) == 0)
	    continue;
	if (strncasecmp(t, "Connection:", 11) == 0)
	    continue;
	if (strncasecmp(t, "Host:", 5) == 0)
	    saw_host = 1;
	if (strncasecmp(t, "Content-length:", 15) == 0) {
	    for (s = t + 15; *s && isspace(*s); s++);
	    content_length = atoi(s);
	}
	if (strncasecmp(t, "Via:", 4) == 0) {
	    viabuf = get_free_4k_page();
	    xstrncpy(viabuf, t, 4096);
	    strcat(viabuf, ", ");
	    continue;
	}
	l = strcspn(t, crlf) + 1;
	if (l > 4096)
	    l = 4096;
	xstrncpy(xbuf, t, l);
	l = strlen(xbuf);
	if (passState->client.len + l > buflen)
	    break;		/* out of room */
	debug(39, 3, "passConnected: Appending Header: '%s'\n", xbuf);
	strcat(passState->client.buf + passState->client.len, xbuf);
	strcat(passState->client.buf + passState->client.len, crlf);
	passState->client.len += (l + 2);
    }
    hdr_len = t - passState->buf;
    /* Add Via: header */
    if (viabuf == NULL) {
	viabuf = get_free_4k_page();
	strcpy(viabuf, "Via: ");
    }
    ybuf = get_free_4k_page();
    sprintf(ybuf, "%3.1f %s:%d (Squid/%s)\r\n",
	passState->request->http_ver,
	getMyHostname(),
	(int) Config.Port.http,
	SQUID_VERSION);
    strcat(viabuf, ybuf);
    strcat(passState->client.buf + passState->client.len, viabuf);
    passState->client.len += strlen(viabuf);
    put_free_4k_page(viabuf);
    put_free_4k_page(ybuf);
    viabuf = ybuf = NULL;
    if (!saw_host) {
	ybuf = get_free_4k_page();
	sprintf(ybuf, "Host: %s\r\n", passState->request->host);
	strcat(passState->client.buf + passState->client.len, ybuf);
	passState->client.len += strlen(ybuf);
	put_free_4k_page(ybuf);
    }
    strcat(passState->client.buf + passState->client.len, crlf);
    passState->client.len += 2;
    return hdr_len;
}

static void
passConnected(int fd, void *data)
{
    PassStateData *passState = data;
    int hdr_len = 0;
    debug(39, 3, "passConnected: FD %d passState=%p\n", fd, passState);
    if (passState->proxying) {
	sprintf(passState->client.buf, "%s %s HTTP/1.0\r\n",
	    RequestMethodStr[passState->request->method],
	    passState->url);
    } else {
	sprintf(passState->client.buf, "%s %s HTTP/1.0\r\n",
	    RequestMethodStr[passState->request->method],
	    passState->request->urlpath);
    }
    passState->client.len = strlen(passState->client.buf);
    hdr_len = passParseHeaders(passState);
    memcpy(passState->client.buf + passState->client.len,
	passState->buf + hdr_len,
	passState->buflen - hdr_len);
    passState->client.len += passState->buflen - hdr_len;
    passState->client.offset = 0;
    commSetSelect(passState->server.fd,
	COMM_SELECT_WRITE,
	passWriteServer,
	(void *) passState, 0);
    comm_set_fd_lifetime(fd, 86400);	/* extend lifetime */
    commSetSelect(passState->server.fd,
	COMM_SELECT_READ,
	passReadServer,
	(void *) passState, 0);
}

static void
passErrorComplete(int fd, char *buf, int size, int errflag, void *passState)
{
    safe_free(buf);
    passClose(passState);
}

static void
passConnect(int fd, const ipcache_addrs * ia, void *data)
{
    PassStateData *passState = data;
    request_t *request = passState->request;
    char *buf = NULL;
    if (ia == NULL) {
	debug(39, 4, "passConnect: Unknown host: %s\n", passState->host);
	buf = squid_error_url(passState->url,
	    request->method,
	    ERR_DNS_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    dns_error_message);
	comm_write(passState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    30,
	    passErrorComplete,
	    (void *) passState,
	    xfree);
	return;
    }
    debug(39, 5, "passConnect: client=%d server=%d\n",
	passState->client.fd,
	passState->server.fd);
    /* Install lifetime handler */
    commSetSelect(passState->server.fd,
	COMM_SELECT_LIFETIME,
	passLifetimeExpire,
	(void *) passState, 0);
    /* NOTE this changes the lifetime handler for the client side.
     * It used to be asciiConnLifetimeHandle, but it does funny things
     * like looking for read handlers and assuming it was still reading
     * the HTTP request.  sigh... */
    commSetSelect(passState->client.fd,
	COMM_SELECT_LIFETIME,
	passLifetimeExpire,
	(void *) passState, 0);
    passState->connectState.fd = fd;
    passState->connectState.host = passState->host;
    passState->connectState.port = passState->port;
    passState->connectState.handler = passConnectDone;
    passState->connectState.data = passState;
    comm_nbconnect(fd, &passState->connectState);
}

static void
passConnectDone(int fd, int status, void *data)
{
    PassStateData *passState = data;
    char *buf = NULL;
    if (status == COMM_ERROR) {
	buf = squid_error_url(passState->url,
	    passState->request->method,
	    ERR_CONNECT_FAIL,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	comm_write(passState->client.fd,
	    xstrdup(buf),
	    strlen(buf),
	    30,
	    passErrorComplete,
	    (void *) passState,
	    xfree);
	return;
    }
    if (opt_no_ipcache)
	ipcacheInvalidate(passState->host);
    passConnected(passState->server.fd, passState);
    if (Config.vizHackAddr.sin_port)
	vizHackSendPkt(&passState->connectState.S, 2);
}

int
passStart(int fd,
    const char *url,
    request_t * request,
    char *buf,
    int buflen,
    int *size_ptr)
{
    /* Create state structure. */
    PassStateData *passState = NULL;
    int sock;
    char *msg = NULL;

    debug(39, 3, "passStart: '%s %s'\n",
	RequestMethodStr[request->method], url);

    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(39, 4, "passStart: Failed because we're out of sockets.\n");
	msg = squid_error_url(url,
	    request->method,
	    ERR_NO_FDS,
	    fd_table[fd].ipaddr,
	    500,
	    xstrerror());
	comm_write(passState->client.fd,
	    xstrdup(msg),
	    strlen(msg),
	    30,
	    passErrorComplete,
	    (void *) passState,
	    xfree);
	return COMM_ERROR;
    }
    passState = xcalloc(1, sizeof(PassStateData));
    passState->url = xstrdup(url);
    passState->request = requestLink(request);
    passState->buf = buf;
    passState->buflen = buflen;
    passState->timeout = Config.readTimeout;
    passState->host = request->host;
    passState->port = request->port;
    passState->size_ptr = size_ptr;
    passState->client.fd = fd;
    passState->server.fd = sock;
    passState->server.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    passState->client.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    comm_add_close_handler(passState->server.fd,
	passStateFree,
	(void *) passState);
    comm_add_close_handler(passState->client.fd,
	passClientClosed,
	(void *) passState);
    /* disable icpDetectClientClose */
    commSetSelect(passState->client.fd,
	COMM_SELECT_READ,
	NULL,
	NULL, 0);
    if (Config.firewall_ip_list) {
	/* must look up IP address */
	ipcache_nbgethostbyname(passState->host,
	    passState->server.fd,
	    passSelectNeighbor,
	    passState);
    } else {
	/* can decide now */
	passSelectNeighbor(passState->server.fd,
	    NULL,
	    (void *) passState);
    }
    return COMM_OK;
}

static void
passSelectNeighbor(int u1, const ipcache_addrs * ia, void *data)
{
    PassStateData *passState = data;
    request_t *request = passState->request;
    edge *e = NULL;
    int fw_ip_match = IP_ALLOW;
    if (ia && Config.firewall_ip_list)
	fw_ip_match = ip_access_check(ia->in_addrs[ia->cur], Config.firewall_ip_list);
    if ((e = Config.passProxy)) {
	hierarchyNote(request, HIER_PASS_PARENT, 0, e->host);
    } else if (matchInsideFirewall(request->host)) {
	hierarchyNote(request, HIER_DIRECT, 0, request->host);
    } else if (fw_ip_match == IP_DENY) {
	hierarchyNote(request, HIER_DIRECT, 0, request->host);
    } else if ((e = getDefaultParent(request))) {
	hierarchyNote(request, HIER_DEFAULT_PARENT, 0, e->host);
    } else if ((e = getSingleParent(request))) {
	hierarchyNote(request, HIER_SINGLE_PARENT, 0, e->host);
    } else if ((e = getFirstUpParent(request))) {
	hierarchyNote(request, HIER_FIRSTUP_PARENT, 0, e->host);
    }
    passState->proxying = e ? 1 : 0;
    passState->host = e ? e->host : request->host;
    passState->port = e ? e->http_port : request->port;
    ipcache_nbgethostbyname(passState->host,
	passState->server.fd,
	passConnect,
	passState);
}
