
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
    request_t *proxy_request;
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
    int ip_lookup_pending;
} PassStateData;

static PF passTimeout;
static void passReadServer _PARAMS((int fd, void *));
static void passReadClient _PARAMS((int fd, void *));
static void passWriteServer _PARAMS((int fd, void *));
static void passWriteClient _PARAMS((int fd, void *));
static void passConnected _PARAMS((int fd, void *));
static IPH passConnect;
static void passErrorComplete _PARAMS((int, char *, int, int, void *));
static void passClose _PARAMS((PassStateData * passState));
static void passClientClosed _PARAMS((int fd, void *));
static void passConnectDone _PARAMS((int fd, int status, void *data));
static void passStateFree _PARAMS((int fd, void *data));
static void passPeerSelectComplete _PARAMS((peer * p, void *data));
static void passPeerSelectFail _PARAMS((peer * p, void *data));

static void
passClose(PassStateData * passState)
{
    if (passState->client.fd > -1) {
	/* remove the "unexpected" client close handler */
	comm_remove_close_handler(passState->client.fd,
	    passClientClosed,
	    passState);
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
    if (passState->ip_lookup_pending)
	ipcacheUnregister(passState->host, passState);
    if (passState->client.fd > -1) {
	commSetSelect(passState->client.fd,
	    COMM_SELECT_READ,
	    NULL,
	    NULL, 0);
    }
    safe_free(passState->server.buf);
    safe_free(passState->client.buf);
    xfree(passState->url);
    requestUnlink(passState->request);
    requestUnlink(passState->proxy_request);
    safe_free(passState);
}

/* This will be called when the server lifetime is expired. */
static void
passTimeout(int fd, void *data)
{
    PassStateData *passState = data;
    debug(39, 3, "passTimeout: FD %d\n", fd);
    passClose(passState);
}

/* Read from server side and queue it for writing to the client */
static void
passReadServer(int fd, void *data)
{
    PassStateData *passState = data;
    int len;
    len = read(passState->server.fd, passState->server.buf, SQUID_TCP_SO_RCVBUF);
    fd_bytes(passState->server.fd, len, FD_READ);
    debug(39, 5, "passReadServer FD %d, read %d bytes\n", fd, len);
    if (len < 0) {
	debug(50, 2, "passReadServer: FD %d: read failure: %s\n",
	    passState->server.fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(passState->server.fd,
		COMM_SELECT_READ,
		passReadServer,
		passState, 0);
	} else {
	    passClose(passState);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	passClose(passState);
    } else {
	passState->server.offset = 0;
	passState->server.len = len;
	commSetTimeout(passState->server.fd, Config.Timeout.read, NULL, NULL);
	commSetSelect(passState->client.fd,
	    COMM_SELECT_WRITE,
	    passWriteClient,
	    passState, 0);
    }
}

/* Read from client side and queue it for writing to the server */
static void
passReadClient(int fd, void *data)
{
    PassStateData *passState = data;
    int len;
    len = read(passState->client.fd, passState->client.buf, SQUID_TCP_SO_RCVBUF);
    fd_bytes(passState->client.fd, len, FD_READ);
    debug(39, 5, "passReadClient FD %d, read %d bytes\n",
	passState->client.fd, len);
    if (len < 0) {
	debug(50, 2, "passReadClient: FD %d: read failure: %s\n",
	    fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(passState->client.fd,
		COMM_SELECT_READ,
		passReadClient,
		passState, 0);
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
	    passState, 0);
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
    fd_bytes(fd, len, FD_WRITE);
    debug(39, 5, "passWriteServer FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(passState->server.fd,
		COMM_SELECT_WRITE,
		passWriteServer,
		passState, 0);
	    return;
	}
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
	    passState, 0);
    } else {
	/* still have more to write */
	commSetSelect(passState->server.fd,
	    COMM_SELECT_WRITE,
	    passWriteServer,
	    passState, 0);
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
    fd_bytes(fd, len, FD_WRITE);
    debug(39, 5, "passWriteClient FD %d, wrote %d bytes\n", fd, len);
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(passState->client.fd,
		COMM_SELECT_WRITE,
		passWriteClient,
		passState, 0);
	    return;
	}
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
	    passState, 0);
    } else {
	/* still have more to write */
	commSetSelect(passState->client.fd,
	    COMM_SELECT_WRITE,
	    passWriteClient,
	    passState, 0);
    }
}

static void
passConnected(int fd, void *data)
{
    PassStateData *passState = data;
    request_t *request = passState->request;
    size_t hdr_len = 0;
    debug(39, 3, "passConnected: FD %d passState=%p\n", fd, passState);
    if (passState->proxying) {
	request = get_free_request_t();
	passState->proxy_request = requestLink(request);
	request->method = passState->request->method;
	xstrncpy(request->urlpath, passState->url, MAX_URL);
    }
    passState->client.len = httpBuildRequestHeader(request,
	passState->request,	/* orig_request */
	NULL,			/* entry */
	passState->buf,
	&hdr_len,
	passState->client.buf,
	SQUID_TCP_SO_RCVBUF >> 1,
	opt_forwarded_for ? passState->client.fd : -1);
    debug(39, 3, "passConnected: Appending %d bytes of content\n",
	passState->buflen - hdr_len);
    xmemcpy(passState->client.buf + passState->client.len,
	passState->buf + hdr_len,
	passState->buflen - hdr_len);
    passState->client.len += passState->buflen - hdr_len;
    passState->client.offset = 0;
    commSetTimeout(passState->server.fd, Config.Timeout.read, NULL, NULL);
    commSetSelect(passState->server.fd,
	COMM_SELECT_WRITE,
	passWriteServer,
	passState, 0);
    commSetSelect(passState->server.fd,
	COMM_SELECT_READ,
	passReadServer,
	passState, 0);
}

static void
passErrorComplete(int fd, char *buf, int size, int errflag, void *passState)
{
    safe_free(buf);
    if (passState == NULL) {
	debug_trap("passErrorComplete: NULL passState\n");
	return;
    }
    passClose(passState);
}

static void
passConnect(int fd, const ipcache_addrs * ia, void *data)
{
    PassStateData *passState = data;
    request_t *request = passState->request;
    char *buf = NULL;
    passState->ip_lookup_pending = 0;
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
	    passErrorComplete,
	    passState,
	    xfree);
	return;
    }
    debug(39, 5, "passConnect: client=%d server=%d\n",
	passState->client.fd,
	passState->server.fd);
    /* Install lifetime handler */
    commSetTimeout(passState->server.fd,
	Config.Timeout.read,
	passTimeout,
	passState);
    commConnectStart(fd,
	passState->host,
	passState->port,
	passConnectDone,
	passState);
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
	    passErrorComplete,
	    passState,
	    xfree);
	return;
    }
    if (opt_no_ipcache)
	ipcacheInvalidate(passState->host);
    passConnected(passState->server.fd, passState);
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
	comm_write(fd,
	    xstrdup(msg),
	    strlen(msg),
	    NULL,
	    NULL,
	    xfree);
	return COMM_ERROR;
    }
    passState = xcalloc(1, sizeof(PassStateData));
    passState->url = xstrdup(url);
    passState->request = requestLink(request);
    passState->buf = buf;
    passState->buflen = buflen;
    passState->timeout = Config.Timeout.read;
    passState->host = request->host;
    passState->port = request->port;
    passState->size_ptr = size_ptr;
    passState->client.fd = fd;
    passState->server.fd = sock;
    passState->server.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    passState->client.buf = xmalloc(SQUID_TCP_SO_RCVBUF);
    comm_add_close_handler(passState->server.fd,
	passStateFree,
	passState);
    comm_add_close_handler(passState->client.fd,
	passClientClosed,
	passState);
    /* disable icpDetectClientClose */
    commSetSelect(passState->client.fd,
	COMM_SELECT_READ,
	NULL,
	NULL, 0);
    peerSelect(request,
	NULL,
	passPeerSelectComplete,
	passPeerSelectFail,
	passState);
    return COMM_OK;
}

static void
passPeerSelectComplete(peer * p, void *data)
{
    PassStateData *passState = data;
    request_t *request = passState->request;
    peer *g = NULL;
    passState->proxying = p ? 1 : 0;
    passState->host = p ? p->host : request->host;
    if (p == NULL) {
	passState->port = request->port;
    } else if (p->http_port != 0) {
	passState->port = p->http_port;
    } else if ((g = neighborFindByName(p->host))) {
	passState->port = g->http_port;
    } else {
	passState->port = CACHE_HTTP_PORT;
    }
    passState->ip_lookup_pending = 1;
    ipcache_nbgethostbyname(passState->host,
	passState->server.fd,
	passConnect,
	passState);
}

static void
passPeerSelectFail(peer * p, void *data)
{
    PassStateData *passState = data;
    squid_error_request(passState->url, ERR_CANNOT_FETCH, 400);
    passClose(passState);
}
