
/*
 * $Id$
 *
 * DEBUG: section 12    Client Handling
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

const char *log_tags[] =
{
    "NONE",
    "TCP_HIT",
    "TCP_MISS",
    "TCP_REFRESH_HIT",
    "TCP_REF_FAIL_HIT",
    "TCP_REFRESH_MISS",
    "TCP_CLIENT_REFRESH",
    "TCP_IMS_HIT",
    "TCP_IMS_MISS",
    "TCP_SWAPFAIL_MISS",
    "TCP_NEGATIVE_HIT",
    "TCP_MEM_HIT",
    "UDP_HIT",
    "UDP_HIT_OBJ",
    "UDP_MISS",
    "UDP_DENIED",
    "UDP_INVALID",
    "UDP_MISS_NOFETCH",
    "LOG_TYPE_MAX"
};

static icpUdpData *UdpQueueHead = NULL;
static icpUdpData *UdpQueueTail = NULL;
static const char *const crlf = "\r\n";

#define REQUEST_BUF_SIZE 4096

/* Local functions */

static CWCB icpHandleIMSComplete;
static PF clientReadRequest;
static PF connStateFree;
static PF requestTimeout;
static STCB icpGetHeadersForIMS;
static char *icpConstruct304reply(struct _http_reply *);
static int CheckQuickAbort2(const clientHttpRequest *);
static int icpCheckTransferDone(clientHttpRequest *);
static int icpCheckUdpHit(StoreEntry *, request_t * request);
#if USE_ICP_HIT_OBJ
static int icpCheckUdpHitObj(StoreEntry * e, request_t * r, icp_common_t * h, int len);
static void *icpCreateHitObjMessage(icp_opcode, int, const char *, int, int, StoreEntry *);
#endif
static void CheckQuickAbort(clientHttpRequest *);
static void checkFailureRatio(log_type, hier_code);
static void icpHandleIcpV2(int, struct sockaddr_in, char *, int);
static void icpHandleIcpV3(int, struct sockaddr_in, char *, int);
static void icpLogIcp(icpUdpData *);
static void icpProcessMISS(int, clientHttpRequest *);
static void clientAppendReplyHeader(char *, const char *, size_t *, size_t);
size_t clientBuildReplyHeader(clientHttpRequest *, char *, size_t *, char *, size_t);
static clientHttpRequest *parseHttpRequest(ConnStateData *, method_t *, int *, char **, size_t *);

/*
 * This function is designed to serve a fairly specific purpose.
 * Occasionally our vBNS-connected caches can talk to each other, but not
 * the rest of the world.  Here we try to detect frequent failures which
 * make the cache unusable (e.g. DNS lookup and connect() failures).  If
 * the failure:success ratio goes above 1.0 then we go into "hit only"
 * mode where we only return UDP_HIT or UDP_MISS_NOFETCH.  Neighbors
 * will only fetch HITs from us if they are using the ICP protocol.  We
 * stay in this mode for 5 minutes.
 * 
 * Duane W., Sept 16, 1996
 */

#define FAILURE_MODE_TIME 300
static time_t hit_only_mode_until = 0;

static void
checkFailureRatio(log_type rcode, hier_code hcode)
{
    static double fail_ratio = 0.0;
    static double magic_factor = 100;
    double n_good;
    double n_bad;

    if (hcode == HIER_NONE)
	return;
    n_good = magic_factor / (1.0 + fail_ratio);
    n_bad = magic_factor - n_good;
    switch (rcode) {
    case ERR_DNS_FAIL:
    case ERR_CONNECT_FAIL:
    case ERR_READ_ERROR:
	n_bad++;
	break;
    default:
	n_good++;
    }
    fail_ratio = n_bad / n_good;
    if (hit_only_mode_until > squid_curtime)
	return;
    if (fail_ratio < 1.0)
	return;
    debug(12, 0) ("Failure Ratio at %4.2f\n", fail_ratio);
    debug(12, 0) ("Going into hit-only-mode for %d minutes...\n",
	FAILURE_MODE_TIME / 60);
    hit_only_mode_until = squid_curtime + FAILURE_MODE_TIME;
    fail_ratio = 0.8;		/* reset to something less than 1.0 */
}

static void
httpRequestFree(void *data)
{
    clientHttpRequest *http = data;
    clientHttpRequest **H;
    ConnStateData *conn = http->conn;
    StoreEntry *entry = http->entry;
    request_t *request = http->request;
    MemObject *mem = NULL;
    debug(12, 3) ("httpRequestFree: %s\n", entry ? entry->url : "no store entry");
    if (!icpCheckTransferDone(http)) {
	if (entry)
	    storeUnregister(entry, http);	/* unregister BEFORE abort */
	CheckQuickAbort(http);
	entry = http->entry;	/* reset, IMS might have changed it */
	if (entry && entry->ping_status == PING_WAITING)
	    storeReleaseRequest(entry);
	protoUnregister(entry, request, conn->peer.sin_addr);
    }
    assert(http->log_type < LOG_TYPE_MAX);
    if (entry)
	mem = entry->mem_obj;
    if (http->out.size || http->log_type) {
	http->al.icp.opcode = 0;
	http->al.url = http->url;
	if (mem) {
	    http->al.http.code = mem->reply->code;
	    http->al.http.content_type = mem->reply->content_type;
	}
	http->al.cache.caddr = conn->log_addr;
	http->al.cache.size = http->out.size;
	http->al.cache.code = http->log_type;
	http->al.cache.msec = tvSubMsec(http->start, current_time);
	http->al.cache.ident = conn->ident.ident;
	if (request) {
	    http->al.http.method = request->method;
	    http->al.headers.request = request->headers;
	    http->al.hier = request->hier;
	}
	accessLogLog(&http->al);
	HTTPCacheInfo->proto_count(HTTPCacheInfo,
	    request ? request->protocol : PROTO_NONE,
	    http->log_type);
	clientdbUpdate(conn->peer.sin_addr, http->log_type, PROTO_HTTP);
    }
    if (http->redirect_state == REDIRECT_PENDING)
	redirectUnregister(http->url, http);
    if (http->acl_checklist)
	aclChecklistFree(http->acl_checklist);
    checkFailureRatio(http->log_type, http->al.hier.code);
    safe_free(http->url);
    safe_free(http->log_url);
    safe_free(http->al.headers.reply);
    if (entry) {
	storeUnregister(entry, http);
	storeUnlockObject(entry);
	http->entry = NULL;
    }
    /* old_entry might still be set if we didn't yet get the reply
     * code in icpHandleIMSReply() */
    if (http->old_entry) {
	storeUnregister(http->old_entry, http);
	storeUnlockObject(http->old_entry);
	http->old_entry = NULL;
    }
    requestUnlink(http->request);
    assert(http != http->next);
    assert(http->conn->chr != NULL);
    H = &http->conn->chr;
    while (*H) {
	if (*H == http)
	    break;
	H = &(*H)->next;
    }
    assert(*H != NULL);
    *H = http->next;
    http->next = NULL;
    cbdataFree(http);
}

/* This is a handler normally called by comm_close() */
static void
connStateFree(int fd, void *data)
{
    ConnStateData *connState = data;
    clientHttpRequest *http;
    debug(12, 3) ("connStateFree: FD %d\n", fd);
    assert(connState != NULL);
    while ((http = connState->chr)) {
	assert(http->conn == connState);
	assert(connState->chr != connState->chr->next);
	httpRequestFree(http);
    }
    if (connState->ident.fd > -1)
	comm_close(connState->ident.fd);
    safe_free(connState->in.buf);
    meta_data.misc -= connState->in.size;
    pconnHistCount(0, connState->nrequests);
    cbdataFree(connState);
}

void
icpParseRequestHeaders(clientHttpRequest * http)
{
    request_t *request = http->request;
    char *request_hdr = request->headers;
    char *t = NULL;
    request->ims = -2;
    request->imslen = -1;
    if ((t = mime_get_header(request_hdr, "If-Modified-Since"))) {
	BIT_SET(request->flags, REQ_IMS);
	request->ims = parse_rfc1123(t);
	while ((t = strchr(t, ';'))) {
	    for (t++; isspace(*t); t++);
	    if (strncasecmp(t, "length=", 7) == 0)
		request->imslen = atoi(t + 7);
	}
    }
    if ((t = mime_get_header(request_hdr, "Pragma"))) {
	if (!strcasecmp(t, "no-cache"))
	    BIT_SET(request->flags, REQ_NOCACHE);
    }
    if (mime_get_header(request_hdr, "Range")) {
	BIT_SET(request->flags, REQ_NOCACHE);
	BIT_SET(request->flags, REQ_RANGE);
    } else if (mime_get_header(request_hdr, "Request-Range")) {
	BIT_SET(request->flags, REQ_NOCACHE);
	BIT_SET(request->flags, REQ_RANGE);
    }
    if (mime_get_header(request_hdr, "Authorization"))
	BIT_SET(request->flags, REQ_AUTH);
    if (request->login[0] != '\0')
	BIT_SET(request->flags, REQ_AUTH);
    if ((t = mime_get_header(request_hdr, "Proxy-Connection"))) {
	if (!strcasecmp(t, "Keep-Alive"))
	    BIT_SET(request->flags, REQ_PROXY_KEEPALIVE);
    }
    if ((t = mime_get_header(request_hdr, "Via")))
	if (strstr(t, ThisCache)) {
	    if (!http->accel) {
		debug(12, 1) ("WARNING: Forwarding loop detected for '%s'\n",
		    http->url);
		debug(12, 1) ("--> %s\n", t);
	    }
	    BIT_SET(request->flags, REQ_LOOPDETECT);
	}
#if USE_USERAGENT_LOG
    if ((t = mime_get_header(request_hdr, "User-Agent")))
	logUserAgent(fqdnFromAddr(http->conn->peer.sin_addr), t);
#endif
    request->max_age = -1;
    if ((t = mime_get_header(request_hdr, "Cache-control"))) {
	if (!strncasecmp(t, "Max-age=", 8))
	    request->max_age = atoi(t + 8);
    }
    if (request->method == METHOD_TRACE) {
	if ((t = mime_get_header(request_hdr, "Max-Forwards")))
	    request->max_forwards = atoi(t);
    }
}

static int
icpCachable(clientHttpRequest * http)
{
    const char *url = http->url;
    request_t *req = http->request;
    method_t method = req->method;
    const wordlist *p;
    for (p = Config.cache_stoplist; p; p = p->next) {
	if (strstr(url, p->key))
	    return 0;
    }
    if (Config.cache_stop_relist)
	if (aclMatchRegex(Config.cache_stop_relist, url))
	    return 0;
    if (req->protocol == PROTO_HTTP)
	return httpCachable(method);
    /* FTP is always cachable */
    if (req->protocol == PROTO_GOPHER)
	return gopherCachable(url);
    if (req->protocol == PROTO_WAIS)
	return 0;
    if (method == METHOD_CONNECT)
	return 0;
    if (method == METHOD_TRACE)
	return 0;
    if (req->protocol == PROTO_CACHEOBJ)
	return 0;
    return 1;
}

/* Return true if we can query our neighbors for this object */
static int
icpHierarchical(clientHttpRequest * http)
{
    const char *url = http->url;
    request_t *request = http->request;
    method_t method = request->method;
    const wordlist *p = NULL;

    /* IMS needs a private key, so we can use the hierarchy for IMS only
     * if our neighbors support private keys */
    if (BIT_TEST(request->flags, REQ_IMS) && !neighbors_do_private_keys)
	return 0;
    if (BIT_TEST(request->flags, REQ_AUTH))
	return 0;
    if (method == METHOD_TRACE)
	return 1;
    if (method != METHOD_GET)
	return 0;
    /* scan hierarchy_stoplist */
    for (p = Config.hierarchy_stoplist; p; p = p->next)
	if (strstr(url, p->key))
	    return 0;
    if (BIT_TEST(request->flags, REQ_LOOPDETECT))
	return 0;
    if (request->protocol == PROTO_HTTP)
	return httpCachable(method);
    if (request->protocol == PROTO_GOPHER)
	return gopherCachable(url);
    if (request->protocol == PROTO_WAIS)
	return 0;
    if (request->protocol == PROTO_CACHEOBJ)
	return 0;
    return 1;
}

void
icpErrorComplete(int fd, void *data, int size)
{
    clientHttpRequest *http = data;
    if (http)
	http->out.size += size;
    comm_close(fd);
}

int
isTcpHit(log_type code)
{
    /* this should be a bitmap for better optimization */
    if (code == LOG_TCP_HIT)
	return 1;
    if (code == LOG_TCP_IMS_HIT)
	return 1;
    if (code == LOG_TCP_REFRESH_FAIL_HIT)
	return 1;
    if (code == LOG_TCP_REFRESH_HIT)
	return 1;
    if (code == LOG_TCP_NEGATIVE_HIT)
	return 1;
    if (code == LOG_TCP_MEM_HIT)
	return 1;
    return 0;
}

static void
clientAppendReplyHeader(char *hdr, const char *line, size_t * sz, size_t max)
{
    size_t n = *sz + strlen(line) + 2;
    if (n >= max)
	return;
    strcpy(hdr + (*sz), line);
    strcat(hdr + (*sz), crlf);
    *sz = n;
}

size_t
clientBuildReplyHeader(clientHttpRequest * http,
    char *hdr_in,
    size_t * in_len,
    char *hdr_out,
    size_t out_sz)
{
    char *xbuf;
    char *ybuf;
    char *t = NULL;
    char *end = NULL;
    size_t len = 0;
    size_t hdr_len = 0;
    size_t l;
    end = mime_headers_end(hdr_in);
    if (end == NULL) {
	debug(12, 3) ("clientBuildReplyHeader: DIDN'T FIND END-OF-HEADERS\n");
	debug(12, 3) ("\n%s", hdr_in);
	return 0;
    }
    xbuf = get_free_4k_page();
    ybuf = get_free_4k_page();
    for (t = hdr_in; t < end; t += strcspn(t, crlf), t += strspn(t, crlf)) {
	hdr_len = t - hdr_in;
	l = strcspn(t, crlf) + 1;
	xstrncpy(xbuf, t, l > 4096 ? 4096 : l);
	debug(12, 5) ("clientBuildReplyHeader: %s\n", xbuf);
#if 0
	if (strncasecmp(xbuf, "Accept-Ranges:", 14) == 0)
	    continue;
	if (strncasecmp(xbuf, "Etag:", 5) == 0)
	    continue;
#endif
	if (strncasecmp(xbuf, "Proxy-Connection:", 17) == 0)
	    continue;
	if (strncasecmp(xbuf, "Connection:", 11) == 0)
	    continue;
	if (strncasecmp(xbuf, "Keep-Alive:", 11) == 0)
	    continue;
	if (strncasecmp(xbuf, "Set-Cookie:", 11) == 0)
	    if (isTcpHit(http->log_type))
		continue;
	clientAppendReplyHeader(hdr_out, xbuf, &len, out_sz - 512);
    }
    hdr_len = end - hdr_in;
    /* Append X-Cache: */
    snprintf(ybuf, 4096, "X-Cache: %s", isTcpHit(http->log_type) ? "HIT" : "MISS");
    clientAppendReplyHeader(hdr_out, ybuf, &len, out_sz);
    /* Append Proxy-Connection: */
    if (BIT_TEST(http->request->flags, REQ_PROXY_KEEPALIVE)) {
	snprintf(ybuf, 4096, "Proxy-Connection: Keep-Alive");
	clientAppendReplyHeader(hdr_out, ybuf, &len, out_sz);
    }
    clientAppendReplyHeader(hdr_out, null_string, &len, out_sz);
    if (in_len)
	*in_len = hdr_len;
    if ((l = strlen(hdr_out)) != len) {
	debug_trap("clientBuildReplyHeader: size mismatch");
	len = l;
    }
    debug(12, 3) ("clientBuildReplyHeader: OUTPUT:\n%s\n", hdr_out);
    put_free_4k_page(xbuf);
    put_free_4k_page(ybuf);
    return len;
}

void
clientCacheHit(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    if (size < 0) {
	/* swap in failure */
	http->log_type = LOG_TCP_SWAPFAIL_MISS;
	icpProcessMISS(http->conn->fd, http);
    } else {
	icpSendMoreData(data, buf, size);
    }
}

void
icpSendMoreData(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    ConnStateData *conn = http->conn;
    int fd = conn->fd;
    char *p = NULL;
    size_t hdrlen;
    size_t l = 0;
    size_t writelen;
    char *newbuf;
    FREE *freefunc = put_free_4k_page;
    int hack = 0;
    char C = '\0';
    assert(size <= SM_PAGE_SIZE);
    debug(12, 5) ("icpSendMoreData: FD %d '%s', out.offset=%d\n",
	fd, entry->url, http->out.offset);
    if (conn->chr != http) {
	/* there is another object in progress, defer this one */
	debug(0, 0) ("icpSendMoreData: Deferring delivery of\n");
	debug(0, 0) ("--> %s\n", entry->url);
	debug(0, 0) ("--> because other requests are in front\n");
	freefunc(buf);
	return;
    } else if (entry->store_status == STORE_ABORTED) {
	freefunc(buf);
	return;
    } else if (size < 0) {
	freefunc(buf);
	return;
    } else if (size == 0) {
	clientWriteComplete(fd, NULL, 0, DISK_OK, http);
	freefunc(buf);
	return;
    }
    writelen = size;
    if (http->out.offset == 0 && http->request->protocol != PROTO_CACHEOBJ) {
	if (Config.onoff.log_mime_hdrs) {
	    if ((p = mime_headers_end(buf))) {
		safe_free(http->al.headers.reply);
		http->al.headers.reply = xcalloc(1 + p - buf, 1);
		xstrncpy(http->al.headers.reply, buf, p - buf);
	    }
	}
	/* make sure 'buf' is null terminated somewhere */
	if (size == SM_PAGE_SIZE) {
	    hack = 1;
	    size--;
	    C = *(buf + size);
	}
	*(buf + size) = '\0';
	newbuf = get_free_8k_page();
	hdrlen = 0;
	l = clientBuildReplyHeader(http, buf, &hdrlen, newbuf, 8192);
	if (hack)
	    *(buf + size++) = C;
	if (l != 0) {
	    writelen = l + size - hdrlen;
	    assert(writelen <= 8192);
	    /*
	     * l is the length of the new headers in newbuf
	     * hdrlen is the length of the old headers in buf
	     * size - hdrlen is the amount of body in buf
	     */
	    debug(12, 3) ("icpSendMoreData: Appending %d bytes after headers\n",
		(int) (size - hdrlen));
	    xmemcpy(newbuf + l, buf + hdrlen, size - hdrlen);
	    /* replace buf with newbuf */
	    freefunc(buf);
	    buf = newbuf;
	    freefunc = put_free_8k_page;
	    newbuf = NULL;
	} else {
	    put_free_8k_page(newbuf);
	    newbuf = NULL;
	    if (size < SM_PAGE_SIZE && entry->store_status == STORE_PENDING) {
		/* wait for more to arrive */
		storeClientCopy(entry,
		    http->out.offset + size,
		    http->out.offset,
		    SM_PAGE_SIZE,
		    buf,
		    icpSendMoreData,
		    http);
		return;
	    }
	}
    }
    http->out.offset += size;
    if (http->request->method == METHOD_HEAD) {
	if ((p = mime_headers_end(buf))) {
	    *p = '\0';
	    writelen = p - buf;
	    /* force end */
	    http->out.offset = entry->mem_obj->inmem_hi;
	}
    }
    comm_write(fd, buf, writelen, clientWriteComplete, http, freefunc);
}

void
clientWriteComplete(int fd, char *buf, int size, int errflag, void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn;
    StoreEntry *entry = http->entry;
    http->out.size += size;
    debug(12, 5) ("clientWriteComplete: FD %d, sz %d, err %d, off %d, len %d\n",
	fd, size, errflag, http->out.offset, entry->object_len);
    if (errflag) {
	CheckQuickAbort(http);
	/* Log the number of bytes that we managed to read */
	HTTPCacheInfo->proto_touchobject(HTTPCacheInfo,
	    urlParseProtocol(entry->url),
	    http->out.size);
	comm_close(fd);
    } else if (entry->store_status == STORE_ABORTED) {
	HTTPCacheInfo->proto_touchobject(HTTPCacheInfo,
	    urlParseProtocol(entry->url),
	    http->out.size);
	comm_close(fd);
    } else if (icpCheckTransferDone(http) || size == 0) {
	debug(12, 5) ("clientWriteComplete: FD %d transfer is DONE\n", fd);
	/* We're finished case */
	HTTPCacheInfo->proto_touchobject(HTTPCacheInfo,
	    http->request->protocol,
	    http->out.size);
	if (http->entry->mem_obj->reply->content_length <= 0) {
	    comm_close(fd);
	} else if (BIT_TEST(http->request->flags, REQ_PROXY_KEEPALIVE)) {
	    debug(12, 5) ("clientWriteComplete: FD %d Keeping Alive\n", fd);
	    conn = http->conn;
	    httpRequestFree(http);
	    if ((http = conn->chr)) {
		debug(12, 1) ("clientWriteComplete: FD %d Sending next request\n", fd);
		storeClientCopy(entry,
		    http->out.offset,
		    http->out.offset,
		    SM_PAGE_SIZE,
		    get_free_4k_page(),
		    icpSendMoreData,
		    http);
	    } else {
		debug(12, 5) ("clientWriteComplete: FD %d Setting read handler for next request\n", fd);
		fd_note(fd, "Reading next request");
		commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
		commSetTimeout(fd, 15, requestTimeout, conn);
	    }
	} else {
	    comm_close(fd);
	}
    } else {
	/* More data will be coming from primary server; register with 
	 * storage manager. */
	storeClientCopy(entry,
	    http->out.offset,
	    http->out.offset,
	    SM_PAGE_SIZE,
	    get_free_4k_page(),
	    icpSendMoreData,
	    http);
    }
}

static void
icpGetHeadersForIMS(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    int fd = http->conn->fd;
    StoreEntry *entry = http->entry;
    MemObject *mem = entry->mem_obj;
    char *reply = NULL;
    assert(size > 0);
    assert(size <= SM_PAGE_SIZE);
    if (size < 0) {
	debug(12, 1) ("storeClientCopy returned %d for '%s'\n", size, entry->key);
	put_free_4k_page(buf);
	comm_close(fd);
	return;
    }
    if (mem->reply->code == 0) {
	if (entry->mem_status == IN_MEMORY) {
	    put_free_4k_page(buf);
	    icpProcessMISS(fd, http);
	    return;
	}
	/* All headers are not yet available, wait for more data */
	storeClientCopy(entry,
	    http->out.offset + size,
	    http->out.offset,
	    SM_PAGE_SIZE,
	    buf,
	    icpGetHeadersForIMS,
	    http);
	return;
    }
    /* All headers are available, check if object is modified or not */
    /* ---------------------------------------------------------------
     * Removed check for reply->code != 200 because of a potential
     * problem with ICP.  We will return a HIT for any public, cached
     * object.  This includes other responses like 301, 410, as coded in
     * http.c.  It is Bad(tm) to return UDP_HIT and then, if the reply
     * code is not 200, hand off to icpProcessMISS(), which may disallow
     * the request based on 'miss_access' rules.  Alternatively, we might
     * consider requiring returning UDP_HIT only for 200's.  This
     * problably means an entry->flag bit, which would be lost during
     * restart because the flags aren't preserved across restarts.
     * --DW 3/11/96.
     * ---------------------------------------------------------------- */
#ifdef CHECK_REPLY_CODE_NOTEQUAL_200
    /* Only objects with statuscode==200 can be "Not modified" */
    if (mem->reply->code != 200) {
	debug(12, 4) ("icpGetHeadersForIMS: Reply code %d!=200\n",
	    mem->reply->code);
	put_free_4k_page(buf);
	icpProcessMISS(fd, http);
	return;
    }
    +
#endif
	http->log_type = LOG_TCP_IMS_HIT;
    entry->refcount++;
    if (modifiedSince(entry, http->request)) {
	storeClientCopy(entry,
	    http->out.offset,
	    http->out.offset,
	    SM_PAGE_SIZE,
	    buf,
	    icpSendMoreData,
	    http);
	return;
    }
    debug(12, 4) ("icpGetHeadersForIMS: Not modified '%s'\n", entry->url);
    reply = icpConstruct304reply(mem->reply);
    comm_write(fd,
	xstrdup(reply),
	strlen(reply),
	icpHandleIMSComplete,
	http,
	xfree);
}

static void
icpHandleIMSComplete(int fd, char *buf_unused, int size, int errflag, void *data)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    debug(12, 5) ("icpHandleIMSComplete: Not Modified sent '%s'\n", entry->url);
    HTTPCacheInfo->proto_touchobject(HTTPCacheInfo,
	http->request->protocol,
	size);
    /* Set up everything for the logging */
    storeUnregister(entry, http);
    storeUnlockObject(entry);
    http->entry = NULL;
    http->out.size += size;
    http->al.http.code = 304;
    if (errflag != COMM_ERR_CLOSING)
	comm_close(fd);
}

/*
 * Below, we check whether the object is a hit or a miss.  If it's a hit,
 * we check whether the object is still valid or whether it is a MISS_TTL.
 */
void
icpProcessRequest(int fd, clientHttpRequest * http)
{
    char *url = http->url;
    const char *pubkey = NULL;
    StoreEntry *entry = NULL;
    request_t *request = http->request;
    char *reply;
    debug(12, 4) ("icpProcessRequest: %s '%s'\n",
	RequestMethodStr[http->request->method],
	url);
    if (http->request->method == METHOD_CONNECT) {
	http->log_type = LOG_TCP_MISS;
	sslStart(fd, url, http->request, &http->out.size);
	return;
    } else if (request->method == METHOD_PURGE) {
	clientPurgeRequest(http);
	return;
    } else if (request->method == METHOD_TRACE) {
	if (request->max_forwards == 0) {
	    reply = clientConstructTraceEcho(http);
	    comm_write(fd,
		xstrdup(reply),
		strlen(reply),
		clientWriteComplete,
		http,
		xfree);
	    return;
	}
	/* yes, continue */
    } else if (request->method != METHOD_GET) {
	http->log_type = LOG_TCP_MISS;
	passStart(fd, url, http->request, &http->out.size);
	return;
    }
    if (icpCachable(http))
	BIT_SET(request->flags, REQ_CACHABLE);
    if (icpHierarchical(http))
	BIT_SET(request->flags, REQ_HIERARCHICAL);
    debug(12, 5) ("icpProcessRequest: REQ_NOCACHE = %s\n",
	BIT_TEST(request->flags, REQ_NOCACHE) ? "SET" : "NOT SET");
    debug(12, 5) ("icpProcessRequest: REQ_CACHABLE = %s\n",
	BIT_TEST(request->flags, REQ_CACHABLE) ? "SET" : "NOT SET");
    debug(12, 5) ("icpProcessRequest: REQ_HIERARCHICAL = %s\n",
	BIT_TEST(request->flags, REQ_HIERARCHICAL) ? "SET" : "NOT SET");

    /* NOTE on HEAD requests: We currently don't cache HEAD reqeusts
     * at all, so look for the corresponding GET object, or just go
     * directly. The only way to get a TCP_HIT on a HEAD reqeust is
     * if someone already did a GET.  Maybe we should turn HEAD
     * misses into full GET's?  */
    if (http->request->method == METHOD_HEAD) {
	pubkey = storeGeneratePublicKey(http->url, METHOD_GET);
    } else
	pubkey = storeGeneratePublicKey(http->url, http->request->method);

    if ((entry = storeGet(pubkey)) == NULL) {
	/* this object isn't in the cache */
	http->log_type = LOG_TCP_MISS;
    } else if (BIT_TEST(entry->flag, ENTRY_SPECIAL)) {
	if (entry->mem_status == IN_MEMORY)
	    http->log_type = LOG_TCP_MEM_HIT;
	else
	    http->log_type = LOG_TCP_HIT;
    } else if (!storeEntryValidToSend(entry)) {
	http->log_type = LOG_TCP_MISS;
	storeRelease(entry);
	entry = NULL;
    } else if (BIT_TEST(request->flags, REQ_NOCACHE)) {
	/* NOCACHE should always eject a negative cached object */
	if (BIT_TEST(entry->flag, ENTRY_NEGCACHED))
	    storeRelease(entry);
	/* NOCACHE+IMS should not eject a valid object */
	else if (BIT_TEST(request->flags, REQ_IMS))
	    (void) 0;
	/* Request-Range should not eject a valid object */
	else if (BIT_TEST(request->flags, REQ_RANGE))
	    (void) 0;
	else
	    storeRelease(entry);
	ipcacheReleaseInvalid(http->request->host);
	entry = NULL;
	http->log_type = LOG_TCP_CLIENT_REFRESH;
    } else if (checkNegativeHit(entry)) {
	http->log_type = LOG_TCP_NEGATIVE_HIT;
    } else if (refreshCheck(entry, request, 0)) {
	/* The object is in the cache, but it needs to be validated.  Use
	 * LOG_TCP_REFRESH_MISS for the time being, maybe change it to
	 * _HIT later in icpHandleIMSReply() */
	if (request->protocol == PROTO_HTTP)
	    http->log_type = LOG_TCP_REFRESH_MISS;
	else
	    http->log_type = LOG_TCP_MISS;	/* XXX zoinks */
    } else if (BIT_TEST(request->flags, REQ_IMS)) {
	/* User-initiated IMS request for something we think is valid */
	http->log_type = LOG_TCP_IMS_MISS;
    } else {
	if (entry->mem_status == IN_MEMORY)
	    http->log_type = LOG_TCP_MEM_HIT;
	else
	    http->log_type = LOG_TCP_HIT;
    }
    debug(12, 4) ("icpProcessRequest: %s for '%s'\n",
	log_tags[http->log_type],
	http->url);
    if (entry) {
	storeLockObject(entry);
	storeClientListAdd(entry, http);
    }
    http->entry = entry;	/* Save a reference to the object */
    http->out.offset = 0;
    switch (http->log_type) {
    case LOG_TCP_HIT:
    case LOG_TCP_NEGATIVE_HIT:
    case LOG_TCP_MEM_HIT:
	entry->refcount++;	/* HIT CASE */
	storeClientCopy(entry,
	    http->out.offset,
	    http->out.offset,
	    SM_PAGE_SIZE,
	    get_free_4k_page(),
	    clientCacheHit,
	    http);
	break;
    case LOG_TCP_IMS_MISS:
	storeClientCopy(entry,
	    http->out.offset,
	    http->out.offset,
	    SM_PAGE_SIZE,
	    get_free_4k_page(),
	    icpGetHeadersForIMS,
	    http);
	break;
    case LOG_TCP_REFRESH_MISS:
	icpProcessExpired(fd, http);
	break;
    default:
	icpProcessMISS(fd, http);
	break;
    }
}

/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 */
static void
icpProcessMISS(int fd, clientHttpRequest * http)
{
    char *url = http->url;
    char *request_hdr = http->request->headers;
    StoreEntry *entry = NULL;
    aclCheck_t ch;
    int answer;
    ErrorState *err = NULL;
    debug(12, 4) ("icpProcessMISS: '%s %s'\n",
	RequestMethodStr[http->request->method], url);
    debug(12, 10) ("icpProcessMISS: request_hdr:\n%s\n", request_hdr);

    /* Check if this host is allowed to fetch MISSES from us */
    memset(&ch, '\0', sizeof(aclCheck_t));
    ch.src_addr = http->conn->peer.sin_addr;
    ch.request = http->request;
    answer = aclCheckFast(Config.accessList.miss, &ch);
    if (answer == 0) {
	http->al.http.code = HTTP_FORBIDDEN;
	err = errorCon(ERR_CANNOT_FORWARD, HTTP_FORBIDDEN);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	err->callback = icpErrorComplete;
	err->callback_data = http;
	errorSend(fd, err);
	return;
    }
    /* Get rid of any references to a StoreEntry (if any) */
    if (http->entry) {
	storeUnregister(http->entry, http);
	storeUnlockObject(http->entry);
	http->entry = NULL;
    }
    entry = storeCreateEntry(url,
	http->log_url,
	http->request->flags,
	http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    storeClientListAdd(entry, http);
    entry->mem_obj->fd = fd;
    entry->refcount++;		/* MISS CASE */
    http->entry = entry;
    http->out.offset = 0;
    /* Register with storage manager to receive updates when data comes in. */
    storeClientCopy(entry,
	http->out.offset,
	http->out.offset,
	SM_PAGE_SIZE,
	get_free_4k_page(),
	icpSendMoreData,
	http);
    /* protoDispatch() needs to go after storeClientCopy() at least
     * for OBJCACHE requests */
    protoDispatch(fd, http->entry, http->request);
    return;
}

static void
icpLogIcp(icpUdpData * queue)
{
    icp_common_t *header = (icp_common_t *) (void *) queue->msg;
    char *url = (char *) header + sizeof(icp_common_t);
    AccessLogEntry al;
    ICPCacheInfo->proto_touchobject(ICPCacheInfo,
	queue->proto,
	queue->len);
    ICPCacheInfo->proto_count(ICPCacheInfo,
	queue->proto,
	queue->logcode);
    clientdbUpdate(queue->address.sin_addr, queue->logcode, PROTO_ICP);
    if (!Config.onoff.log_udp)
	return;
    memset(&al, '\0', sizeof(AccessLogEntry));
    al.icp.opcode = ICP_OP_QUERY;
    al.url = url;
    al.cache.caddr = queue->address.sin_addr;
    al.cache.size = queue->len;
    al.cache.code = queue->logcode;
    al.cache.msec = tvSubMsec(queue->start, current_time);
    accessLogLog(&al);
}

void
icpUdpReply(int fd, void *data)
{
    icpUdpData *queue = data;
    int x;
    /* Disable handler, in case of errors. */
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    while ((queue = UdpQueueHead)) {
	debug(12, 5) ("icpUdpReply: FD %d sending %d bytes to %s port %d\n",
	    fd,
	    queue->len,
	    inet_ntoa(queue->address.sin_addr),
	    ntohs(queue->address.sin_port));
	x = comm_udp_sendto(fd,
	    &queue->address,
	    sizeof(struct sockaddr_in),
	    queue->msg,
	    queue->len);
	if (x < 0) {
	    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
		break;		/* don't de-queue */
	}
	UdpQueueHead = queue->next;
	if (queue->logcode)
	    icpLogIcp(queue);
	safe_free(queue->msg);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (UdpQueueHead) {
	commSetSelect(fd, COMM_SELECT_WRITE, icpUdpReply, UdpQueueHead, 0);
    }
}

void *
icpCreateMessage(
    icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad)
{
    char *buf = NULL;
    icp_common_t *headerp = NULL;
    char *urloffset = NULL;
    int buf_len;
    buf_len = sizeof(icp_common_t) + strlen(url) + 1;
    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    headerp->flags = htonl(flags);
    headerp->pad = htonl(pad);
    headerp->shostid = htonl(theOutICPAddr.s_addr);
    urloffset = buf + sizeof(icp_common_t);
    if (opcode == ICP_OP_QUERY)
	urloffset += sizeof(u_num32);
    xmemcpy(urloffset, url, strlen(url));
    return buf;
}

#if USE_ICP_HIT_OBJ
static void *
icpCreateHitObjMessage(
    icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad,
    StoreEntry * entry)
{
    char *buf = NULL;
    char *entryoffset = NULL;
    char *urloffset = NULL;
    icp_common_t *headerp = NULL;
    int buf_len;
    u_short data_sz;
    int size;
    MemObject *m = entry->mem_obj;
    assert(m != NULL);
    buf_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;
    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    headerp->flags = htonl(flags);
    headerp->pad = htonl(pad);
    headerp->shostid = htonl(theOutICPAddr.s_addr);
    urloffset = buf + sizeof(icp_common_t);
    xmemcpy(urloffset, url, strlen(url));
    data_sz = htons((u_short) entry->object_len);
    entryoffset = urloffset + strlen(url) + 1;
    xmemcpy(entryoffset, &data_sz, sizeof(u_short));
    entryoffset += sizeof(u_short);
    assert(m->data != NULL);
    size = memCopy(m->data, 0, entryoffset, entry->object_len);
    if (size < 0 || size != entry->object_len) {
	debug(12, 1) ("icpCreateHitObjMessage: copy failed, wanted %d got %d bytes\n",
	    entry->object_len, size);
	safe_free(buf);
	return NULL;
    }
    return buf;
}
#endif

void
icpUdpSend(int fd,
    const struct sockaddr_in *to,
    icp_common_t * msg,
    log_type logcode,
    protocol_t proto)
{
    icpUdpData *data = xcalloc(1, sizeof(icpUdpData));
    debug(12, 4) ("icpUdpSend: Queueing %s for %s\n",
	IcpOpcodeStr[msg->opcode],
	inet_ntoa(to->sin_addr));
    data->address = *to;
    data->msg = msg;
    data->len = (int) ntohs(msg->length);
#ifndef LESS_TIMING
    data->start = current_time;	/* wrong for HIT_OBJ */
#endif
    data->logcode = logcode;
    data->proto = proto;
    AppendUdp(data);
    commSetSelect(fd, COMM_SELECT_WRITE, icpUdpReply, UdpQueueHead, 0);
}

static int
icpCheckUdpHit(StoreEntry * e, request_t * request)
{
    if (e == NULL)
	return 0;
    if (!storeEntryValidToSend(e))
	return 0;
    if (Config.onoff.icp_hit_stale)
	return 1;
    if (refreshCheck(e, request, 30))
	return 0;
    /* MUST NOT do UDP_HIT_OBJ if object is not in memory with async_io. The */
    /* icpHandleV2 code has not been written to support it - squid will die! */
#if USE_ASYNC_IO || defined(MEM_UDP_HIT_OBJ)
    if (e->mem_status != IN_MEMORY)
	return 0;
#endif
    return 1;
}

#if USE_ICP_HIT_OBJ
static int
icpCheckUdpHitObj(StoreEntry * e, request_t * r, icp_common_t * h, int len)
{
    if (!BIT_TEST(h->flags, ICP_FLAG_HIT_OBJ))	/* not requested */
	return 0;
    if (len > Config.udpMaxHitObjsz)	/* too big */
	return 0;
    if (refreshCheck(e, r, 0))	/* stale */
	return 0;
#ifdef MEM_UDP_HIT_OBJ
    if (e->mem_status != IN_MEMORY)
	return 0;
#endif
    return 1;
}
#endif

static void
icpHandleIcpV2(int fd, struct sockaddr_in from, char *buf, int len)
{
    icp_common_t header;
    icp_common_t *headerp = (icp_common_t *) (void *) buf;
    StoreEntry *entry = NULL;
    char *url = NULL;
    const char *key = NULL;
    request_t *icp_request = NULL;
    int allow = 0;
    char *data = NULL;
    u_short data_sz = 0;
    u_short u;
    int pkt_len;
    aclCheck_t checklist;
    icp_common_t *reply;
    int src_rtt = 0;
    u_num32 flags = 0;
    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
    header.flags = ntohl(headerp->flags);
    header.shostid = ntohl(headerp->shostid);
    header.pad = ntohl(headerp->pad);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	nudpconn++;
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    reply = icpCreateMessage(ICP_OP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, PROTO_NONE);
	    break;
	}
	checklist.src_addr = from.sin_addr;
	checklist.request = icp_request;
	allow = aclCheckFast(Config.accessList.icp, &checklist);
	if (!allow) {
	    debug(12, 2) ("icpHandleIcpV2: Access Denied for %s by %s.\n",
		inet_ntoa(from.sin_addr), AclMatchedName);
	    if (clientdbDeniedPercent(from.sin_addr) < 95) {
		reply = icpCreateMessage(ICP_OP_DENIED, 0, url, header.reqnum, 0);
		icpUdpSend(fd, &from, reply, LOG_UDP_DENIED, icp_request->protocol);
	    }
	    break;
	}
	if (header.flags & ICP_FLAG_SRC_RTT) {
	    int rtt = netdbHostRtt(icp_request->host);
	    int hops = netdbHostHops(icp_request->host);
	    src_rtt = ((hops & 0xFFFF) << 16) | (rtt & 0xFFFF);
	    if (rtt)
		flags |= ICP_FLAG_SRC_RTT;
	}
	/* The peer is allowed to use this cache */
	entry = storeGet(storeGeneratePublicKey(url, METHOD_GET));
	debug(12, 5) ("icpHandleIcpV2: OPCODE %s\n", IcpOpcodeStr[header.opcode]);
	if (icpCheckUdpHit(entry, icp_request)) {
	    pkt_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;
#if USE_ICP_HIT_OBJ
	    if (icpCheckUdpHitObj(entry, icp_request, &header, pkt_len)) {
		reply = icpCreateHitObjMessage(ICP_OP_HIT_OBJ,
		    flags,
		    url,
		    header.reqnum,
		    src_rtt,
		    entry);
		icpUdpSend(fd, &from, reply, LOG_UDP_HIT, icp_request->protocol);
		break;
	    } else {
#endif
		reply = icpCreateMessage(ICP_OP_HIT, flags, url, header.reqnum, src_rtt);
		icpUdpSend(fd, &from, reply, LOG_UDP_HIT, icp_request->protocol);
		break;
#if USE_ICP_HIT_OBJ
	    }
#endif
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (store_rebuilding && opt_reload_hit_only) {
	    reply = icpCreateMessage(ICP_OP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else if (hit_only_mode_until > squid_curtime) {
	    reply = icpCreateMessage(ICP_OP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else {
	    reply = icpCreateMessage(ICP_OP_MISS, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS, icp_request->protocol);
	}
	break;

    case ICP_OP_HIT_OBJ:
    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:
    case ICP_OP_DENIED:
    case ICP_OP_MISS_NOFETCH:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0) ("icpHandleIcpV2: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0) ("icpHandleIcpV2: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
	if (header.opcode == ICP_OP_HIT_OBJ) {
	    data = url + strlen(url) + 1;
	    xmemcpy((char *) &u, data, sizeof(u_short));
	    data += sizeof(u_short);
	    data_sz = ntohs(u);
	    if ((int) data_sz > (len - (data - buf))) {
		debug(12, 0) ("icpHandleIcpV2: ICP_OP_HIT_OBJ object too small\n");
		break;
	    }
	}
	debug(12, 3) ("icpHandleIcpV2: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (neighbors_do_private_keys && header.reqnum) {
	    key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
	} else {
	    key = storeGeneratePublicKey(url, METHOD_GET);
	}
	debug(12, 3) ("icpHandleIcpV2: Looking for key '%s'\n", key);
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3) ("icpHandleIcpV2: Ignoring %s for NULL Entry.\n",
		IcpOpcodeStr[header.opcode]);
	} else {
	    /* call neighborsUdpAck even if ping_status != PING_WAITING */
	    neighborsUdpAck(fd,
		url,
		&header,
		&from,
		entry,
		data,
		(int) data_sz);
	}
	break;

    case ICP_OP_INVALID:
    case ICP_OP_ERR:
	break;

    default:
	debug(12, 0) ("icpHandleIcpV2: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
    if (icp_request)
	put_free_request_t(icp_request);
}

/* Currently Harvest cached-2.x uses ICP_VERSION_3 */
static void
icpHandleIcpV3(int fd, struct sockaddr_in from, char *buf, int len)
{
    icp_common_t header;
    icp_common_t *reply;
    icp_common_t *headerp = (icp_common_t *) (void *) buf;
    StoreEntry *entry = NULL;
    char *url = NULL;
    const char *key = NULL;
    request_t *icp_request = NULL;
    int allow = 0;
    char *data = NULL;
    u_short data_sz = 0;
    u_short u;
    aclCheck_t checklist;

    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
    header.flags = ntohl(headerp->flags);
    header.shostid = ntohl(headerp->shostid);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	nudpconn++;
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    reply = icpCreateMessage(ICP_OP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, PROTO_NONE);
	    break;
	}
	checklist.src_addr = from.sin_addr;
	checklist.request = icp_request;
	allow = aclCheckFast(Config.accessList.icp, &checklist);
	if (!allow) {
	    debug(12, 2) ("icpHandleIcpV3: Access Denied for %s by %s.\n",
		inet_ntoa(from.sin_addr), AclMatchedName);
	    if (clientdbDeniedPercent(from.sin_addr) < 95) {
		reply = icpCreateMessage(ICP_OP_DENIED, 0, url, header.reqnum, 0);
		icpUdpSend(fd, &from, reply, LOG_UDP_DENIED, icp_request->protocol);
	    }
	    break;
	}
	/* The peer is allowed to use this cache */
	entry = storeGet(storeGeneratePublicKey(url, METHOD_GET));
	debug(12, 5) ("icpHandleIcpV3: OPCODE %s\n",
	    IcpOpcodeStr[header.opcode]);
	if (icpCheckUdpHit(entry, icp_request)) {
	    reply = icpCreateMessage(ICP_OP_HIT, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_HIT, icp_request->protocol);
	    break;
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (opt_reload_hit_only && store_rebuilding) {
	    reply = icpCreateMessage(ICP_OP_MISS_NOFETCH, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else if (hit_only_mode_until > squid_curtime) {
	    reply = icpCreateMessage(ICP_OP_MISS_NOFETCH, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else {
	    reply = icpCreateMessage(ICP_OP_MISS, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS, icp_request->protocol);
	}
	break;

    case ICP_OP_HIT_OBJ:
    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:
    case ICP_OP_DENIED:
    case ICP_OP_MISS_NOFETCH:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0) ("icpHandleIcpV3: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0) ("icpHandleIcpV3: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
	if (header.opcode == ICP_OP_HIT_OBJ) {
	    data = url + strlen(url) + 1;
	    xmemcpy((char *) &u, data, sizeof(u_short));
	    data += sizeof(u_short);
	    data_sz = ntohs(u);
	    if ((int) data_sz > (len - (data - buf))) {
		debug(12, 0) ("icpHandleIcpV3: ICP_OP_HIT_OBJ object too small\n");
		break;
	    }
	}
	debug(12, 3) ("icpHandleIcpV3: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (neighbors_do_private_keys && header.reqnum) {
	    key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
	} else {
	    key = storeGeneratePublicKey(url, METHOD_GET);
	}
	debug(12, 3) ("icpHandleIcpV3: Looking for key '%s'\n", key);
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3) ("icpHandleIcpV3: Ignoring %s for NULL Entry.\n",
		IcpOpcodeStr[header.opcode]);
	} else {
	    /* call neighborsUdpAck even if ping_status != PING_WAITING */
	    neighborsUdpAck(fd,
		url,
		&header,
		&from,
		entry,
		data,
		(int) data_sz);
	}
	break;

    case ICP_OP_INVALID:
    case ICP_OP_ERR:
	break;

    default:
	debug(12, 0) ("icpHandleIcpV3: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
    if (icp_request)
	put_free_request_t(icp_request);
}

#ifdef ICP_PKT_DUMP
static void
icpPktDump(icp_common_t * pkt)
{
    struct in_addr a;

    debug(12, 9) ("opcode:     %3d %s\n",
	(int) pkt->opcode,
	IcpOpcodeStr[pkt->opcode]);
    debug(12, 9) ("version: %-8d\n", (int) pkt->version);
    debug(12, 9) ("length:  %-8d\n", (int) ntohs(pkt->length));
    debug(12, 9) ("reqnum:  %-8d\n", ntohl(pkt->reqnum));
    debug(12, 9) ("flags:   %-8x\n", ntohl(pkt->flags));
    a.s_addr = ntohl(pkt->shostid);
    debug(12, 9) ("shostid: %s\n", inet_ntoa(a));
    debug(12, 9) ("payload: %s\n", (char *) pkt + sizeof(icp_common_t));
}
#endif

void
icpHandleUdp(int sock, void *not_used)
{
    struct sockaddr_in from;
    int from_len;
    LOCAL_ARRAY(char, buf, SQUID_UDP_SO_RCVBUF);
    int len;
    icp_common_t *headerp = NULL;
    int icp_version;

    commSetSelect(sock, COMM_SELECT_READ, icpHandleUdp, NULL, 0);
    from_len = sizeof(from);
    memset(&from, '\0', from_len);
    len = recvfrom(sock,
	buf,
	SQUID_UDP_SO_RCVBUF - 1,
	0,
	(struct sockaddr *) &from,
	&from_len);
    if (len < 0) {
#ifdef _SQUID_LINUX_
	/* Some Linux systems seem to set the FD for reading and then
	 * return ECONNREFUSED when sendto() fails and generates an ICMP
	 * port unreachable message. */
	/* or maybe an EHOSTUNREACH "No route to host" message */
	if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif
	    debug(50, 1) ("icpHandleUdp: FD %d recvfrom: %s\n",
		sock, xstrerror());
	return;
    }
    buf[len] = '\0';
    debug(12, 4) ("icpHandleUdp: FD %d: received %d bytes from %s.\n",
	sock,
	len,
	inet_ntoa(from.sin_addr));
#ifdef ICP_PACKET_DUMP
    icpPktDump(buf);
#endif
    if (len < sizeof(icp_common_t)) {
	debug(12, 4) ("icpHandleUdp: Ignoring too-small UDP packet\n");
	return;
    }
    headerp = (icp_common_t *) (void *) buf;
    if ((icp_version = (int) headerp->version) == ICP_VERSION_2)
	icpHandleIcpV2(sock, from, buf, len);
    else if (icp_version == ICP_VERSION_3)
	icpHandleIcpV3(sock, from, buf, len);
    else
	debug(12, 0) ("WARNING: Unused ICP version %d received from %s:%d\n",
	    icp_version,
	    inet_ntoa(from.sin_addr),
	    ntohs(from.sin_port));
}

/*
 *  parseHttpRequest()
 * 
 *  Returns
 *   -1 on error
 *    0 on incomplete request
 *    1 on success
 */
static clientHttpRequest *
parseHttpRequest(ConnStateData * conn, method_t * method_p, int *status,
    char **headers_p, size_t * headers_sz_p)
{
    char *inbuf = NULL;
    char *mstr = NULL;
    char *url = NULL;
    char *req_hdr = NULL;
    LOCAL_ARRAY(char, http_ver_s, 32);
    float http_ver;
    char *token = NULL;
    char *t = NULL;
    char *end = NULL;
    int free_request = 0;
    size_t header_sz;		/* size of headers, not including first line */
    size_t req_sz;		/* size of whole request */
    size_t url_sz;
    method_t method;
    clientHttpRequest *http = NULL;

    /* Make sure a complete line has been received */
    if (strchr(conn->in.buf, '\n') == NULL) {
	debug(12, 5) ("Incomplete request line, waiting for more data\n");
	*status = 0;
	return NULL;
    }
    /* Use xmalloc/xmemcpy instead of xstrdup because inbuf might
     * contain NULL bytes; especially for POST data  */
    inbuf = xmalloc(conn->in.offset + 1);
    xmemcpy(inbuf, conn->in.buf, conn->in.offset);
    *(inbuf + conn->in.offset) = '\0';

    /* Look for request method */
    if ((mstr = strtok(inbuf, "\t ")) == NULL) {
	debug(12, 1) ("parseHttpRequest: Can't get request method\n");
	xfree(inbuf);
	*status = -1;
	return NULL;
    }
    method = urlParseMethod(mstr);
    if (method == METHOD_NONE) {
	debug(12, 1) ("parseHttpRequest: Unsupported method '%s'\n", mstr);
	xfree(inbuf);
	*status = -1;
	return NULL;
    }
    debug(12, 5) ("parseHttpRequest: Method is '%s'\n", mstr);

    /* look for URL */
    if ((url = strtok(NULL, "\r\n\t ")) == NULL) {
	debug(12, 1) ("parseHttpRequest: Missing URL\n");
	xfree(inbuf);
	*status = -1;
	return NULL;
    }
    debug(12, 5) ("parseHttpRequest: Request is '%s'\n", url);

    token = strtok(NULL, null_string);
    for (t = token; t && *t && *t != '\n' && *t != '\r'; t++);
    if (t == NULL || *t == '\0' || t == token) {
	debug(12, 3) ("parseHttpRequest: Missing HTTP identifier\n");
	xfree(inbuf);
	*status = -1;
	return NULL;
    }
    memset(http_ver_s, '\0', 32);
    xstrncpy(http_ver_s, token, 32);
    sscanf(http_ver_s, "HTTP/%f", &http_ver);
    debug(12, 5) ("parseHttpRequest: HTTP version is '%3.1f'\n", http_ver);

    /* Check if headers are received */
    if ((end = mime_headers_end(t)) == NULL) {
	xfree(inbuf);
	*status = 0;
	return NULL;
    }
    while (isspace(*t))
	t++;
    req_hdr = t;
    header_sz = end - req_hdr;
    req_sz = end - inbuf;

    /* Ok, all headers are received */
    http = xcalloc(1, sizeof(clientHttpRequest));
    cbdataAdd(http);
    http->http_ver = http_ver;
    http->conn = conn;
    http->start = current_time;
    http->req_sz = req_sz;
    *headers_sz_p = header_sz;
    *headers_p = xmalloc(header_sz + 1);
    xmemcpy(*headers_p, req_hdr, header_sz);
    *(*headers_p + header_sz) = '\0';

    debug(12, 5) ("parseHttpRequest: Request Header is\n%s\n", *headers_p);

    /* Assign http->url */
    if ((t = strchr(url, '\n')))	/* remove NL */
	*t = '\0';
    if ((t = strchr(url, '\r')))	/* remove CR */
	*t = '\0';
    if ((t = strchr(url, '#')))	/* remove HTML anchors */
	*t = '\0';

    /* see if we running in Config2.Accel.on, if so got to convert it to URL */
    if (Config2.Accel.on && *url == '/') {
	/* prepend the accel prefix */
	if (vhost_mode) {
	    /* Put the local socket IP address as the hostname */
	    url_sz = strlen(url) + 32 + Config.appendDomainLen;
	    http->url = xcalloc(url_sz, 1);
	    snprintf(http->url, url_sz, "http://%s:%d%s",
		inet_ntoa(http->conn->me.sin_addr),
		(int) Config.Accel.port,
		url);
	    debug(12, 5) ("VHOST REWRITE: '%s'\n", http->url);
	} else if (opt_accel_uses_host && (t = mime_get_header(req_hdr, "Host"))) {
	    /* If a Host: header was specified, use it to build the URL 
	     * instead of the one in the Config file. */
	    /*
	     * XXX Use of the Host: header here opens a potential
	     * security hole.  There are no checks that the Host: value
	     * corresponds to one of your servers.  It might, for example,
	     * refer to www.playboy.com.  The 'dst' and/or 'dst_domain' ACL 
	     * types should be used to prevent httpd-accelerators 
	     * handling requests for non-local servers */
	    strtok(t, " :/;@");
	    url_sz = strlen(url) + 32 + Config.appendDomainLen;
	    http->url = xcalloc(url_sz, 1);
	    snprintf(http->url, url_sz, "http://%s:%d%s",
		t, (int) Config.Accel.port, url);
	} else {
	    url_sz = strlen(Config2.Accel.prefix) + strlen(url) +
		Config.appendDomainLen + 1;
	    http->url = xcalloc(url_sz, 1);
	    snprintf(http->url, url_sz, "%s%s", Config2.Accel.prefix, url);
	}
	http->accel = 1;
    } else {
	/* URL may be rewritten later, so make extra room */
	url_sz = strlen(url) + Config.appendDomainLen + 5;
	http->url = xcalloc(url_sz, 1);
	strcpy(http->url, url);
	http->accel = 0;
    }
    http->log_url = xstrdup(http->url);
    debug(12, 5) ("parseHttpRequest: Complete request received\n");
    if (free_request)
	safe_free(url);
    xfree(inbuf);
    *method_p = method;
    *status = 1;
    return http;
}

static int
clientReadDefer(int fd, void *data)
{
    ConnStateData *conn = data;
    return conn->defer.until > squid_curtime;
}

static void
clientReadRequest(int fd, void *data)
{
    ConnStateData *conn = data;
    int parser_return_code = 0;
    int k;
    request_t *request = NULL;
    char *tmp;
    int size;
    int len;
    method_t method;
    clientHttpRequest *http = NULL;
    clientHttpRequest **H = NULL;
    char *headers;
    size_t headers_sz;
    ErrorState *err = NULL;
    fde *F = &fd_table[fd];

    len = conn->in.size - conn->in.offset - 1;
    debug(12, 4) ("clientReadRequest: FD %d: reading request...\n", fd);
    size = read(fd, conn->in.buf + conn->in.offset, len);
    fd_bytes(fd, size, FD_READ);

    if (size == 0) {
	if (conn->chr == NULL) {
	    /* no current or pending requests */
	    comm_close(fd);
	    return;
	}
	/* It might be half-closed, we can't tell */
	debug(12, 5) ("clientReadRequest: FD %d closed?\n", fd);
	BIT_SET(F->flags, FD_SOCKET_EOF);
	conn->defer.until = squid_curtime + 1;
	conn->defer.n++;
	commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
	return;
    } else if (size < 0) {
	if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
	    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
	} else {
	    debug(50, 2) ("clientReadRequest: FD %d: %s\n", fd, xstrerror());
	    comm_close(fd);
	}
	return;
    }
    conn->in.offset += size;
    conn->in.buf[conn->in.offset] = '\0';	/* Terminate the string */

    while (conn->in.offset > 0) {
	http = parseHttpRequest(conn,
	    &method,
	    &parser_return_code,
	    &headers,
	    &headers_sz);
	if (http) {
	    assert(http->req_sz > 0);
	    conn->in.offset -= http->req_sz;
	    assert(conn->in.offset >= 0);
	    if (conn->in.offset > 0) {
		tmp = xstrdup(conn->in.buf + http->req_sz);
		xstrncpy(conn->in.buf, tmp, conn->in.size);
		safe_free(tmp);
	    }
	    /* link */
	    for (H = &conn->chr; *H; H = &(*H)->next);
	    *H = http;
	    conn->nrequests++;
	    commSetTimeout(fd, Config.Timeout.lifetime, NULL, NULL);
	    if ((request = urlParse(method, http->url)) == NULL) {
		debug(12, 5) ("Invalid URL: %s\n", http->url);
		err = errorCon(ERR_INVALID_URL, HTTP_BAD_REQUEST);
		err->src_addr = conn->peer.sin_addr;
		err->callback = icpErrorComplete;
		err->callback_data = http;
		err->url = xstrdup(http->url);
		http->al.http.code = err->http_status;
		errorSend(fd, err);
		safe_free(headers);
		break;
	    }
	    request->client_addr = conn->peer.sin_addr;
	    request->http_ver = http->http_ver;
	    request->headers = headers;
	    request->headers_sz = headers_sz;
	    if (!urlCheckRequest(request)) {
		err = errorCon(ERR_UNSUP_REQ, HTTP_NOT_IMPLEMENTED);
		err->src_addr = conn->peer.sin_addr;
		err->callback = icpErrorComplete;
		err->callback_data = http;
		err->request = requestLink(request);
		http->al.http.code = err->http_status;
		errorSend(fd, err);
		return;
	    }
	    http->request = requestLink(request);
	    clientAccessCheck(http);
	    /* break here for NON-GET because most likely there is a
	     * reqeust body following and we don't want to parse it
	     * as though it was new request */
	    if (request->method != METHOD_GET) {
		if (conn->in.offset) {
		    request->body_sz = conn->in.offset;
		    request->body = xmalloc(request->body_sz);
		    xmemcpy(request->body, conn->in.buf, request->body_sz);
		    conn->in.offset = 0;
		}
		break;
	    }
	    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
	    continue;		/* while offset > 0 */
	} else if (parser_return_code == 0) {
	    /*
	     *    Partial request received; reschedule until parseHttpRequest()
	     *    is happy with the input
	     */
	    k = conn->in.size - 1 - conn->in.offset;
	    if (k == 0) {
		if (conn->in.offset >= Config.maxRequestSize) {
		    /* The request is too large to handle */
		    debug(12, 0) ("Request won't fit in buffer.\n");
		    debug(12, 0) ("Config 'request_size'= %d bytes.\n",
			Config.maxRequestSize);
		    debug(12, 0) ("This request = %d bytes.\n",
			conn->in.offset);
		    err = errorCon(ERR_INVALID_REQ, HTTP_REQUEST_ENTITY_TOO_LARGE);
		    err->callback = icpErrorComplete;
		    err->callback_data = NULL;
		    errorSend(fd, err);
		    return;
		}
		/* Grow the request memory area to accomodate for a large request */
		conn->in.size += REQUEST_BUF_SIZE;
		conn->in.buf = xrealloc(conn->in.buf, conn->in.size);
		meta_data.misc += REQUEST_BUF_SIZE;
		debug(12, 2) ("Handling a large request, offset=%d inbufsize=%d\n",
		    conn->in.offset, conn->in.size);
		k = conn->in.size - 1 - conn->in.offset;
	    }
	    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
	    break;
	} else {
	    /* parser returned -1 */
	    debug(12, 1) ("clientReadRequest: FD %d Invalid Request\n", fd);
	    err = errorCon(ERR_INVALID_REQ, HTTP_BAD_REQUEST);
	    err->callback = icpErrorComplete;
	    err->callback_data = NULL;
	    errorSend(fd, err);
	    return;
	}
    }
}

/* general lifetime handler for HTTP requests */
static void
requestTimeout(int fd, void *data)
{
    ConnStateData *conn = data;
    ErrorState *err;
    debug(12, 2) ("requestTimeout: FD %d: lifetime is expired.\n", fd);
    if (fd_table[fd].rwstate) {
	/* Some data has been sent to the client, just close the FD */
	comm_close(fd);
    } else if (conn->nrequests) {
	/* assume its a persistent connection; just close it */
	comm_close(fd);
    } else {
	/* Generate an error */
	err = errorCon(ERR_LIFETIME_EXP, HTTP_REQUEST_TIMEOUT);
	err->callback = icpErrorComplete;
	err->url = xstrdup("N/A");
	errorSend(fd, err);
	/* if we don't close() here, we still need a timeout handler! */
	commSetTimeout(fd, 30, requestTimeout, conn);
    }
}

int
httpAcceptDefer(int fd, void *notused)
{
    return !fdstat_are_n_free_fd(RESERVED_FD);
}

/* Handle a new connection on ascii input socket. */
void
httpAccept(int sock, void *notused)
{
    int fd = -1;
    ConnStateData *connState = NULL;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    memset(&peer, '\0', sizeof(struct sockaddr_in));
    memset(&me, '\0', sizeof(struct sockaddr_in));
    commSetSelect(sock, COMM_SELECT_READ, httpAccept, NULL, 0);
    if ((fd = comm_accept(sock, &peer, &me)) < 0) {
	debug(50, 1) ("httpAccept: FD %d: accept failure: %s\n",
	    sock, xstrerror());
	return;
    }
    ntcpconn++;
    debug(12, 4) ("httpAccept: FD %d: accepted\n", fd);
    connState = xcalloc(1, sizeof(ConnStateData));
    connState->peer = peer;
    connState->log_addr = peer.sin_addr;
    connState->log_addr.s_addr &= Config.Addrs.client_netmask.s_addr;
    connState->me = me;
    connState->fd = fd;
    connState->ident.fd = -1;
    connState->in.size = REQUEST_BUF_SIZE;
    connState->in.buf = xcalloc(connState->in.size, 1);
    cbdataAdd(connState);
    meta_data.misc += connState->in.size;
    comm_add_close_handler(fd, connStateFree, connState);
    if (Config.onoff.log_fqdn)
	fqdncache_gethostbyaddr(peer.sin_addr, FQDN_LOOKUP_IF_MISS);
    commSetTimeout(fd, Config.Timeout.request, requestTimeout, connState);
    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, connState, 0);
    commSetDefer(fd, clientReadDefer, connState);
}

void
AppendUdp(icpUdpData * item)
{
    item->next = NULL;
    if (UdpQueueHead == NULL) {
	UdpQueueHead = item;
	UdpQueueTail = item;
    } else if (UdpQueueTail == UdpQueueHead) {
	UdpQueueTail = item;
	UdpQueueHead->next = item;
    } else {
	UdpQueueTail->next = item;
	UdpQueueTail = item;
    }
}

/* return 1 if the request should be aborted */
static int
CheckQuickAbort2(const clientHttpRequest * http)
{
    long curlen;
    long minlen;
    long expectlen;

    if (!BIT_TEST(http->request->flags, REQ_CACHABLE))
	return 1;
    if (BIT_TEST(http->entry->flag, KEY_PRIVATE))
	return 1;
    if (http->entry->mem_obj == NULL)
	return 1;
    expectlen = http->entry->mem_obj->reply->content_length;
    curlen = http->entry->mem_obj->inmem_hi;
    minlen = Config.quickAbort.min;
    if (minlen < 0)
	/* disabled */
	return 0;
    if (curlen > expectlen)
	/* bad content length */
	return 1;
    if ((expectlen - curlen) < minlen)
	/* only little more left */
	return 0;
    if ((expectlen - curlen) > Config.quickAbort.max)
	/* too much left to go */
	return 1;
    if ((curlen / (expectlen / 128U)) > Config.quickAbort.pct)
	/* past point of no return */
	return 0;
    return 1;
}


static void
CheckQuickAbort(clientHttpRequest * http)
{
    StoreEntry *entry = http->entry;
    /* Note, set entry here because http->entry might get changed (for IMS
     * requests) during the storeAbort() call */
    if (entry == NULL)
	return;
    if (storePendingNClients(entry) > 1)
	return;
    if (entry->store_status != STORE_PENDING)
	return;
    if (CheckQuickAbort2(http) == 0)
	return;
    debug(12, 3) ("CheckQuickAbort: ABORTING %s\n", entry->url);
    storeAbort(entry, 1);
}

static int
icpCheckTransferDone(clientHttpRequest * http)
{
    StoreEntry *entry = http->entry;
    MemObject *mem = NULL;

    if (entry == NULL)
	return 0;
    if (entry->store_status != STORE_PENDING)
	if (http->out.offset >= entry->object_len)
	    return 1;
    if ((mem = entry->mem_obj) == NULL)
	return 0;
    if (mem->reply->content_length == 0)
	return 0;
    if (http->out.offset >= mem->reply->content_length + mem->reply->hdr_sz)
	return 1;
    return 0;
}

static char *
icpConstruct304reply(struct _http_reply *source)
{
    LOCAL_ARRAY(char, line, 256);
    LOCAL_ARRAY(char, reply, 8192);

    memset(reply, '\0', 8192);
    strcpy(reply, "HTTP/1.0 304 Not Modified\r\n");
    if (source->date > -1) {
	snprintf(line, 256, "Date: %s\r\n", mkrfc1123(source->date));
	strcat(reply, line);
    }
    if ((int) strlen(source->content_type) > 0) {
	snprintf(line, 256, "Content-type: %s\r\n", source->content_type);
	strcat(reply, line);
    }
    if (source->content_length) {
	snprintf(line, 256, "Content-length: %d\r\n", source->content_length);
	strcat(reply, line);
    }
    if (source->expires > -1) {
	snprintf(line, 256, "Expires: %s\r\n", mkrfc1123(source->expires));
	strcat(reply, line);
    }
    if (source->last_modified > -1) {
	snprintf(line, 256, "Last-modified: %s\r\n",
	    mkrfc1123(source->last_modified));
	strcat(reply, line);
    }
    strcat(reply, "\r\n");
    return reply;
}

struct viz_pkt {
    u_num32 from;
    char type;
};
