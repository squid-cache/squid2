
/*
 * $Id$
 *
 * DEBUG: section 12    Client Handling
 * AUTHOR: Harvest Derived
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

int neighbors_do_private_keys = 1;

static char NotModified[] = "HTTP/1.0 304 Not Modified\r\n\r\n";
static char *log_tags[] =
{
    "LOG_NONE",
    "TCP_HIT",
    "TCP_MISS",
    "TCP_EXPIRED",
    "TCP_REFRESH",
    "TCP_IFMODSINCE",
    "TCP_SWAPFAIL",
    "TCP_DENIED",
    "UDP_HIT",
    "UDP_HIT_OBJ",
    "UDP_MISS",
    "UDP_DENIED",
    "UDP_INVALID",
    "UDP_RELOADING",
    "ERR_READ_TIMEOUT",
    "ERR_LIFETIME_EXP",
    "ERR_NO_CLIENTS_BIG_OBJ",
    "ERR_READ_ERROR",
    "ERR_CLIENT_ABORT",
    "ERR_CONNECT_FAIL",
    "ERR_INVALID_REQ",
    "ERR_UNSUP_REQ",
    "ERR_INVALID_URL",
    "ERR_NO_FDS",
    "ERR_DNS_FAIL",
    "ERR_NOT_IMPLEMENTED",
    "ERR_CANNOT_FETCH",
    "ERR_NO_RELAY",
    "ERR_DISK_IO",
    "ERR_ZERO_SIZE_OBJECT"
};

typedef struct iwd {
    icp_common_t header;	/* Allows access to previous header */
    char *url;
    char *inbuf;
    int inbufsize;
    method_t method;		/* GET, POST, ... */
    request_t *request;		/* Parsed URL ... */
    char *request_hdr;		/* Mime header */
    int req_hdr_sz;
    StoreEntry *entry;
    long offset;
    int log_type;
    int http_code;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    char *ptr_to_4k_page;
    char *buf;
    struct timeval start;
    int accel;
    int size;			/* hack for CONNECT which doesnt use sentry */
} icpStateData;

#if DELAY_HACK
int _delay_fetch;
#endif

static icpUdpData *UdpQueueHead = NULL;
static icpUdpData *UdpQueueTail = NULL;
#define ICP_SENDMOREDATA_BUF SM_PAGE_SIZE

typedef struct {
    int fd;
    struct sockaddr_in to;
    StoreEntry *entry;
    icp_common_t header;
    struct timeval started;
} icpHitObjStateData;

/* Local functions */
static void icpHandleStore _PARAMS((int, StoreEntry *, icpStateData *));
static void icpHandleStoreComplete _PARAMS((int, char *, int, int, void *icpState));
static void icpHandleStoreIMS _PARAMS((int, StoreEntry *, icpStateData *));
static void icpHandleIMSComplete _PARAMS((int, char *, int, int, void *icpState));
static int icpProcessHIT _PARAMS((int, icpStateData *));
static int icpProcessIMS _PARAMS((int, icpStateData *));
static int icpProcessMISS _PARAMS((int, icpStateData *));
static void CheckQuickAbort _PARAMS((icpStateData *));
static void icpHitObjHandler _PARAMS((int, void *));
static void icpLogIcp _PARAMS((icpUdpData *));
static void icpDetectClientClose _PARAMS((int, icpStateData *));
static void icpHandleIcpV2 _PARAMS((int fd, struct sockaddr_in, char *, int len));
static void icpHandleIcpV3 _PARAMS((int fd, struct sockaddr_in, char *, int len));
static void checkFailureRatio _PARAMS((log_type, hier_code));
static void icpUdpSendEntry _PARAMS((int fd,
	char *url,
	int reqnum,
	struct sockaddr_in * to,
	icp_opcode opcode,
	StoreEntry * entry,
	struct timeval start_time));

/*
 * This function is designed to serve a fairly specific purpose.
 * Occasionally our vBNS-connected caches can talk to each other, but not
 * the rest of the world.  Here we try to detect frequent failures which
 * make the cache unusable (e.g. DNS lookup and connect() failures).  If
 * the failure:success ratio goes above 1.0 then we go into "hit only"
 * mode where we only return UDP_HIT or UDP_RELOADING.  (UDP_RELOADING
 * isn't quite the appropriate term but it gets the job done).  Neighbors
 * will only fetch HITs from us if they are using the ICP protocol.  We
 * stay in this mode for 5 minutes.
 * 
 * Duane W., Sept 16, 1996
 */

#define FAILURE_MODE_TIME 300
static time_t hit_only_mode_until = 0;

static void checkFailureRatio(rcode, hcode)
     log_type rcode;
     hier_code hcode;
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
    debug(12, 0, "Failure Ratio at %4.2f\n", fail_ratio);
    debug(12, 0, "Going into hit-only-mode for %d minutes...\n",
	FAILURE_MODE_TIME / 60);
    hit_only_mode_until = squid_curtime + FAILURE_MODE_TIME;
    fail_ratio = 0.8;		/* reset to something less than 1.0 */
}

static void icpFreeBufOrPage(icpState)
     icpStateData *icpState;
{
    if (icpState->ptr_to_4k_page && icpState->buf)
	fatal_dump("icpFreeBufOrPage: Shouldn't have both a 4k ptr and a string");
    if (icpState->ptr_to_4k_page) {
	put_free_4k_page(icpState->ptr_to_4k_page);
    } else {
	safe_free(icpState->buf);
    }
    icpState->ptr_to_4k_page = icpState->buf = NULL;
}


/* This is a handler normally called by comm_close() */
static int icpStateFree(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    int size = 0;
    int http_code = 0;
    int elapsed_msec;
    hier_code hier_code = HIER_NONE;

    if (!icpState)
	return 1;
    if (icpState->log_type < LOG_TAG_NONE || icpState->log_type > ERR_ZERO_SIZE_OBJECT)
	fatal_dump("icpStateFree: icpState->log_type out of range.");
    if (icpState->entry) {
	if (icpState->entry->mem_obj)
	    size = icpState->entry->mem_obj->e_current_len;
    } else {
	size = icpState->size;	/* hack added for CONNECT objects */
    }
    if (icpState->entry) {
	if (icpState->entry->mem_obj)
	    http_code = icpState->entry->mem_obj->reply->code;
    } else {
	http_code = icpState->http_code;
    }
    elapsed_msec = tvSubMsec(icpState->start, current_time);
    if (icpState->request)
	hier_code = icpState->request->hierarchy_code;
    CacheInfo->log_append(CacheInfo,
	icpState->url,
	inet_ntoa(icpState->peer.sin_addr),
	size,
	log_tags[icpState->log_type],
	RequestMethodStr[icpState->method],
	http_code,
	elapsed_msec,
	hier_code);
    checkFailureRatio(icpState->log_type, hier_code);
    safe_free(icpState->inbuf);
    meta_data.misc -= icpState->inbufsize;
    safe_free(icpState->url);
    safe_free(icpState->request_hdr);
    if (icpState->entry) {
	storeUnregister(icpState->entry, fd);
	storeUnlockObject(icpState->entry);
	icpState->entry = NULL;
    }
    requestUnlink(icpState->request);
    icpFreeBufOrPage(icpState);
    safe_free(icpState);
    return 0;			/* XXX gack, all comm handlers return ints */
}

static void icpParseRequestHeaders(icpState)
     icpStateData *icpState;
{
    char *request_hdr = icpState->request_hdr;
    char *t = NULL;
    request_t *request = icpState->request;
    if (mime_get_header(request_hdr, "If-Modified-Since"))
	BIT_SET(request->flags, REQ_IMS);
    if ((t = mime_get_header(request_hdr, "Pragma"))) {
	if (!strcasecmp(t, "no-cache"))
	    BIT_SET(request->flags, REQ_NOCACHE);
    }
    if (mime_get_header(request_hdr, "Authorization"))
	BIT_SET(request->flags, REQ_AUTH);
    if (strstr(request_hdr, ForwardedBy))
	BIT_SET(request->flags, REQ_LOOPDETECT);
}

static int icpCachable(icpState)
     icpStateData *icpState;
{
    char *request = icpState->url;
    request_t *req = icpState->request;
    method_t method = req->method;
    if (BIT_TEST(icpState->request->flags, REQ_AUTH))
	return 0;
    if (req->protocol == PROTO_HTTP)
	return httpCachable(request, method);
    if (req->protocol == PROTO_FTP)
	return ftpCachable(request);
    if (req->protocol == PROTO_GOPHER)
	return gopherCachable(request);
    if (req->protocol == PROTO_WAIS)
	return 0;
    if (method == METHOD_CONNECT)
	return 0;
    if (req->protocol == PROTO_CACHEOBJ)
	return 0;
    return 1;
}

/* Return true if we can query our neighbors for this object */
static int icpHierarchical(icpState)
     icpStateData *icpState;
{
    char *url = icpState->url;
    request_t *request = icpState->request;
    method_t method = request->method;
    wordlist *p = NULL;
    /* IMS needs a private key, so we can use the hierarchy for IMS only
     * if our neighbors support private keys */
    if (BIT_TEST(request->flags, REQ_IMS) && !neighbors_do_private_keys)
	return 0;
    if (BIT_TEST(request->flags, REQ_AUTH))
	return 0;
    if (method != METHOD_GET)
	return 0;
    /* scan hierarchy_stoplist */
    for (p = getHierarchyStoplist(); p; p = p->next)
	if (strstr(url, p->key))
	    return 0;
    if (BIT_TEST(request->flags, REQ_LOOPDETECT))
	return 0;
    if (request->protocol == PROTO_HTTP)
	return httpCachable(url, method);
    if (request->protocol == PROTO_FTP)
	return ftpCachable(url);
    if (request->protocol == PROTO_GOPHER)
	return gopherCachable(url);
    if (request->protocol == PROTO_WAIS)
	return 0;
    if (request->protocol == PROTO_CACHEOBJ)
	return 0;
    return 1;
}

static void icpSendERRORComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     void *data;
{
    debug(12, 4, "icpSendERRORComplete: FD %d: sz %d: err %d.\n",
	fd, size, errflag);
    comm_close(fd);
}

/* Send ERROR message. */
static int icpSendERROR(fd, errorCode, msg, icpState)
     int fd;
     int errorCode;
     char *msg;
     icpStateData *icpState;
{
    char *buf = NULL;
    int buf_len = 0;
    u_short port = 0;

    port = comm_local_port(fd);
    debug(12, 4, "icpSendERROR: code %d: port %hd: msg: '%s'\n",
	errorCode, port, msg);

    if (port == 0) {
	/* This file descriptor isn't bound to a socket anymore.
	 * It probably timed out. */
	debug(12, 2, "icpSendERROR: COMM_ERROR msg: %80.80s\n", msg);
	icpSendERRORComplete(fd, (char *) NULL, 0, 1, icpState);
	return COMM_ERROR;
    }
    if (port != getHttpPortNum()) {
	sprintf(tmp_error_buf, "icpSendERROR: FD %d unexpected port %hd.",
	    fd, port);
	fatal_dump(tmp_error_buf);
    }
    if (icpState->entry && icpState->entry->mem_obj) {
	if (icpState->entry->mem_obj->e_current_len > 0) {
	    comm_close(fd);
	    return COMM_OK;
	}
    }
    /* Error message for the ascii port */
    buf_len = strlen(msg);
    buf_len = buf_len > 4095 ? 4095 : buf_len;
    buf = icpState->ptr_to_4k_page = get_free_4k_page();
    icpState->buf = NULL;
    strcpy(buf, msg);
    *(buf + buf_len) = '\0';
    comm_write(fd, buf, buf_len, 30, icpSendERRORComplete, (void *) icpState);
    return COMM_OK;
}

/* Send available data from an object in the cache.  This is called either
 * on select for  write or directly by icpHandleStore. */

static int icpSendMoreData(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    StoreEntry *entry = icpState->entry;
    char *buf = NULL;
    char *p = NULL;
    icp_common_t *header = &icpState->header;
    int buf_len;
    int len;
    int max_len = 0;
    int result = COMM_ERROR;
    int tcode = 555;
    double http_ver;
    static char scanbuf[20];

    debug(12, 5, "icpSendMoreData: <URL:%s> sz %d: len %d: off %d.\n",
	entry->url, entry->object_len,
	entry->mem_obj ? entry->mem_obj->e_current_len : 0, icpState->offset);

    p = icpState->ptr_to_4k_page = buf = get_free_4k_page();
    icpState->buf = NULL;

    /* Set maxlen to largest amount of data w/o header
     * place p pointing to beginning of data portion of message */

    buf_len = 0;		/* No header for ascii mode */

    max_len = ICP_SENDMOREDATA_BUF - buf_len;
    /* Should limit max_len to something like 1.5x last successful write */
    p += buf_len;

    storeClientCopy(icpState->entry, icpState->offset, max_len, p, &len, fd);

    buf_len += len;

    if (icpState->offset == 0 && entry->mem_obj->reply->code == 0 && len > 0) {
	memset(scanbuf, '\0', 20);
	xmemcpy(scanbuf, buf, len > 19 ? 19 : len);
	sscanf(scanbuf, "HTTP/%lf %d", &http_ver, &tcode);
	entry->mem_obj->reply->code = tcode;
    }
    if ((icpState->offset == 0) && (header->opcode != ICP_OP_DATABEG)) {
	header->opcode = ICP_OP_DATABEG;
    } else if ((entry->mem_obj->e_current_len == entry->object_len) &&
	    ((entry->object_len - icpState->offset) == len) &&
	(entry->store_status != STORE_PENDING)) {
	/* No more data; this is the last message. */
	header->opcode = ICP_OP_DATAEND;
    } else {
	/* We know there is more data to come. */
	header->opcode = ICP_OP_DATA;
    }
    debug(12, 6, "icpSendMoreData: opcode %d: len %d.\n",
	header->opcode, entry->object_len);

    header->length = buf_len;

    icpState->offset += len;

    /* Do this here, so HandleStoreComplete can tell whether more data 
     * needs to be sent. */
    comm_write(fd, buf, buf_len, 30, icpHandleStoreComplete, (void *) icpState);
    result = COMM_OK;
    return result;
}

/* Called by storage manager when more data arrives from source. 
 * Starts state machine towards client with new batch of data or
 * error messages.  We get here by invoking the handlers in the
 * pending list.
 */
static void icpHandleStore(fd, entry, icpState)
     int fd;
     StoreEntry *entry;
     icpStateData *icpState;
{
    debug(12, 5, "icpHandleStore: FD %d: off %d: <URL:%s>\n",
	fd, icpState->offset, entry->url);

    if (entry->store_status == STORE_ABORTED) {
	icpState->log_type = entry->mem_obj->abort_code;
	debug(12, 3, "icpHandleStore: abort_code=%d\n", entry->mem_obj->abort_code);
	icpState->ptr_to_4k_page = NULL;	/* Nothing to deallocate */
	icpState->buf = NULL;	/* Nothing to deallocate */
	icpSendERROR(fd,
	    ICP_ERROR_TIMEDOUT,
	    entry->mem_obj->e_abort_msg,
	    icpState);
	return;
    }
    icpState->entry = entry;
    icpSendMoreData(fd, icpState);
}

static void icpHandleStoreComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     void *data;
{
    icpStateData *icpState = (icpStateData *) data;
    StoreEntry *entry = NULL;

    entry = icpState->entry;
    debug(12, 5, "icpHandleStoreComplete: FD %d: sz %d: err %d: off %d: len %d: tsmp %d: lref %d.\n",
	fd, size, errflag,
	icpState->offset, entry->object_len,
	entry->timestamp, entry->lastref);

    icpFreeBufOrPage(icpState);
    if (errflag) {
	/* if runs in quick abort mode, set flag to tell 
	 * fetching module to abort the fetching */
	CheckQuickAbort(icpState);
	/* Log the number of bytes that we managed to read */
	CacheInfo->proto_touchobject(CacheInfo,
	    urlParseProtocol(entry->url),
	    icpState->offset);
	/* Now we release the entry and DON'T touch it from here on out */
	comm_close(fd);
    } else if (icpState->offset < entry->mem_obj->e_current_len) {
	/* More data available locally; write it now */
	icpSendMoreData(fd, icpState);
    } else if (icpState->offset == entry->object_len &&
	entry->store_status != STORE_PENDING) {
	/* We're finished case */
	CacheInfo->proto_touchobject(CacheInfo,
	    CacheInfo->proto_id(entry->url),
	    icpState->offset);
	comm_close(fd);
    } else {
	/* More data will be coming from primary server; register with 
	 * storage manager. */
	storeRegister(icpState->entry, fd, (PIF) icpHandleStore, (void *) icpState);
    }
}

static int icpGetHeadersForIMS(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    StoreEntry *entry = icpState->entry;
    MemObject *mem = entry->mem_obj;
    int buf_len = icpState->offset;
    int len;
    int max_len = 8191 - buf_len;
    char *p = icpState->buf + buf_len;
    char *IMS_hdr = NULL;
    time_t IMS;
    int IMS_length;
    time_t date;
    int length;

    if (max_len <= 0) {
	debug(12, 1, "icpGetHeadersForIMS: To much headers '%s'\n",
	    entry->key ? entry->key : entry->url);
	icpFreeBufOrPage(icpState);
	icpState->offset = 0;
	return icpProcessMISS(fd, icpState);
    }
    storeClientCopy(entry, icpState->offset, max_len, p, &len, fd);
    buf_len = icpState->offset = +len;

    if (!mime_headers_end(icpState->buf)) {
	/* All headers are not yet available, wait for more data */
	storeRegister(entry, fd, (PIF) icpHandleStoreIMS, (void *) icpState);
	return COMM_OK;
    }
    /* All headers are available, check if object is modified or not */
    IMS_hdr = mime_get_header(icpState->request_hdr, "If-Modified-Since");
    httpParseHeaders(icpState->buf, mem->reply);

    if (!IMS_hdr)
	fatal_dump("icpGetHeadersForIMS: Cant find IMS header in request\n");
    /* Restart the object from the beginning */
    icpState->offset = 0;

    /* Only objects with statuscode==200 can be "Not modified" */
    /* XXX: Should we ignore this? */
    if (mem->reply->code != 200)
	return icpProcessMISS(fd, icpState);
    p = strtok(IMS_hdr, ";");
    IMS = parse_rfc850(p);
    IMS_length = -1;
    while ((p = strtok(NULL, ";"))) {
	while (isspace(*p))
	    p++;
	if (strncasecmp(p, "length=", 7) == 0)
	    IMS_length = atoi(strchr(p, '=') + 1);
    }

    /* Find date when the object last was modified */
    if (*mem->reply->last_modified)
	date = parse_rfc850(mem->reply->last_modified);
    else if (*mem->reply->date)
	date = parse_rfc850(mem->reply->date);
    else
	date = entry->timestamp;

    /* Find size of the object */
    if (mem->reply->content_length)
	length = mem->reply->content_length;
    else
	length = entry->object_len - mime_headers_size(icpState->buf);

    /* Headers is no longer needed (they are parsed) */
    icpFreeBufOrPage(icpState);

    /* Compare with If-Modified-Since header */
    if (IMS > date || (IMS == date && (IMS_length < 0 || IMS_length == length))) {
	/* The object is not modified */
	debug(12, 4, "icpGetHeadersForIMS: Not modified '%s'\n", entry->url);
	comm_write(fd,
	    NotModified,
	    strlen(NotModified),
	    30,
	    icpHandleIMSComplete,
	    icpState);
	return COMM_OK;
    } else {
	debug(12, 4, "icpGetHeadersForIMS: We have newer '%s'\n", entry->url);
	/* We have a newer object */
	return icpProcessHIT(fd, icpState);
    }
}

static void icpHandleStoreIMS(fd, entry, icpState)
     int fd;
     StoreEntry *entry;
     icpStateData *icpState;
{
    icpGetHeadersForIMS(fd, icpState);
}

static void icpHandleIMSComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     void *data;
{
    icpStateData *icpState = data;
    StoreEntry *entry = icpState->entry;
    debug(12, 5, "icpHandleIMSComplete: Not Modified sent '%s'\n", entry->url);
    CacheInfo->proto_touchobject(CacheInfo,
	CacheInfo->proto_id(entry->url),
	strlen(buf));
    /* Set up everything for the logging */
    storeUnlockObject(entry);
    icpState->entry = NULL;
    icpState->size = strlen(buf);
    icpState->http_code = 304;
    comm_close(fd);
}

/*
 * Below, we check whether the object is a hit or a miss.  If it's a hit,
 * we check whether the object is still valid or whether it is a MISS_TTL.
 */
static void icp_hit_or_miss(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    char *url = icpState->url;
    char *pubkey = NULL;
    StoreEntry *entry = NULL;
    request_t *request = icpState->request;

    debug(12, 4, "icp_hit_or_miss: %s <URL:%s>\n",
	RequestMethodStr[icpState->method],
	url);
    if (icpState->method == METHOD_CONNECT) {
	icpState->log_type = LOG_TCP_MISS;
	sslStart(fd,
	    url,
	    icpState->request,
	    icpState->request_hdr,
	    &icpState->size);
	return;
    }
    if (icpCachable(icpState))
	BIT_SET(request->flags, REQ_CACHABLE);
    if (icpHierarchical(icpState))
	BIT_SET(request->flags, REQ_HIERARCHICAL);

    debug(12, 5, "icp_hit_or_miss: REQ_NOCACHE = %s\n",
	BIT_TEST(request->flags, REQ_NOCACHE) ? "SET" : "NOT SET");
    debug(12, 5, "icp_hit_or_miss: REQ_CACHABLE = %s\n",
	BIT_TEST(request->flags, REQ_CACHABLE) ? "SET" : "NOT SET");
    debug(12, 5, "icp_hit_or_miss: REQ_HIERARCHICAL = %s\n",
	BIT_TEST(request->flags, REQ_HIERARCHICAL) ? "SET" : "NOT SET");

    /* XXX hmm, should we check for IFMODSINCE and USER_REFRESH before
     * TCP_MISS?  It is possible to get IMS header for objects
     * not in the cache */

    pubkey = storeGeneratePublicKey(icpState->url, icpState->method);
    if ((entry = storeGet(pubkey)) == NULL) {
	/* This object isn't in the cache.  We do not hold a lock yet */
	icpState->log_type = LOG_TCP_MISS;
    } else if (!storeEntryValidToSend(entry)) {
	/* The object is in the cache, but is not valid */
	/* Eject old cached object */
	storeRelease(entry);
	entry = NULL;
	icpState->log_type = LOG_TCP_EXPIRED;
    } else if (BIT_TEST(request->flags, REQ_NOCACHE)) {
	/* IMS+NOCACHE should not eject valid object */
	if (!BIT_TEST(request->flags, REQ_IMS))
	    storeRelease(entry);
	entry = NULL;
	icpState->log_type = LOG_TCP_USER_REFRESH;
    } else if (BIT_TEST(request->flags, REQ_IMS)) {
	/* A cached IMS request */
	icpState->log_type = LOG_TCP_IFMODSINCE;
    } else {
	icpState->log_type = LOG_TCP_HIT;
    }

    /* Lock the object */
    if (entry != NULL && storeLockObject(entry, NULL, NULL) < 0) {
	storeRelease(entry);
	entry = NULL;
	icpState->log_type = LOG_TCP_SWAPIN_FAIL;
    }
    /* Reset header fields for  reply. */
    memset(&icpState->header, 0, sizeof(icp_common_t));
    icpState->header.version = ICP_VERSION_CURRENT;
    /* icpState->header.reqnum = 0; */
    icpState->header.shostid = 0;
    icpState->entry = entry;	/* Save a reference to the object */
    icpState->offset = 0;

    debug(12, 4, "icp_hit_or_miss: %s for '%s'\n",
	log_tags[icpState->log_type],
	icpState->url);

    if (entry != NULL) {
	CacheInfo->proto_hit(CacheInfo, CacheInfo->proto_id(entry->url));
	entry->refcount++;
    } else {
	CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
    }

    switch (icpState->log_type) {
    case LOG_TCP_HIT:
	icpProcessHIT(fd, icpState);
	break;
    case LOG_TCP_IFMODSINCE:
	icpProcessIMS(fd, icpState);
	break;
    default:
	icpProcessMISS(fd, icpState);
	break;
    }
}

/*
 * Send object as a cache hit
 */
static int icpProcessHIT(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    /* Send object to requestor */
    return icpSendMoreData(fd, icpState);
}


/*
 * Prepare to respond to a IMS request
 * This requires fetching the Last-Modified (or Date) header
 * and compare this with the request.
 * If the object is unmodified (older, or same date(+size))
 * respond with 304, else process as a HIT
 */
static int icpProcessIMS(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    /* Use buf as a temporary storage for mime headers */
    icpState->buf = xcalloc(8192, 1);
    /* And fetch headers */
    return icpGetHeadersForIMS(fd, icpState);
}


/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 */
static int icpProcessMISS(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    char *url = icpState->url;
    char *request_hdr = icpState->request_hdr;
    StoreEntry *entry = NULL;

    debug(12, 4, "icpProcessMISS: '%s %s'\n",
	RequestMethodStr[icpState->method], url);
    debug(12, 10, "icpProcessMISS: request_hdr:\n%s\n", request_hdr);

    /* Get rid of any references to a StoreEntry (if any) */
    if (icpState->entry) {
	storeUnregister(icpState->entry, fd);
	storeUnlockObject(icpState->entry);
	icpState->entry = NULL;
    }
    entry = storeCreateEntry(url,
	request_hdr,
	icpState->req_hdr_sz,
	icpState->request->flags,
	icpState->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */

    entry->refcount++;		/* MISS CASE */
    entry->mem_obj->fd_of_first_client = fd;
    fd_table[fd].store_entry = entry;
    BIT_SET(entry->flag, IP_LOOKUP_PENDING);

    /* Reset header fields for  reply. */
    memset(&icpState->header, 0, sizeof(icp_common_t));
    icpState->header.version = ICP_VERSION_CURRENT;
    /* icpState->header.reqnum = 0; */
    icpState->header.shostid = 0;
    icpState->entry = entry;
    icpState->offset = 0;

    /* Register with storage manager to receive updates when data comes in. */
    storeRegister(entry, fd, (PIF) icpHandleStore, (void *) icpState);
#if DELAY_HACK
    _delay_fetch = 0;
    if (aclCheck(DelayAccessList, icpState->peer.sin_addr, icpState->request))
	_delay_fetch = 1;
#endif
    return (protoDispatch(fd, url, icpState->entry, icpState->request));
}

static void icpLogIcp(queue)
     icpUdpData *queue;
{
    icp_common_t *header = (icp_common_t *) queue->msg;
    char *url = (char *) header + sizeof(icp_common_t);
    CacheInfo->log_append(CacheInfo,
	url,
	inet_ntoa(queue->address.sin_addr),
	queue->len,
	log_tags[queue->logcode],
	IcpOpcodeStr[ICP_OP_QUERY],
	0,
	tvSubMsec(queue->start, current_time),
	HIER_NONE);
}


int icpUdpReply(fd, queue)
     int fd;
     icpUdpData *queue;
{
    int result = COMM_OK;
    int x;
    /* Disable handler, in case of errors. */
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	0,
	0);
    while ((queue = UdpQueueHead)) {
	debug(12, 5, "icpUdpReply: FD %d sending %d bytes to %s port %d\n",
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
	    if (errno == EWOULDBLOCK || errno == EAGAIN)
		break;		/* don't de-queue */
	    else
		result = COMM_ERROR;
	}
	UdpQueueHead = queue->next;
	if (queue->logcode)
	    icpLogIcp(queue);
	safe_free(queue->msg);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (UdpQueueHead) {
	comm_set_select_handler(fd,
	    COMM_SELECT_WRITE,
	    (PF) icpUdpReply,
	    (void *) UdpQueueHead);
    }
    return result;
}

int icpUdpSend(fd, url, reqnum, to, flags, opcode, logcode)
     int fd;
     char *url;
     int reqnum;
     struct sockaddr_in *to;
     int flags;			/* icp_common_t->flags */
     icp_opcode opcode;
     log_type logcode;
{
    char *buf = NULL;
    int buf_len = sizeof(icp_common_t) + strlen(url) + 1;
    icp_common_t *headerp = NULL;
    icpUdpData *data = xmalloc(sizeof(icpUdpData));
    struct sockaddr_in our_socket_name;
    int sock_name_length = sizeof(our_socket_name);
    char *urloffset = NULL;

#ifdef CHECK_BAD_ADDRS
    if (to->sin_addr.s_addr == 0xFFFFFFFF) {
	debug(12, 0, "icpUdpSend: URL '%s'\n", url);
	fatal_dump("icpUdpSend: BAD ADDRESS: 255.255.255.255");
    }
#endif

    if (getsockname(fd, (struct sockaddr *) &our_socket_name,
	    &sock_name_length) == -1) {
	debug(12, 1, "icpUdpSend: FD %d: getsockname failure: %s\n",
	    fd, xstrerror());
	return COMM_ERROR;
    }
    memset(data, '\0', sizeof(icpUdpData));
    data->address = *to;

    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    if (opcode == ICP_OP_QUERY && !BIT_TEST(flags, REQ_NOCACHE)
	&& opt_udp_hit_obj)
	headerp->flags = htonl(ICP_FLAG_HIT_OBJ);
    headerp->flags = htonl(flags);
    headerp->pad = 0;
    /* xmemcpy(headerp->auth, , ICP_AUTH_SIZE); */
    headerp->shostid = htonl(our_socket_name.sin_addr.s_addr);
    debug(12, 5, "icpUdpSend: headerp->reqnum = %d\n", headerp->reqnum);

    urloffset = buf + sizeof(icp_common_t);

    if (opcode == ICP_OP_QUERY)
	urloffset += sizeof(u_num32);
    xmemcpy(urloffset, url, strlen(url));
    data->msg = buf;
    data->len = buf_len;
    data->start = current_time;
    data->logcode = logcode;

    debug(12, 4, "icpUdpSend: Queueing for %s: \"%s %s\"\n",
	inet_ntoa(to->sin_addr),
	IcpOpcodeStr[opcode],
	url);
    AppendUdp(data);
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) icpUdpReply,
	(void *) UdpQueueHead);
    return COMM_OK;
}

static void icpUdpSendEntry(fd, url, reqnum, to, opcode, entry, start_time)
     int fd;
     char *url;
     int reqnum;
     struct sockaddr_in *to;
     icp_opcode opcode;
     StoreEntry *entry;
     struct timeval start_time;
{
    char *buf = NULL;
    int buf_len;
    icp_common_t *headerp = NULL;
    icpUdpData *data = NULL;
    struct sockaddr_in our_socket_name;
    int sock_name_length = sizeof(our_socket_name);
    char *urloffset = NULL;
    char *entryoffset = NULL;
    MemObject *m = entry->mem_obj;
    u_short data_sz;
    int size;

    debug(12, 3, "icpUdpSendEntry: fd = %d\n", fd);
    debug(12, 3, "icpUdpSendEntry: url = '%s'\n", url);
    debug(12, 3, "icpUdpSendEntry: to = %s:%d\n", inet_ntoa(to->sin_addr), ntohs(to->sin_port));
    debug(12, 3, "icpUdpSendEntry: opcode = %d %s\n", opcode, IcpOpcodeStr[opcode]);
    debug(12, 3, "icpUdpSendEntry: entry = %p\n", entry);

    buf_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;

#ifdef CHECK_BAD_ADDRS
    if (to->sin_addr.s_addr == 0xFFFFFFFF) {
	debug(12, 0, "icpUdpSendEntry: URL '%s'\n", url);
	fatal_dump("icpUdpSend: BAD ADDRESS: 255.255.255.255");
    }
#endif

    if (getsockname(fd, (struct sockaddr *) &our_socket_name,
	    &sock_name_length) == -1) {
	debug(12, 1, "icpUdpSendEntry: FD %d: getsockname failure: %s\n",
	    fd, xstrerror());
	return;
    }
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    headerp->flags = htonl(ICP_FLAG_HIT_OBJ);
    headerp->shostid = htonl(our_socket_name.sin_addr.s_addr);
    urloffset = buf + sizeof(icp_common_t);
    xmemcpy(urloffset, url, strlen(url));
    data_sz = htons((u_short) entry->object_len);
    entryoffset = urloffset + strlen(url) + 1;
    xmemcpy(entryoffset, &data_sz, sizeof(u_short));
    entryoffset += sizeof(u_short);
    size = m->data->mem_copy(m->data, 0, entryoffset, entry->object_len);
    if (size != entry->object_len) {
	debug(12, 1, "icpUdpSendEntry: copy failed, wanted %d got %d bytes\n",
	    entry->object_len, size);
	safe_free(buf);
	return;
    }
    data = xcalloc(1, sizeof(icpUdpData));
    data->address = *to;
    data->msg = buf;
    data->len = buf_len;
    data->start = start_time;
    data->logcode = LOG_UDP_HIT_OBJ;
    debug(12, 4, "icpUdpSendEntry: Queueing for %s: \"%s %s\"\n",
	inet_ntoa(to->sin_addr),
	IcpOpcodeStr[opcode],
	url);
    AppendUdp(data);
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) icpUdpReply,
	(void *) UdpQueueHead);
}

static void icpHitObjHandler(errflag, data)
     int errflag;
     void *data;
{
    icpHitObjStateData *icpHitObjState = data;
    StoreEntry *entry = NULL;
    if (data == NULL)
	return;
    entry = icpHitObjState->entry;
    debug(12, 3, "icpHitObjHandler: '%s'\n", icpHitObjState->entry->url);
    if (!errflag) {
	icpUdpSendEntry(icpHitObjState->fd,
	    entry->url,
	    icpHitObjState->header.reqnum,
	    &icpHitObjState->to,
	    ICP_OP_HIT_OBJ,
	    icpHitObjState->entry,
	    icpHitObjState->started);
	CacheInfo->proto_hit(CacheInfo, CacheInfo->proto_id(entry->url));
    } else {
	debug(12, 3, "icpHitObjHandler: errflag=%d, aborted!\n", errflag);
    }
    storeUnlockObject(entry);
    safe_free(icpHitObjState);
}

static void icpHandleIcpV2(fd, from, buf, len)
     int fd;
     struct sockaddr_in from;
     char *buf;
     int len;
{
    icp_common_t header;
    icp_common_t *headerp = (icp_common_t *) buf;
    StoreEntry *entry = NULL;
    char *url = NULL;
    char *key = NULL;
    request_t *icp_request = NULL;
    int allow = 0;
    char *data = NULL;
    u_short data_sz = 0;
    u_short u;
    icpHitObjStateData *icpHitObjState = NULL;
    int pkt_len;

    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
    header.flags = ntohl(headerp->flags);
    /* xmemcpy(headerp->auth, , ICP_AUTH_SIZE); */
    header.shostid = ntohl(headerp->shostid);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	nudpconn++;
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_ERR,
		LOG_UDP_INVALID);
	    break;
	}
	allow = aclCheck(ICPAccessList, from.sin_addr, icp_request);
	put_free_request_t(icp_request);
	if (!allow) {
	    debug(12, 2, "icpHandleIcpV2: Access Denied for %s.\n",
		inet_ntoa(from.sin_addr));
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_DENIED,
		LOG_UDP_DENIED);
	    break;
	}
	/* The peer is allowed to use this cache */
	entry = storeGet(storeGeneratePublicKey(url, METHOD_GET));
	debug(12, 5, "icpHandleIcpV2: OPCODE %s\n", IcpOpcodeStr[header.opcode]);
	if (entry &&
	    (entry->store_status == STORE_OK) &&
	    (entry->expires > (squid_curtime + getNegativeTTL()))) {
	    pkt_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;
	    if (header.flags & ICP_FLAG_HIT_OBJ && pkt_len < SQUID_UDP_SO_SNDBUF) {
		icpHitObjState = xcalloc(1, sizeof(icpHitObjStateData));
		icpHitObjState->entry = entry;
		icpHitObjState->fd = fd;
		icpHitObjState->to = from;
		icpHitObjState->header = header;
		icpHitObjState->started = current_time;
		if (storeLockObject(entry, icpHitObjHandler, icpHitObjState) == 0)
		    break;
		/* else, problems */
		safe_free(icpHitObjState);
	    }
	    CacheInfo->proto_hit(CacheInfo, CacheInfo->proto_id(entry->url));
	    icpUdpSend(fd, url, header.reqnum, &from, 0, ICP_OP_HIT, LOG_UDP_HIT);
	    break;
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (store_rebuilding == STORE_REBUILDING_FAST && opt_reload_hit_only) {
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_RELOADING,
		LOG_UDP_RELOADING);
	} else if (hit_only_mode_until > squid_curtime) {
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_RELOADING,
		LOG_UDP_RELOADING);
	} else {
	    CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
	    icpUdpSend(fd, url, header.reqnum, &from, 0, ICP_OP_MISS, LOG_UDP_MISS);
	}
	break;

    case ICP_OP_HIT_OBJ:
    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:
    case ICP_OP_DENIED:
    case ICP_OP_RELOADING:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0, "icpHandleIcpV2: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0, "icpHandleIcpV2: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
	if (header.opcode == ICP_OP_HIT_OBJ) {
	    data = url + strlen(url) + 1;
	    xmemcpy((char *) &u, data, sizeof(u_short));
	    data += sizeof(u_short);
	    data_sz = ntohs(u);
	    if (data_sz > (len - (data - buf))) {
		debug(12, 0, "icpHandleIcpV2: ICP_OP_HIT_OBJ object too small\n");
		break;
	    }
	}
	debug(12, 3, "icpHandleIcpV2: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (neighbors_do_private_keys && header.reqnum) {
	    key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
	} else {
	    key = storeGeneratePublicKey(url, METHOD_GET);
	}
	debug(12, 3, "icpHandleIcpV2: Looking for key '%s'\n", key);
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3, "icpHandleIcpV2: Ignoring %s for NULL Entry.\n",
		IcpOpcodeStr[header.opcode]);
	} else if (entry->lock_count == 0) {
	    debug(12, 3, "icpHandleIcpV2: Ignoring %s for Entry without locks.\n",
		IcpOpcodeStr[header.opcode]);
	} else {
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
	break;

    default:
	debug(12, 0, "icpHandleIcpV2: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
}

/* Currently Harvest cached-2.x uses ICP_VERSION_3 */
static void icpHandleIcpV3(fd, from, buf, len)
     int fd;
     struct sockaddr_in from;
     char *buf;
     int len;
{
    icp_common_t header;
    icp_common_t *headerp = (icp_common_t *) buf;
    StoreEntry *entry = NULL;
    char *url = NULL;
    char *key = NULL;
    request_t *icp_request = NULL;
    int allow = 0;
    char *data = NULL;
    u_short data_sz = 0;
    u_short u;

    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
    header.flags = ntohl(headerp->flags);
    /* xmemcpy(headerp->auth, , ICP_AUTH_SIZE); */
    header.shostid = ntohl(headerp->shostid);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	nudpconn++;
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_INVALID,
		LOG_UDP_INVALID);
	    break;
	}
	allow = aclCheck(ICPAccessList, from.sin_addr, icp_request);
	put_free_request_t(icp_request);
	if (!allow) {
	    debug(12, 2, "icpHandleIcpV3: Access Denied for %s.\n",
		inet_ntoa(from.sin_addr));
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_DENIED,
		LOG_UDP_DENIED);
	    break;
	}
	/* The peer is allowed to use this cache */
	entry = storeGet(storeGeneratePublicKey(url, METHOD_GET));
	debug(12, 5, "icpHandleIcpV3: OPCODE %s\n", IcpOpcodeStr[header.opcode]);
	if (entry &&
	    (entry->store_status == STORE_OK) &&
	    (entry->expires > (squid_curtime + getNegativeTTL()))) {
	    CacheInfo->proto_hit(CacheInfo, CacheInfo->proto_id(entry->url));
	    icpUdpSend(fd, url, header.reqnum, &from, 0, ICP_OP_HIT, LOG_UDP_HIT);
	    break;
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (store_rebuilding == STORE_REBUILDING_FAST && opt_reload_hit_only) {
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_RELOADING,
		LOG_UDP_RELOADING);
	} else if (hit_only_mode_until > squid_curtime) {
	    icpUdpSend(fd,
		url,
		header.reqnum,
		&from,
		0,
		ICP_OP_RELOADING,
		LOG_UDP_RELOADING);
	} else {
	    CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
	    icpUdpSend(fd, url, header.reqnum, &from, 0, ICP_OP_MISS, LOG_UDP_MISS);
	}
	break;

    case ICP_OP_HIT_OBJ:
    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:
    case ICP_OP_DENIED:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0, "icpHandleIcpV3: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0, "icpHandleIcpV3: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
	if (header.opcode == ICP_OP_HIT_OBJ) {
	    data = url + strlen(url) + 1;
	    xmemcpy((char *) &u, data, sizeof(u_short));
	    data += sizeof(u_short);
	    data_sz = ntohs(u);
	    if (data_sz > (len - (data - buf))) {
		debug(12, 0, "icpHandleIcpV3: ICP_OP_HIT_OBJ object too small\n");
		break;
	    }
	}
	debug(12, 3, "icpHandleIcpV3: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (neighbors_do_private_keys && header.reqnum) {
	    key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
	} else {
	    key = storeGeneratePublicKey(url, METHOD_GET);
	}
	debug(12, 3, "icpHandleIcpV3: Looking for key '%s'\n", key);
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3, "icpHandleIcpV3: Ignoring %s for NULL Entry.\n",
		IcpOpcodeStr[header.opcode]);
	} else if (entry->lock_count == 0) {
	    debug(12, 3, "icpHandleIcpV3: Ignoring %s for Entry without locks.\n",
		IcpOpcodeStr[header.opcode]);
	} else {
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
	debug(12, 0, "icpHandleIcpV3: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
}

int icpHandleUdp(sock, not_used)
     int sock;
     void *not_used;
{
    int result = 0;
    struct sockaddr_in from;
    int from_len;
    static char buf[SQUID_UDP_SO_RCVBUF];
    int len;
    icp_common_t *headerp = NULL;
    int icp_version;

    from_len = sizeof(from);
    memset(&from, 0, from_len);
    len = comm_udp_recv(sock, buf, SQUID_UDP_SO_RCVBUF - 1, &from, &from_len);
    if (len < 0) {
	debug(12, 1, "icpHandleUdp: FD %d: error receiving.\n", sock);
	comm_set_select_handler(sock, COMM_SELECT_READ, icpHandleUdp, 0);
	return result;
    }
    buf[len] = '\0';
    debug(12, 4, "icpHandleUdp: FD %d: received %d bytes from %s.\n",
	sock,
	len,
	inet_ntoa(from.sin_addr));

    if (len < sizeof(icp_common_t)) {
	debug(12, 4, "icpHandleUdp: Bad sized UDP packet ignored. %d < %d\n",
	    len, sizeof(icp_common_t));
	comm_set_select_handler(sock, COMM_SELECT_READ, icpHandleUdp, 0);
	return result;
    }
    headerp = (icp_common_t *) (void *) buf;
    if ((icp_version = (int) headerp->version) == ICP_VERSION_2)
	icpHandleIcpV2(sock, from, buf, len);
    else if (icp_version == ICP_VERSION_3)
	icpHandleIcpV3(sock, from, buf, len);
    else
	debug(12, 0, "Unused ICP version %d received from %s:%d\n",
	    icp_version,
	    inet_ntoa(from.sin_addr),
	    ntohs(from.sin_port));

    comm_set_select_handler(sock,
	COMM_SELECT_READ,
	icpHandleUdp,
	0);
    return result;
}

static char *do_append_domain(url, ad)
     char *url;
     char *ad;
{
    char *b = NULL;		/* beginning of hostname */
    char *e = NULL;		/* end of hostname */
    char *p = NULL;
    char *u = NULL;
    int lo;
    int ln;
    int adlen;

    if (!(b = strstr(url, "://")))	/* find beginning of host part */
	return NULL;
    b += 3;
    if (!(e = strchr(b, '/')))	/* find end of host part */
	e = b + strlen(b);
    if ((p = strchr(b, '@')) && p < e)	/* After username info */
	b = p + 1;
    if ((p = strchr(b, ':')) && p < e)	/* Before port */
	e = p;
    if ((p = strchr(b, '.')) && p < e)	/* abort if host has dot already */
	return NULL;
    lo = strlen(url);
    ln = lo + (adlen = strlen(ad));
    u = xcalloc(ln + 1, 1);
    strncpy(u, url, (e - url));	/* copy first part */
    b = u + (e - url);
    p = b + adlen;
    strncpy(b, ad, adlen);	/* copy middle part */
    strncpy(p, e, lo - (e - url));	/* copy last part */
    return (u);
}


/*
 *  parseHttpRequest()
 * 
 *  Called by
 *    asciiProcessInput() after the request has been read
 *  Calls
 *    mime_process()
 *    do_append_domain()
 *  Returns
 *   -1 on error
 *    0 on incomplete request
 *    1 on success
 */
static int parseHttpRequest(icpState)
     icpStateData *icpState;
{
    char *inbuf = NULL;
    char *method = NULL;
    char *url = NULL;
    char *req_hdr = NULL;
    static char http_ver[32];
    char *token = NULL;
    char *t = NULL;
    char *ad = NULL;
    char *post_data = NULL;
    int free_request = 0;
    int content_length;
    int req_hdr_sz;
    int post_sz;
    int len;

    /* Make sure a complete line has been received */
    if (strchr(icpState->inbuf, '\n') == NULL) {
	debug(12, 5, "Incomplete request line, waiting for more data\n");
	return 0;
    }
    /* Use xmalloc/xmemcpy instead of xstrdup because inbuf might
     * contain NULL bytes; especially for POST data  */
    inbuf = xmalloc(icpState->offset + 1);
    xmemcpy(inbuf, icpState->inbuf, icpState->offset);
    *(inbuf + icpState->offset) = '\0';

    /* Look for request method */
    if ((method = strtok(inbuf, "\t ")) == NULL) {
	debug(12, 1, "parseHttpRequest: Can't get request method\n");
	xfree(inbuf);
	return -1;
    }
    icpState->method = urlParseMethod(method);
    if (icpState->method == METHOD_NONE) {
	debug(12, 1, "parseHttpRequest: Unsupported method '%s'\n", method);
	xfree(inbuf);
	return -1;
    }
    debug(12, 5, "parseHttpRequest: Method is '%s'\n", method);

    /* look for URL */
    if ((url = strtok(NULL, "\r\n\t ")) == NULL) {
	debug(12, 1, "parseHttpRequest: Missing URL\n");
	xfree(inbuf);
	return -1;
    }
    debug(12, 5, "parseHttpRequest: Request is '%s'\n", url);

    token = strtok(NULL, "");
    for (t = token; t && *t && *t != '\n' && *t != '\r'; t++);
    if (t && *t && t != token) {
	len = (int) (t - token);
	memset(http_ver, '\0', 32);
	strncpy(http_ver, token, len < 31 ? len : 31);
    } else {
	strcpy(http_ver, "HTTP/0.9");
    }
    debug(12, 5, "parseHttpRequest: HTTP version is '%s'\n", http_ver);

    req_hdr = t;
    req_hdr_sz = icpState->offset - (req_hdr - inbuf);

    /* Check if headers are received */
    if (req_hdr == NULL || !mime_headers_end(req_hdr)) {
	xfree(inbuf);
	return 0;		/* not a complete request */
    }
    /* Ok, all headers are received */
    icpState->req_hdr_sz = req_hdr_sz;
    icpState->request_hdr = xmalloc(req_hdr_sz + 1);
    xmemcpy(icpState->request_hdr, req_hdr, req_hdr_sz);
    *(icpState->request_hdr + req_hdr_sz) = '\0';

    debug(12, 5, "parseHttpRequest: Request Header is\n---\n%s\n---\n",
	icpState->request_hdr);

    if (icpState->method == METHOD_POST || icpState->method == METHOD_PUT) {
	/* Expect Content-Length: and POST data after the headers */
	if ((t = mime_get_header(req_hdr, "Content-Length")) == NULL) {
	    debug(12, 2, "POST without Content-Length\n");
	    xfree(inbuf);
	    return -1;
	}
	content_length = atoi(t);
	debug(12, 3, "parseHttpRequest: Expecting POST/PUT Content-Length of %d\n",
	    content_length);
	if (!(post_data = mime_headers_end(req_hdr))) {
	    debug(12, 1, "parseHttpRequest: Can't find end of headers in POST/PUT request?\n");
	    xfree(inbuf);
	    return 0;		/* not a complete request */
	}
	post_sz = icpState->offset - (post_data - inbuf);
	debug(12, 3, "parseHttpRequest: Found POST/PUT Content-Length of %d\n",
	    post_sz);
	if (post_sz < content_length) {
	    xfree(inbuf);
	    return 0;
	}
    }
    /* Assign icpState->url */
    if ((t = strchr(url, '\n')))	/* remove NL */
	*t = '\0';
    if ((t = strchr(url, '\r')))	/* remove CR */
	*t = '\0';
    if ((t = strchr(url, '#')))	/* remove HTML anchors */
	*t = '\0';

    if ((ad = getAppendDomain())) {
	if ((t = do_append_domain(url, ad))) {
	    if (free_request)
		safe_free(url);
	    url = t;
	    free_request = 1;
	    /* NOTE: We don't have to free the old request pointer
	     * because it points to inside inbuf. But
	     * do_append_domain() allocates new memory so set a flag
	     * if the request should be freed later. */
	}
    }
    /* see if we running in httpd_accel_mode, if so got to convert it to URL */
    if (httpd_accel_mode && *url == '/') {
	if (!vhost_mode) {
	    /* prepend the accel prefix */
	    icpState->url = xcalloc(strlen(getAccelPrefix()) +
		strlen(url) +
		1, 1);
	    sprintf(icpState->url, "%s%s", getAccelPrefix(), url);
	} else {
	    /* Put the local socket IP address as the hostname */
	    icpState->url = xcalloc(strlen(url) + 32, 1);
	    sprintf(icpState->url, "http://%s:%d%s",
		inet_ntoa(icpState->me.sin_addr),
		getAccelPort(),
		url);
	    debug(12, 5, "VHOST REWRITE: '%s'\n", icpState->url);
	}
	icpState->accel = 1;
    } else {
	/* URL may be rewritten later, so make extra room */
	icpState->url = xcalloc(strlen(url) + 5, 1);
	strcpy(icpState->url, url);
	icpState->accel = 0;
    }

    debug(12, 5, "parseHttpRequest: Complete request received\n");
    if (free_request)
	safe_free(url);
    xfree(inbuf);
    return 1;
}

static int icpAccessCheck(icpState)
     icpStateData *icpState;
{
    request_t *r = icpState->request;
    if (httpd_accel_mode && !getAccelWithProxy() && r->protocol != PROTO_CACHEOBJ) {
	/* this cache is an httpd accelerator ONLY */
	if (icpState->accel == 0)
	    return 0;
    }
    return aclCheck(HTTPAccessList, icpState->peer.sin_addr, r);
}

#define ASCII_INBUF_BLOCKSIZE 4096
/*
 * asciiProcessInput()
 * 
 * Handler set by
 *   asciiHandleConn()
 * Called by
 *   comm_select() when data has been read
 * Calls
 *   parseAsciiUrl()
 *   icp_hit_or_miss()
 *   icpSendERROR()
 */
static void asciiProcessInput(fd, buf, size, flag, data)
     int fd;
     char *buf;
     int size;
     int flag;
     void *data;
{
    icpStateData *icpState = (icpStateData *) data;
    static char client_msg[64];
    int parser_return_code = 0;
    int k;
    request_t *request = NULL;

    debug(12, 4, "asciiProcessInput: FD %d: reading request...\n", fd);
    debug(12, 4, "asciiProcessInput: size = %d\n", size);

    if (flag != COMM_OK) {
	/* connection closed by foreign host */
	comm_close(fd);
	return;
    }
    icpState->offset += size;
    icpState->inbuf[icpState->offset] = '\0';	/* Terminate the string */

    parser_return_code = parseHttpRequest(icpState);
    if (parser_return_code == 1) {
	if ((request = urlParse(icpState->method, icpState->url)) == NULL) {
	    debug(12, 5, "Invalid URL: %s\n", icpState->url);
	    icpState->log_type = ERR_INVALID_URL;
	    icpState->http_code = 400;
	    icpState->buf = xstrdup(squid_error_url(icpState->url,
		    icpState->method,
		    ERR_INVALID_URL,
		    fd_table[fd].ipaddr,
		    icpState->http_code,
		    NULL));
	    icpState->ptr_to_4k_page = NULL;
	    comm_write(fd,
		icpState->buf,
		strlen(icpState->buf),
		30,
		icpSendERRORComplete,
		(void *) icpState);
	    return;
	}
	if (!urlCheckRequest(request)) {
	    icpState->log_type = ERR_UNSUP_REQ;
	    icpState->http_code = 501;
	    icpState->buf = xstrdup(squid_error_url(icpState->url,
		    icpState->method,
		    ERR_UNSUP_REQ,
		    fd_table[fd].ipaddr,
		    icpState->http_code,
		    NULL));
	    icpState->ptr_to_4k_page = NULL;
	    comm_write(fd,
		icpState->buf,
		strlen(icpState->buf),
		30,
		icpSendERRORComplete,
		(void *) icpState);
	    return;
	}
	icpState->request = requestLink(request);
	if (!icpAccessCheck(icpState)) {
	    debug(12, 5, "Access Denied: %s\n", icpState->url);
	    icpState->log_type = LOG_TCP_DENIED;
	    icpState->http_code = 403;
	    icpState->buf = xstrdup(access_denied_msg(icpState->http_code,
		    icpState->method,
		    icpState->url,
		    fd_table[fd].ipaddr));
	    icpState->ptr_to_4k_page = NULL;
	    comm_write(fd,
		icpState->buf,
		strlen(tmp_error_buf),
		30,
		icpSendERRORComplete,
		(void *) icpState);
	    icpState->log_type = LOG_TCP_DENIED;
	    return;
	}
	/* The request is good, let's go... */
	urlCanonical(icpState->request, icpState->url);
	icpParseRequestHeaders(icpState);
	sprintf(client_msg, "%16.16s %-4.4s %-40.40s",
	    fd_note(fd, 0),
	    RequestMethodStr[icpState->method],
	    icpState->url);
	fd_note(fd, client_msg);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) icpDetectClientClose,
	    (void *) icpState);
	icp_hit_or_miss(fd, icpState);
    } else if (parser_return_code == 0) {
	/*
	 *    Partial request received; reschedule until parseAsciiUrl()
	 *    is happy with the input
	 */
	k = icpState->inbufsize - 1 - icpState->offset;
	if (k == 0) {
	    if (icpState->offset >= getMaxRequestSize()) {
		/* The request is too large to handle */
		debug(12, 0, "asciiProcessInput: Request won't fit in buffer.\n");
		debug(12, 0, "-->     max size = %d\n", getMaxRequestSize());
		debug(12, 0, "--> icpState->offset = %d\n", icpState->offset);
		icpState->buf = NULL;
		icpState->ptr_to_4k_page = NULL;
		icpSendERROR(fd, ICP_ERROR_INTERNAL, "error reading request", icpState);
		return;
	    }
	    /* Grow the request memory area to accomodate for a large request */
	    icpState->inbufsize += ASCII_INBUF_BLOCKSIZE;
	    icpState->inbuf = xrealloc(icpState->inbuf, icpState->inbufsize);
	    meta_data.misc += ASCII_INBUF_BLOCKSIZE;
	    debug(12, 2, "Handling a large request, offset=%d inbufsize=%d\n",
		icpState->offset, icpState->inbufsize);
	    k = icpState->inbufsize - 1 - icpState->offset;
	}
	comm_read(fd,
	    icpState->inbuf + icpState->offset,
	    k,			/* size */
	    30,			/* timeout */
	    TRUE,		/* handle immed */
	    asciiProcessInput,
	    (void *) icpState);
    } else {
	/* parser returned -1 */
	debug(12, 1, "asciiProcessInput: FD %d Invalid Request\n", fd);
	icpState->log_type = ERR_INVALID_REQ;
	icpState->http_code = 400;
	icpState->buf = xstrdup(squid_error_request(icpState->inbuf,
		ERR_INVALID_REQ,
		fd_table[fd].ipaddr,
		icpState->http_code));
	comm_write(fd,
	    icpState->buf,
	    strlen(icpState->buf),
	    30,
	    icpSendERRORComplete,
	    (void *) icpState);
    }
}


/* general lifetime handler for ascii connection */
static void asciiConnLifetimeHandle(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    debug(12, 2, "asciiConnLifetimeHandle: FD %d: lifetime is expired.\n", fd);
    CheckQuickAbort(icpState);
    /* Unregister us from the dnsserver pending list and cause a DNS
     * related storeAbort() for other attached clients.  If this
     * doesn't succeed, then the fetch has already started for this
     * URL. */
    if (icpState->entry && icpState->url)
	protoUndispatch(fd, icpState->url, icpState->entry, icpState->request);
    comm_close(fd);
}

/* Handle a new connection on ascii input socket. */
int asciiHandleConn(sock, notused)
     int sock;
     void *notused;
{
    int fd = -1;
    int lft = -1;
    icpStateData *icpState = NULL;
    struct sockaddr_in peer;
    struct sockaddr_in me;

    memset((char *) &peer, '\0', sizeof(struct sockaddr_in));
    memset((char *) &me, '\0', sizeof(struct sockaddr_in));
    if ((fd = comm_accept(sock, &peer, &me)) < 0) {
	debug(12, 1, "asciiHandleConn: FD %d: accept failure: %s\n",
	    sock, xstrerror());
	comm_set_select_handler(sock, COMM_SELECT_READ, asciiHandleConn, 0);
	return -1;
    }
    /* set the hardwired lifetime */
    lft = comm_set_fd_lifetime(fd, getClientLifetime());
    ntcpconn++;

    debug(12, 4, "asciiHandleConn: FD %d: accepted (lifetime %d).\n", fd, lft);
    fd_note(fd, inet_ntoa(peer.sin_addr));

    icpState = xcalloc(1, sizeof(icpStateData));
    icpState->start = current_time;
    icpState->inbufsize = ASCII_INBUF_BLOCKSIZE;
    icpState->inbuf = xcalloc(icpState->inbufsize, 1);
    icpState->header.shostid = htonl(peer.sin_addr.s_addr);
    icpState->peer = peer;
    icpState->me = me;
    icpState->entry = NULL;
    meta_data.misc += ASCII_INBUF_BLOCKSIZE;
    comm_set_select_handler(fd,
	COMM_SELECT_LIFETIME,
	(PF) asciiConnLifetimeHandle,
	(void *) icpState);
    comm_add_close_handler(fd,
	(PF) icpStateFree,
	(void *) icpState);
    comm_read(fd,
	icpState->inbuf,
	icpState->inbufsize - 1,	/* size */
	30,			/* timeout */
	1,			/* handle immed */
	asciiProcessInput,
	(void *) icpState);
    comm_set_select_handler(sock,
	COMM_SELECT_READ,
	asciiHandleConn,
	0);
    return 0;
}

void AppendUdp(item)
     icpUdpData *item;
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

static void CheckQuickAbort(icpState)
     icpStateData *icpState;
{
    if (icpState->entry == NULL)
	return;
    if (storePendingNClients(icpState->entry) > 1)
	return;
    if (icpState->entry->store_status == STORE_OK)
	return;
    if (!getQuickAbort() &&
	BIT_TEST(icpState->request->flags, REQ_CACHABLE) &&
	!BIT_TEST(icpState->entry->flag, KEY_PRIVATE))
	return;
    BIT_SET(icpState->entry->flag, CLIENT_ABORT_REQUEST);
    storeReleaseRequest(icpState->entry);
    icpState->log_type = ERR_CLIENT_ABORT;
}

static void icpDetectClientClose(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    static char buf[256];
    int n;
    StoreEntry *entry = icpState->entry;
    errno = 0;
    n = read(fd, buf, 256);
    if (n > 0) {
	debug(12, 0, "icpDetectClientClose: FD %d, %d unexpected bytes\n",
	    fd, n);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) icpDetectClientClose,
	    (void *) icpState);
    } else if (n < 0) {
	debug(12, 5, "icpDetectClientClose: FD %d\n", fd);
	debug(12, 5, "--> URL '%s'\n", icpState->url);
	if (errno == ECONNRESET)
	    debug(12, 2, "icpDetectClientClose: ERROR %s\n", xstrerror());
	else
	    debug(12, 1, "icpDetectClientClose: ERROR %s\n", xstrerror());
	CheckQuickAbort(icpState);
	if (entry && icpState->url)
	    protoUndispatch(fd, icpState->url, entry, icpState->request);
	if (entry && entry->ping_status == PING_WAITING)
	    storeReleaseRequest(entry);
	comm_close(fd);
    } else if (entry != NULL && icpState->offset == entry->object_len &&
	entry->store_status != STORE_PENDING) {
	/* All data has been delivered */
	debug(12, 5, "icpDetectClientClose: FD %d end of transmission\n", fd);
	CacheInfo->proto_touchobject(CacheInfo,
	    CacheInfo->proto_id(entry->url),
	    icpState->offset);
	comm_close(fd);
    } else {
	debug(12, 5, "icpDetectClientClose: FD %d closed?\n", fd);
	comm_set_stall(fd, 60);	/* check again in a minute */
    }
}
