/* $Id$ */

/*
 * DEBUG: Section 12          icp:
 */

#include "squid.h"

int neighbors_do_private_keys = 1;

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
#ifdef UDP_HIT_WITH_OBJ
    "UDP_HIT_OBJ",
#endif
    "UDP_MISS",
    "UDP_DENIED",
    "UDP_INVALID",
    "ERR_READ_TIMEOUT",
    "ERR_LIFETIME_EXP",
    "ERR_NO_CLIENTS_BIG_OBJ",
    "ERR_READ_ERROR",
    "ERR_CLIENT_ABORT",
    "ERR_CONNECT_FAIL",
    "ERR_INVALID_REQ",
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
    StoreEntry *entry;
    long offset;
    int log_type;
    int http_code;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    char *ptr_to_4k_page;
    char *buf;
    struct timeval start;
    int flags;
    int size;			/* hack for CONNECT which doesnt use sentry */
} icpStateData;

static icpUdpData *UdpQueueHead = NULL;
static icpUdpData *UdpQueueTail = NULL;
#define ICP_SENDMOREDATA_BUF SM_PAGE_SIZE

#ifdef UDP_HIT_WITH_OBJ
typedef struct {
    int fd;
    struct sockaddr_in to;
    StoreEntry *entry;
    icp_common_t header;
    struct timeval started;
} icpHitObjStateData;

#endif

/* Local functions */
static void icpHandleStore _PARAMS((int, StoreEntry *, icpStateData *));
static void icpHandleStoreComplete _PARAMS((int, char *, int, int, void *icpState));
static int icpProcessMISS _PARAMS((int, icpStateData *));
static void CheckQuickAbort _PARAMS((icpStateData *));
#ifdef UDP_HIT_WITH_OBJ
static void icpHitObjHandler _PARAMS((int, void *));
#endif
static void icpLogIcp _PARAMS((icpUdpData *));
static void icpDetectClientClose _PARAMS((int, icpStateData *));

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

    if (!icpState)
	return 1;
    if (icpState->log_type < LOG_TAG_NONE || icpState->log_type > ERR_ZERO_SIZE_OBJECT)
	fatal_dump("icpStateFree: icpState->log_type out of range.");
    if (icpState->entry) {
	size = icpState->entry->mem_obj->e_current_len;
    } else {
	size = icpState->size;	/* hack added for CONNECT objects */
    }
    if (icpState->entry) {
	http_code = icpState->entry->mem_obj->reply->code;
    } else {
	http_code = icpState->http_code;
    }
    elapsed_msec = tvSubMsec(icpState->start, current_time);
    CacheInfo->log_append(CacheInfo,
	icpState->url,
	inet_ntoa(icpState->peer.sin_addr),
	size,
	log_tags[icpState->log_type],
	RequestMethodStr[icpState->method],
	http_code,
	elapsed_msec);
    safe_free(icpState->inbuf);
    safe_free(icpState->url);
    safe_free(icpState->request_hdr);
    if (icpState->entry) {
	storeUnregister(icpState->entry, fd);
	storeUnlockObject(icpState->entry);
	icpState->entry = NULL;
    }
    if (icpState->request && --icpState->request->link_count == 0)
	safe_free(icpState->request);
    icpFreeBufOrPage(icpState);
    safe_free(icpState);
    return 0;			/* XXX gack, all comm handlers return ints */
}

static void icpParseRequestHeaders(icpState)
     icpStateData *icpState;
{
    char *request_hdr = icpState->request_hdr;
    char *t = NULL;
    if (mime_get_header(request_hdr, "If-Modified-Since"))
	BIT_SET(icpState->flags, REQ_IMS);
    if ((t = mime_get_header(request_hdr, "Pragma"))) {
	if (!strcasecmp(t, "no-cache"))
	    BIT_SET(icpState->flags, REQ_NOCACHE);
    }
    if (mime_get_header(request_hdr, "Authorization"))
	BIT_SET(icpState->flags, REQ_AUTH);
}

static int icpCachable(icpState)
     icpStateData *icpState;
{
    char *request = icpState->url;
    request_t *req = icpState->request;
    method_t method = req->method;
    if (BIT_TEST(icpState->flags, REQ_AUTH))
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
    char *request = icpState->url;
    request_t *req = icpState->request;
    method_t method = req->method;
    wordlist *p = NULL;
    if (BIT_TEST(icpState->flags, REQ_IMS))
	return 0;
    if (BIT_TEST(icpState->flags, REQ_AUTH))
	return 0;
    if (method != METHOD_GET)
	return 0;
    if (req->protocol == PROTO_HTTP)
	return httpCachable(request, method);
    if (req->protocol == PROTO_FTP)
	return ftpCachable(request);
    if (req->protocol == PROTO_GOPHER)
	return gopherCachable(request);
    if (req->protocol == PROTO_WAIS)
	return 0;
    if (req->protocol == PROTO_CACHEOBJ)
	return 0;
    /* scan hierarchy_stoplist */
    for (p = getHierarchyStoplist(); p; p = p->next)
	if (strstr(request, p->key))
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
    if (port != getAsciiPortNum()) {
	sprintf(tmp_error_buf, "icpSendERROR: FD %d unexpected port %hd.",
	    fd, port);
	fatal_dump(tmp_error_buf);
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
	memcpy(scanbuf, buf, len > 19 ? 19 : len);
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

    debug(12, 4, "icp_hit_or_miss: %s <URL:%s>\n",
	RequestMethodStr[icpState->method],
	url);

    if (icpState->method == METHOD_CONNECT) {
	icpState->log_type = LOG_TCP_MISS;
	sslStart(fd, url, icpState->request, icpState->request_hdr, &icpState->size);
	return;
    }
    if (icpCachable(icpState))
	BIT_SET(icpState->flags, REQ_CACHABLE);
    if (icpHierarchical(icpState))
	BIT_SET(icpState->flags, REQ_HIERARCHICAL);

    debug(12, 5, "icp_hit_or_miss: REQ_NOCACHE = %s\n",
	BIT_TEST(icpState->flags, REQ_NOCACHE) ? "SET" : "NOT SET");
    debug(12, 5, "icp_hit_or_miss: REQ_CACHABLE = %s\n",
	BIT_TEST(icpState->flags, REQ_CACHABLE) ? "SET" : "NOT SET");
    debug(12, 5, "icp_hit_or_miss: REQ_HIERARCHICAL = %s\n",
	BIT_TEST(icpState->flags, REQ_HIERARCHICAL) ? "SET" : "NOT SET");

    /* XXX hmm, should we check for IFMODSINCE and USER_REFRESH before
     * TCP_MISS?  It is possible to get IMS header for objects
     * not in the cache */

    pubkey = storeGeneratePublicKey(icpState->url, icpState->method);
    if ((entry = storeGet(pubkey)) == NULL) {
	/* This object isn't in the cache.  We do not hold a lock yet */
	icpState->log_type = LOG_TCP_MISS;
	CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
	icpProcessMISS(fd, icpState);
	return;
    }
    /* The object is in the cache, but is it valid? */
    if (!storeEntryValidToSend(entry)) {
	storeRelease(entry);
	icpState->log_type = LOG_TCP_EXPIRED;
    } else if (BIT_TEST(icpState->flags, REQ_IMS)) {
	/* no storeRelease() here because this request will always
	 * start private (IMS clears HIERARCHICAL) */
	/* check IMS before nocache so IMS+NOCACHE won't eject valid object */
	icpState->log_type = LOG_TCP_IFMODSINCE;
    } else if (BIT_TEST(icpState->flags, REQ_NOCACHE)) {
	storeRelease(entry);
	icpState->log_type = LOG_TCP_USER_REFRESH;
    } else if (storeLockObject(entry, NULL, NULL) < 0) {
	storeRelease(entry);
	icpState->log_type = LOG_TCP_SWAPIN_FAIL;
    } else {
	icpState->log_type = LOG_TCP_HIT;
    }

    debug(12, 4, "icp_hit_or_miss: %s for '%s'\n",
	log_tags[icpState->log_type],
	icpState->url);
    switch (icpState->log_type) {
    case LOG_TCP_HIT:
	/* We HOLD a lock on object "entry" */
	CacheInfo->proto_hit(CacheInfo, CacheInfo->proto_id(entry->url));

	/* Reset header for reply. */
	memset(&icpState->header, 0, sizeof(icp_common_t));
	icpState->header.version = ICP_VERSION_CURRENT;
	/* icpState->header.reqnum = 0; */
	icpState->header.shostid = 0;
	icpState->entry = entry;
	icpState->offset = 0;

	/* Send object to requestor */
	entry->refcount++;	/* HIT CASE */

	icpSendMoreData(fd, icpState);
	break;
    default:
	CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
	icpProcessMISS(fd, icpState);
	break;
    }
}

/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 * The calling client should NOT hold a lock on object at this
 * time, as we're about to release any TCP_MISS version of the object.
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

    entry = storeCreateEntry(url,
	request_hdr,
	icpState->flags,
	icpState->method);

    entry->refcount++;		/* MISS CASE */
    entry->mem_obj->fd_of_first_client = fd;
    fd_table[fd].store_entry = entry;
    BIT_SET(entry->flag, IP_LOOKUP_PENDING);
    storeLockObject(entry, NULL, NULL);

    /* Reset header fields for  reply. */
    memset(&icpState->header, 0, sizeof(icp_common_t));
    icpState->header.version = ICP_VERSION_CURRENT;
    /* icpState->header.reqnum = 0; */
    icpState->header.shostid = 0;
    icpState->entry = entry;
    icpState->offset = 0;

    /* Register with storage manager to receive updates when data comes in. */
    storeRegister(entry, fd, (PIF) icpHandleStore, (void *) icpState);

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
	tvSubMsec(queue->start, current_time));
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

int icpUdpSend(fd, url, reqheaderp, to, opcode, logcode)
     int fd;
     char *url;
     icp_common_t *reqheaderp;
     struct sockaddr_in *to;
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
    memcpy(&data->address, to, sizeof(struct sockaddr_in));

    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqheaderp->reqnum);
#ifdef UDP_HIT_WITH_OBJ
    if (opcode == ICP_OP_QUERY)
	headerp->flags = htonl(ICP_FLAG_HIT_OBJ);
    headerp->pad = 0;
#else
/*  memcpy(headerp->auth, , ICP_AUTH_SIZE); */
#endif
    headerp->shostid = htonl(our_socket_name.sin_addr.s_addr);
    debug(12, 5, "icpUdpSend: headerp->reqnum = %d\n", headerp->reqnum);

    urloffset = buf + sizeof(icp_common_t);

    if (opcode == ICP_OP_QUERY)
	urloffset += sizeof(u_num32);
    /* it's already zero filled by xcalloc */
    memcpy(urloffset, url, strlen(url));
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

#ifdef UDP_HIT_WITH_OBJ
static void icpUdpSendEntry(fd, url, reqheaderp, to, opcode, entry, start_time)
     int fd;
     char *url;
     icp_common_t *reqheaderp;
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
    headerp->reqnum = htonl(reqheaderp->reqnum);
    headerp->flags = htonl(ICP_FLAG_HIT_OBJ);
    headerp->shostid = htonl(our_socket_name.sin_addr.s_addr);
    urloffset = buf + sizeof(icp_common_t);
    memcpy(urloffset, url, strlen(url));
    data_sz = htons((u_short) entry->object_len);
    entryoffset = urloffset + strlen(url) + 1;
    memcpy(entryoffset, &data_sz, sizeof(u_short));
    entryoffset += sizeof(u_short);
    size = m->data->mem_copy(m->data, 0, entryoffset, entry->object_len);
    if (size != entry->object_len) {
	debug(12, 1, "icpUdpSendEntry: copy failed, wanted %d got %d bytes\n",
	    entry->object_len, size);
	safe_free(buf);
	return;
    }
    data = xcalloc(1, sizeof(icpUdpData));
    memcpy(&data->address, to, sizeof(struct sockaddr_in));
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

#endif

#ifdef UDP_HIT_WITH_OBJ
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
	    &icpHitObjState->header,
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
#endif

int icpHandleUdp(sock, not_used)
     int sock;
     void *not_used;
{
    int result = 0;
    struct sockaddr_in from;
    int from_len;
    static char buf[SQUID_UDP_SO_RCVBUF];
    int len;
    icp_common_t header;
    icp_common_t *headerp = NULL;
    StoreEntry *entry = NULL;
    char *url = NULL;
    char *key = NULL;
    request_t *icp_request = NULL;
    int allow = 0;
    char *data = NULL;
    u_short data_sz = 0;
#ifdef UDP_HIT_WITH_OBJ
    u_short u;
    icpHitObjStateData *icpHitObjState = NULL;
    int pkt_len;
#endif

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
    /* Get fields from incoming message. */
    headerp = (icp_common_t *) (void *) buf;
    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
#ifdef UDP_HIT_WITH_OBJ
    header.flags = ntohl(headerp->flags);
#else
    /*  memcpy(headerp->auth, , ICP_AUTH_SIZE); */
#endif
    header.shostid = ntohl(headerp->shostid);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	nudpconn++;
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    icpUdpSend(sock, url, &header, &from, ICP_OP_INVALID, LOG_UDP_INVALID);
	    break;
	}
	allow = aclCheck(ICPAccessList,
	    from.sin_addr,
	    icp_request->method,
	    icp_request->protocol,
	    icp_request->host,
	    icp_request->port,
	    icp_request->urlpath);
	safe_free(icp_request);
	if (!allow) {
	    debug(12, 2, "icpHandleUdp: Access Denied for %s.\n",
		inet_ntoa(from.sin_addr));
	    icpUdpSend(sock, url, &header, &from, ICP_OP_DENIED, LOG_UDP_DENIED);
	    break;
	}
	/* The peer is allowed to use this cache */
	entry = storeGet(storeGeneratePublicKey(url, METHOD_GET));
	debug(12, 5, "icpHandleUdp: OPCODE %s\n", IcpOpcodeStr[header.opcode]);
	if (entry &&
	    (entry->store_status == STORE_OK) &&
	    (entry->expires > (squid_curtime + getNegativeTTL()))) {
#ifdef UDP_HIT_WITH_OBJ
	    pkt_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;
	    if (header.flags & ICP_FLAG_HIT_OBJ && pkt_len < SQUID_UDP_SO_SNDBUF) {
		icpHitObjState = xcalloc(1, sizeof(icpHitObjStateData));
		icpHitObjState->entry = entry;
		icpHitObjState->fd = sock;
		icpHitObjState->to = from;
		icpHitObjState->header = header;
		icpHitObjState->started = current_time;
		if (storeLockObject(entry, icpHitObjHandler, icpHitObjState) == 0)
		    break;
		/* else, problems */
		safe_free(icpHitObjState);
	    }
#endif
	    CacheInfo->proto_hit(CacheInfo,
		CacheInfo->proto_id(entry->url));
	    icpUdpSend(sock, url, &header, &from, ICP_OP_HIT, LOG_UDP_HIT);
	    break;
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (opt_reload_hit_only && store_rebuilding == STORE_REBUILDING_FAST) {
	    icpUdpSend(sock,
		url,
		&header,
		&from,
		ICP_OP_DENIED,
		LOG_UDP_DENIED);
	    break;
	}
	CacheInfo->proto_miss(CacheInfo,
	    CacheInfo->proto_id(url));
	icpUdpSend(sock, url, &header, &from, ICP_OP_MISS, LOG_UDP_MISS);
	break;


#ifdef UDP_HIT_WITH_OBJ
    case ICP_OP_HIT_OBJ:
#endif
    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:
    case ICP_OP_DENIED:

	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0, "icpHandleUdp: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0, "icpHandleUdp: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
#ifdef UDP_HIT_WITH_OBJ
	if (header.opcode == ICP_OP_HIT_OBJ) {
	    data = url + strlen(url) + 1;
	    memcpy((char *) &u, data, sizeof(u_short));
	    data += sizeof(u_short);
	    data_sz = ntohs(u);
	    if (data_sz > (len - (data - buf))) {
		debug(12, 0, "icpHandleUdp: ICP_OP_HIT_OBJ object too small\n");
		break;
	    }
	}
#endif
	debug(12, 3, "icpHandleUdp: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (neighbors_do_private_keys && header.reqnum) {
	    key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
	} else {
	    key = storeGeneratePublicKey(url, METHOD_GET);
	}
	debug(12, 3, "icpHandleUdp: Looking for key '%s'\n", key);
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3, "icpHandleUdp: Ignoring %s for NULL Entry.\n",
		IcpOpcodeStr[header.opcode]);
	} else if (entry->lock_count == 0) {
	    debug(12, 3, "icpHandleUdp: Ignoring %s for Entry without locks.\n",
		IcpOpcodeStr[header.opcode]);
	} else {
	    neighborsUdpAck(sock, url, &header, &from, entry, data, (int) data_sz);
	}
	break;

    default:
	debug(12, 0, "icpHandleUdp: UNKNOWN OPCODE: %d\n", header.opcode);
	break;
    }

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
    char *request = NULL;
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
	debug(12, 5, "Incomplete request line, waiting for more data");
	return 0;
    }
    /* Use xmalloc/memcpy instead of xstrdup because inbuf might
     * contain NULL bytes; especially for POST data  */
    inbuf = xmalloc(icpState->offset + 1);
    memcpy(inbuf, icpState->inbuf, icpState->offset);
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
    BIT_SET(icpState->flags, REQ_HTML);

    /* look for URL */
    if ((request = strtok(NULL, "\r\n\t ")) == NULL) {
	debug(12, 1, "parseHttpRequest: Missing URL\n");
	xfree(inbuf);
	return -1;
    }
    debug(12, 5, "parseHttpRequest: Request is '%s'\n", request);

    token = strtok(NULL, "");
    for (t = token; t && *t && *t != '\n' && *t != '\r'; t++);
    if (t == NULL || *t == '\0' || t == token) {
	debug(12, 3, "parseHttpRequest: Missing HTTP identifier\n");
	xfree(inbuf);
	return -1;
    }
    len = (int) (t - token);
    memset(http_ver, '\0', 32);
    strncpy(http_ver, token, len < 31 ? len : 31);
    debug(12, 5, "parseHttpRequest: HTTP version is '%s'\n", http_ver);

    req_hdr = t;
    req_hdr_sz = icpState->offset - (req_hdr - inbuf);

    /* The request is received when a empty header line is receied */
    if (!strstr(req_hdr, "\r\n\r\n") && !strstr(req_hdr, "\n\n")) {
	xfree(inbuf);
	return 0;		/* not a complete request */
    }
    /* Ok, all headers are received */
    icpState->request_hdr = xmalloc(req_hdr_sz + 1);
    memcpy(icpState->request_hdr, req_hdr, req_hdr_sz);
    *(icpState->request_hdr + req_hdr_sz) = '\0';

    debug(12, 5, "parseHttpRequest: Request Header is\n---\n%s\n---\n",
	icpState->request_hdr);

    if (icpState->method == METHOD_POST) {
	/* Expect Content-Length: and POST data after the headers */
	if ((t = mime_get_header(req_hdr, "Content-Length")) == NULL) {
	    debug(12, 2, "POST without Content-Length\n");
	    xfree(inbuf);
	    return -1;
	}
	content_length = atoi(t);
	debug(12, 3, "parseHttpRequest: Expecting POST Content-Length of %d\n",
	    content_length);
	if ((t = strstr(req_hdr, "\r\n\r\n"))) {
	    post_data = t + 4;
	} else if ((t = strstr(req_hdr, "\n\n"))) {
	    post_data = t + 2;
	} else {
	    debug(12, 1, "parseHttpRequest: Can't find end of headers in POST request?\n");
	    xfree(inbuf);
	    return 0;		/* not a complete request */
	}
	post_sz = icpState->offset - (post_data - inbuf);
	debug(12, 3, "parseHttpRequest: Found POST Content-Length of %d\n",
	    post_sz);
	if (post_sz < content_length) {
	    xfree(inbuf);
	    return 0;
	}
    }
    /* Assign icpState->url */
    if ((t = strchr(request, '\n')))	/* remove NL */
	*t = '\0';
    if ((t = strchr(request, '\r')))	/* remove CR */
	*t = '\0';
    if ((t = strchr(request, '#')))	/* remove HTML anchors */
	*t = '\0';

    if ((ad = getAppendDomain())) {
	if ((t = do_append_domain(request, ad))) {
	    if (free_request)
		safe_free(request);
	    request = t;
	    free_request = 1;
	    /* NOTE: We don't have to free the old request pointer
	     * because it points to inside inbuf. But
	     * do_append_domain() allocates new memory so set a flag
	     * if the request should be freed later. */
	}
    }
    /* see if we running in httpd_accel_mode, if so got to convert it to URL */
    if (httpd_accel_mode && *request == '/') {
	if (!vhost_mode) {
	    /* prepend the accel prefix */
	    icpState->url = xcalloc(strlen(getAccelPrefix()) +
		strlen(request) +
		1, 1);
	    sprintf(icpState->url, "%s%s", getAccelPrefix(), request);
	} else {
	    /* Put the local socket IP address as the hostname */
	    icpState->url = xcalloc(strlen(request) + 24, 1);
	    sprintf(icpState->url, "http://%s:%d%s",
		inet_ntoa(icpState->me.sin_addr),
		getAccelPort(),
		request);
	    debug(12, 0, "VHOST REWRITE: '%s'\n", icpState->url);
	}
	BIT_SET(icpState->flags, REQ_ACCEL);
    } else {
	icpState->url = xstrdup(request);
	BIT_RESET(icpState->flags, REQ_ACCEL);
    }

    debug(12, 5, "parseHttpRequest: Complete request received\n");
    if (free_request)
	safe_free(request);
    xfree(inbuf);
    return 1;
}

static int icpAccessCheck(icpState)
     icpStateData *icpState;
{
    request_t *r = icpState->request;
    if (httpd_accel_mode && !getAccelWithProxy() && r->protocol != PROTO_CACHEOBJ) {
	/* this cache is an httpd accelerator ONLY */
	if (!BIT_TEST(icpState->flags, REQ_ACCEL))
	    return 0;
    }
    return aclCheck(HTTPAccessList,
	icpState->peer.sin_addr,
	r->method,
	r->protocol,
	r->host,
	r->port,
	r->urlpath);
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
	if ((icpState->request = urlParse(icpState->method, icpState->url)) == NULL) {
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
	icpState->request->link_count++;
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
    comm_set_select_handler(fd,
	COMM_SELECT_LIFETIME,
	(PF) asciiConnLifetimeHandle,
	(void *) icpState);
    comm_set_select_handler(fd,
	COMM_SELECT_CLOSE,
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
    if (icpState->entry->lock_count != 1)
	return;
    if (icpState->entry->store_status == STORE_OK)
	return;
    if (!getQuickAbort() &&
	BIT_TEST(icpState->flags, REQ_CACHABLE) &&
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
    n = read(fd, buf, 256);
    if (n > 0) {
	debug(12, 0, "icpDetectClientClose: FD %d, %d unexpected bytes\n",
	    fd, n);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) icpDetectClientClose,
	    (void *) icpState);
	return;
    }
    if (n == 0 && entry != NULL && icpState->offset == entry->object_len &&
	entry->store_status != STORE_PENDING) {
	/* All data has been delivered */
	debug(12, 5, "icpDetectClientClose: FD %d end of transmission\n", fd);
	CacheInfo->proto_touchobject(CacheInfo,
	    CacheInfo->proto_id(entry->url),
	    icpState->offset);
	comm_close(fd);
    } else {
	debug(12, 5, "icpDetectClientClose: FD %d\n", fd);
	debug(12, 5, "--> URL '%s'\n", icpState->url);
	if (n < 0) {
	    switch (errno) {
	    case ECONNRESET:
		debug(12, 2, "icpDetectClientClose: ERROR %s\n", xstrerror());
		break;
	    default:
		debug(12, 1, "icpDetectClientClose: ERROR %s\n", xstrerror());
		break;
	    }
	}
	CheckQuickAbort(icpState);
	if (entry && icpState->url)
	    protoUndispatch(fd, icpState->url, entry, icpState->request);
	if (entry && entry->ping_status == WAITING)
	    storeReleaseRequest(entry);
	comm_close(fd);
    }
}
