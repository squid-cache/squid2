

/* $Id$ */

/*
 * DEBUG: Section 12          icp:
 */

#include "squid.h"

int neighbors_do_private_keys = 1;

static char *log_tags[] =
{
    "LOG_TAG_MIN",
    "TCP_HIT",
    "TCP_MISS",
    "TCP_EXPIRED",
    "TCP_REFRESH",
    "TCP_IFMODSINCE",
    "TCP_SWAPFAIL",
    "TCP_BLOCK",
    "TCP_DENIED",
    "UDP_HIT",
    "UDP_MISS",
    "UDP_DENIED",
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
    "ERR_URL_BLOCKED",
    "ERR_ZERO_SIZE_OBJECT"
};

typedef struct iwd {
    icp_common_t header;	/* Allows access to previous header */
#ifdef NOTUSED_CODE
    u_num32 query_host;
#endif
    char *url;
    char *inbuf;
    int inbufsize;
    int method;			/* GET, POST, ... */
    char *request_hdr;		/* Mime header */
    StoreEntry *entry;
    long offset;
#ifdef NOT_NEEDED_CODE
    int bytes_needed;		/*  Used for content_length */
#endif
    int log_type;
    int http_code;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    char *ptr_to_4k_page;
    char *buf;
    struct timeval start;
    int flags;
} icpStateData;

static icpUdpData *UdpQueueHead = NULL;
static icpUdpData *UdpQueueTail = NULL;
#define ICP_MAX_UDP_SIZE 4096
#define ICP_SENDMOREDATA_BUF SM_PAGE_SIZE

#if !defined(UDP_HIT_THRESH)
#define UDP_HIT_THRESH 300
#endif

typedef void (*complete_handler) _PARAMS((int fd, char *buf, int size, int errflag, void *data));
typedef struct ireadd {
    int fd;
    char *buf;
    long size;
    long offset;
    int timeout;		/* XXX Not used at present. */
    time_t time;
    complete_handler handler;
    void *client_data;
} icpReadWriteData;

/* Local functions */
static void icpHandleStore _PARAMS((int, StoreEntry *, icpStateData *));
static void icpHandleStoreComplete _PARAMS((int, char *, int, int, icpStateData *));
static int icpProcessMISS _PARAMS((int, icpStateData *, char *key));
static void CheckQuickAbort _PARAMS((icpStateData *));

static void icpFreeBufOrPage(icpState)
     icpStateData *icpState;
{
    if (icpState->ptr_to_4k_page && icpState->buf)
	fatal_dump("icpFreeBufOrPage: Shouldn't have both a 4k ptr and a string");
    if (icpState->ptr_to_4k_page)
	put_free_4k_page(icpState->ptr_to_4k_page);
    else
	safe_free(icpState->buf);
    icpState->ptr_to_4k_page = icpState->buf = NULL;
}


static void icpCloseAndFree(fd, icpState, line)
     int fd;
     icpStateData *icpState;
     int line;			/* __LINE__ number of caller */
{
    int size = 0;
    int http_code = 0;
    int elapsed_msec;

    if (fd > 0)
	comm_close(fd);
    if (!icpState) {
	sprintf(tmp_error_buf, "icpCloseAndFree: Called with NULL icpState from %s line %d", __FILE__, line);
	fatal_dump(tmp_error_buf);
    }
    if (icpState->log_type < LOG_TAG_MIN || icpState->log_type > ERR_ZERO_SIZE_OBJECT)
	fatal_dump("icpCloseAndFree: icpState->log_type out of range.");
    if (icpState->entry) {
	size = icpState->entry->mem_obj->e_current_len;
	http_code = icpState->entry->mem_obj->reply->code;
    } else {
	http_code = icpState->http_code;
    }
    elapsed_msec = (current_time.tv_sec - icpState->start.tv_sec) * 1000 +
	(current_time.tv_usec - icpState->start.tv_usec) / 1000;
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
    safe_free(icpState);
}

int icpCachable(icpState)
     icpStateData *icpState;
{
    char *request_hdr = icpState->request_hdr;
    char *request = icpState->url;
    int method = icpState->method;
    char *t = NULL;

    if (mime_get_header(request_hdr, "If-Modified-Since")) {
	BIT_SET(icpState->flags, REQ_IMS);
	return 0;
    }
    if ((t = mime_get_header(request_hdr, "Pragma"))) {
	BIT_SET(icpState->flags, REQ_NOCACHE);
	if (strcasecmp(t, "no-cache"))
	    return 0;
    }
    if (mime_get_header(request_hdr, "Authorization")) {
	BIT_SET(icpState->flags, REQ_AUTH);
	return 0;
    }
    if (!strncasecmp(request, "http://", 7))
	return httpCachable(request, method, request_hdr);
    if (!strncasecmp(request, "ftp://", 6))
	return ftpCachable(request);
    if (!strncasecmp(request, "gopher://", 9))
	return gopherCachable(request);
    if (!strncasecmp(request, "wais://", 7))
	return 0;
    if (!strncasecmp(request, "cache_object://", 15))
	return 0;
    return 1;
}

/* Read from FD. */
int icpHandleRead(fd, rw_state_machine)
     int fd;
     icpReadWriteData *rw_state_machine;
{
    int len = read(fd, rw_state_machine->buf + rw_state_machine->offset,
	rw_state_machine->size - rw_state_machine->offset);

    if (len <= 0) {
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	    /* reschedule self */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) icpHandleRead,
		(void *) rw_state_machine);
	    return COMM_OK;
	default:
	    /* Len == 0 means connection closed; otherwise,  would not have been
	     * called by comm_select(). */
	    debug(12, 1, "icpHandleRead: FD %d: read failure: %s\n",
		fd, len == 0 ? "connection closed" : xstrerror());
	    rw_state_machine->handler(fd,
		rw_state_machine->buf,
		rw_state_machine->offset,
		COMM_ERROR,
		rw_state_machine->client_data);
	    safe_free(rw_state_machine);
	    return COMM_ERROR;
	}
    }
    rw_state_machine->offset += len;

    /* Check for \r\n delimiting end of ascii transmission, or */
    /* if we've read content-length bytes already */
    if ((rw_state_machine->offset >= rw_state_machine->size)
	|| (strstr(rw_state_machine->buf, "\r\n") != (char *) NULL)) {
	rw_state_machine->handler(fd,
	    rw_state_machine->buf,
	    rw_state_machine->offset,
	    COMM_OK,
	    rw_state_machine->client_data);
	safe_free(rw_state_machine);
    } else {
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) icpHandleRead,
	    (void *) rw_state_machine);
    }

    return COMM_OK;
}

/* Select for reading on FD, until SIZE bytes are received.  Call
 * HANDLER when complete. */
void icpRead(fd, bin_mode, buf, size, timeout, handler, client_data)
     int fd;
     int bin_mode;
     char *buf;
     int size;
     int timeout;
     void (*handler) _PARAMS((int fd, char *buf, int size, int errflag, void *data));
     void *client_data;
{
    icpReadWriteData *data = NULL;
    data = (icpReadWriteData *) xcalloc(1, sizeof(icpReadWriteData));
    data->fd = fd;
    data->buf = buf;
    data->size = size;
    data->offset = 0;
    data->handler = handler;
    data->timeout = timeout;
    data->time = cached_curtime;
    data->client_data = client_data;
    comm_set_select_handler(fd,
	COMM_SELECT_READ,
	(PF) icpHandleRead,
	(void *) data);
}

/* Write to FD. */
void icpHandleWrite(fd, rwsm)
     int fd;
     icpReadWriteData *rwsm;
{
    int len = 0;
    int nleft;

    debug(12, 5, "icpHandleWrite: FD %d: off %d: sz %d.\n",
	fd, rwsm->offset, rwsm->size);

    nleft = rwsm->size - rwsm->offset;
    len = write(fd, rwsm->buf + rwsm->offset, nleft);

    if (len == 0) {
	/* We're done */
	if (nleft != 0)
	    debug(12, 2, "icpHandleWrite: FD %d: write failure: connection closed with %d bytes remaining.\n", fd, nleft);
	rwsm->handler(fd,
	    rwsm->buf,
	    rwsm->offset,
	    nleft == 0 ? COMM_OK : COMM_ERROR,
	    rwsm->client_data);
	safe_free(rwsm);
	return;
    }
    if (len < 0) {
	/* An error */
	if (errno == EWOULDBLOCK || errno == EAGAIN) {
	    /* XXX: Re-install the handler rather than giving up. I hope
	     * this doesn't freeze this socket due to some random OS bug
	     * returning EWOULDBLOCK indefinitely.  Ought to maintain a
	     * retry count in rwsm? */
	    debug(12, 10, "icpHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) icpHandleWrite,
		(void *) rwsm);
	    return;
	}
	debug(12, 2, "icpHandleWrite: FD %d: write failure: %s.\n",
	    fd, xstrerror());
	rwsm->handler(fd,
	    rwsm->buf,
	    rwsm->offset,
	    COMM_ERROR,
	    rwsm->client_data);
	safe_free(rwsm);
	return;
    }
    /* A successful write, continue */
    rwsm->offset += len;
    if (rwsm->offset < rwsm->size) {
	/* Reinstall the read handler and get some more */
	comm_set_select_handler(fd,
	    COMM_SELECT_WRITE,
	    (PF) icpHandleWrite,
	    (void *) rwsm);
	return;
    }
    rwsm->handler(fd,
	rwsm->buf,
	rwsm->offset,
	COMM_OK,
	rwsm->client_data);
    safe_free(rwsm);
}



/* Select for Writing on FD, until SIZE bytes are sent.  Call
 * HANDLER when complete. */
char *icpWrite(fd, buf, size, timeout, handler, client_data)
     int fd;
     char *buf;
     int size;
     int timeout;
     void (*handler) _PARAMS((int fd, char *buf, int size, int errflag, void *data));
     void *client_data;
{
    icpReadWriteData *data = NULL;

    debug(12, 5, "icpWrite: FD %d: sz %d: tout %d: hndl %p: data %p.\n",
	fd, size, timeout, handler, client_data);

    data = (icpReadWriteData *) xcalloc(1, sizeof(icpReadWriteData));
    data->fd = fd;
    data->buf = buf;
    data->size = size;
    data->offset = 0;
    data->handler = handler;
    data->timeout = timeout;
    data->time = cached_curtime;
    data->client_data = client_data;
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) icpHandleWrite,
	(void *) data);
    return ((char *) data);
}

void icpSendERRORComplete(fd, buf, size, errflag, state)
     int fd;
     char *buf;
     int size;
     int errflag;
     icpStateData *state;
{
    StoreEntry *entry = NULL;
    debug(12, 4, "icpSendERRORComplete: FD %d: sz %d: err %d.\n",
	fd, size, errflag);

    /* Clean up client side statemachine */
    entry = state->entry;
    icpFreeBufOrPage(state);
    icpCloseAndFree(fd, state, __LINE__);

    /* If storeAbort() has been called, then we don't execute this.
     * If we timed out on the client side, then we need to
     * unregister/unlock */
    if (entry) {
	storeUnregister(entry, fd);
	storeUnlockObject(entry);
    }
}

/* Send ERROR message. */
int icpSendERROR(fd, errorCode, msg, state)
     int fd;
     int errorCode;
     char *msg;
     icpStateData *state;
{
    char *buf = NULL;
    int buf_len = 0;
    int port = 0;

    port = comm_port(fd);
    debug(12, 4, "icpSendERROR: code %d: port %d: msg: '%s'\n",
	errorCode, port, msg);

    if (port == COMM_ERROR) {
	/* This file descriptor isn't bound to a socket anymore.
	 * It probably timed out. */
	debug(12, 2, "icpSendERROR: COMM_ERROR msg: %80.80s\n", msg);
	icpCloseAndFree(fd, state, __LINE__);
	return COMM_ERROR;
    }
    if (port != getAsciiPortNum()) {
	sprintf(tmp_error_buf, "icpSendERROR: FD %d unexpected port %d.",
	    fd, port);
	fatal_dump(tmp_error_buf);
    }
    /* Error message for the ascii port */
    buf_len = strlen(msg);
    buf_len = buf_len > 4095 ? 4095 : buf_len;
    buf = state->ptr_to_4k_page = get_free_4k_page();
    state->buf = NULL;
    strcpy(buf, msg);
    *(buf + buf_len) = '\0';
    icpWrite(fd, buf, buf_len, 30, icpSendERRORComplete, (void *) state);
    return COMM_OK;
}

/* Send available data from an object in the cache.  This is called either
 * on select for  write or directly by icpHandleStore. */

int icpSendMoreData(fd, state)
     int fd;
     icpStateData *state;
{
    StoreEntry *entry = state->entry;
    char *buf = NULL;
    char *p = NULL;
    icp_common_t *header = &state->header;
    int buf_len;
    int len;
    int max_len = 0;
    int result = COMM_ERROR;
    int tcode = 555;
    double http_ver;
    static char scanbuf[20];

    debug(12, 5, "icpSendMoreData: <URL:%s> sz %d: len %d: off %d.\n",
	entry->url, entry->object_len,
	entry->mem_obj ? entry->mem_obj->e_current_len : 0, state->offset);

    p = state->ptr_to_4k_page = buf = get_free_4k_page();
    state->buf = NULL;

    /* Set maxlen to largest amount of data w/o header
     * place p pointing to beginning of data portion of message */

    buf_len = 0;		/* No header for ascii mode */

    max_len = ICP_SENDMOREDATA_BUF - buf_len;
    /* Should limit max_len to something like 1.5x last successful write */
    p += buf_len;

    storeClientCopy(state->entry, state->offset, max_len, p, &len, fd);

    buf_len += len;

    if (state->offset == 0 && entry->mem_obj->reply->code == 0 && len > 0) {
	memset(scanbuf, '\0', 20);
	memcpy(scanbuf, buf, 20);
	sscanf(scanbuf, "HTTP/%lf %d", &http_ver, &tcode);
	entry->mem_obj->reply->code = tcode;
    }
    if ((state->offset == 0) && (header->opcode != ICP_OP_DATABEG)) {
	header->opcode = ICP_OP_DATABEG;
    } else if ((entry->mem_obj->e_current_len == entry->object_len) &&
	    ((entry->object_len - state->offset) == len) &&
	(entry->status != STORE_PENDING)) {
	/* No more data; this is the last message. */
	header->opcode = ICP_OP_DATAEND;
    } else {
	/* We know there is more data to come. */
	header->opcode = ICP_OP_DATA;
    }
    debug(12, 6, "icpSendMoreData: opcode %d: len %d.\n",
	header->opcode, entry->object_len);

    header->length = buf_len;

    state->offset += len;

    /* Do this here, so HandleStoreComplete can tell whether more data 
     * needs to be sent. */
    icpWrite(fd, buf, buf_len, 30, icpHandleStoreComplete, (void *) state);
    result = COMM_OK;
    return result;
}

/* Called by storage manager when more data arrives from source. 
 * Starts state machine towards client with new batch of data or
 * error messages.  We get here by invoking the handlers in the
 * pending list.
 */
static void icpHandleStore(fd, entry, state)
     int fd;
     StoreEntry *entry;
     icpStateData *state;
{
    debug(12, 5, "icpHandleStore: FD %d: off %d: <URL:%s>\n",
	fd, state->offset, entry->url);

    if (entry->status == STORE_ABORTED) {
	state->log_type = entry->mem_obj->abort_code;
	debug(12, 3, "icpHandleStore: abort_code=%d\n", entry->mem_obj->abort_code);
	state->ptr_to_4k_page = NULL;	/* Nothing to deallocate */
	state->buf = NULL;	/* Nothing to deallocate */
	icpSendERROR(fd,
	    ICP_ERROR_TIMEDOUT,
	    entry->mem_obj->e_abort_msg,
	    state);
	return;
    }
    state->entry = entry;
    icpSendMoreData(fd, state);
}

void icpHandleStoreComplete(fd, buf, size, errflag, state)
     int fd;
     char *buf;
     int size;
     int errflag;
     icpStateData *state;
{
    StoreEntry *entry = NULL;

    entry = state->entry;
    debug(12, 5, "icpHandleStoreComplete: FD %d: sz %d: err %d: off %d: len %d: tsmp %d: lref %d.\n",
	fd, size, errflag,
	state->offset, entry->object_len,
	entry->timestamp, entry->lastref);

    icpFreeBufOrPage(state);
    if (errflag) {
	/* if runs in quick abort mode, set flag to tell 
	 * fetching module to abort the fetching */
	CheckQuickAbort(state);
	/* Log the number of bytes that we managed to read */
	CacheInfo->proto_touchobject(CacheInfo,
	    urlParseProtocol(entry->url),
	    state->offset);
	/* Now we release the entry and DON'T touch it from here on out */
	icpCloseAndFree(fd, state, __LINE__);
	storeUnregister(entry, fd);
	storeUnlockObject(entry);
    } else if (state->offset < entry->mem_obj->e_current_len) {
	/* More data available locally; write it now */
	icpSendMoreData(fd, state);
    } else
	/* We're finished case */
	if (state->offset == entry->object_len &&
	entry->status != STORE_PENDING) {
	CacheInfo->proto_touchobject(CacheInfo,
	    CacheInfo->proto_id(entry->url),
	    state->offset);
	icpCloseAndFree(fd, state, __LINE__);
	storeUnregister(entry, fd);
	storeUnlockObject(entry);	/* unlock after icpClose.. */
    } else {
	/* More data will be coming from primary server; register with 
	 * storage manager. */
	storeRegister(state->entry, fd, (PIF) icpHandleStore, (void *) state);
    }
}

int icpDoQuery(fd, state)
     int fd;
     icpStateData *state;
{
    state->buf = state->ptr_to_4k_page = NULL;	/* Nothing to free */
    /* XXX not implemented over tcp. */
    icpSendERROR(fd,
	ICP_ERROR_INTERNAL,
	"not implemented over tcp",
	state);
    return COMM_OK;
}

/*
 * Below, we check whether the object is a hit or a miss.  If it's a hit,
 * we check whether the object is still valid or whether it is a MISS_TTL.
 */
void icp_hit_or_miss(fd, usm)
     int fd;
     icpStateData *usm;
{
    char *url = usm->url;
    char *pubkey = NULL;
    StoreEntry *entry = NULL;
    int lock = 0;

    debug(12, 4, "icp_hit_or_miss: %s <URL:%s>\n",
	RequestMethodStr[usm->method],
	url);

    pubkey = storeGeneratePublicKey(usm->url, usm->method);
    if ((entry = storeGet(pubkey)) == NULL) {
	/* This object isn't in the cache.  We do not hold a lock yet */
	usm->log_type = LOG_TCP_MISS;
	CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
	icpProcessMISS(fd, usm, pubkey);
	return;
    }
    /* The object is in the cache, but is it valid? */
    if (!storeEntryValidToSend(entry))
	usm->log_type = LOG_TCP_EXPIRED;
    else if (BIT_TEST(usm->flags, REQ_NOCACHE))
	usm->log_type = LOG_TCP_USER_REFRESH;
    else if (BIT_TEST(usm->flags, REQ_IMS))
	usm->log_type = LOG_TCP_IFMODSINCE;
    else if ((lock = storeLockObject(entry)) < 0)
	usm->log_type = LOG_TCP_SWAPIN_FAIL;
    else
	usm->log_type = LOG_TCP_HIT;

    debug(12, 4, "icp_hit_or_miss: %s for '%s'\n",
	log_tags[usm->log_type],
	usm->url);
    switch (usm->log_type) {
    case LOG_TCP_HIT:
	/* We HOLD a lock on object "entry" */
	CacheInfo->proto_hit(CacheInfo, CacheInfo->proto_id(entry->url));

	/* Reset header for reply. */
	memset(&usm->header, 0, sizeof(icp_common_t));
	usm->header.version = ICP_VERSION_CURRENT;
	/* usm->header.reqnum = 0; */
	usm->header.shostid = 0;
	usm->entry = entry;
	usm->offset = 0;

	/* Send object to requestor */
	entry->refcount++;	/* HIT CASE */

	icpSendMoreData(fd, usm);
	break;
    default:
	CacheInfo->proto_miss(CacheInfo, CacheInfo->proto_id(url));
	icpProcessMISS(fd, usm, pubkey);
	break;
    }
}

/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 * The calling client should NOT hold a lock on object at this
 * time, as we're about to release any TCP_MISS version of the object.
 */
static int icpProcessMISS(fd, usm, key)
     int fd;
     icpStateData *usm;
     char *key;
{
    char *url = usm->url;
    char *request_hdr = usm->request_hdr;
    StoreEntry *entry = NULL;

    debug(12, 4, "icpProcessMISS: '%s %s'\n",
	RequestMethodStr[usm->method], url);
    debug(12, 10, "icpProcessMISS: request_hdr:\n%s\n", request_hdr);

    if ((entry = storeGet(key))) {
	debug(12, 4, "icpProcessMISS: key '%s' already exists, moving.\n", key);
	/* get rid of the old entry */
	if (storeEntryLocked(entry)) {
	    /* change original hash key to get out of the new object's way */
	    if (!storeOriginalKey(entry))
		fatal_dump("ProcessMISS: Object located by changed key?");
	    storeSetPrivateKey(entry);
	} else {
	    storeRelease(entry);
	}
    }
    entry = storeCreateEntry(url,
	request_hdr,
	usm->flags,
	usm->method);

    entry->refcount++;		/* MISS CASE */
    entry->mem_obj->fd_of_first_client = fd;
    fd_table[fd].store_entry = entry;
    BIT_SET(entry->flag, IP_LOOKUP_PENDING);
    storeLockObject(entry);

    /* Reset header fields for  reply. */
    memset(&usm->header, 0, sizeof(icp_common_t));
    usm->header.version = ICP_VERSION_CURRENT;
    /* usm->header.reqnum = 0; */
    usm->header.shostid = 0;
    usm->entry = entry;
    usm->offset = 0;

    /* Register with storage manager to receive updates when data comes in. */
    storeRegister(entry, fd, (PIF) icpHandleStore, (void *) usm);

    return (protoDispatch(fd, url, usm->entry));
}

#ifdef NOTUSED_CODE
void icpProcessUrl(fd, buf, size, flag, usm)
     int fd;
     char *buf;
     int size;
     int flag;
     icpStateData *usm;
{
    if (flag || size < usm->header.length - sizeof(icp_common_t)) {
	debug(12, 1, "icpProcessUrl: failure trying to read host id.\n");
	safe_free(buf);
	usm->buf = usm->ptr_to_4k_page = NULL;	/* Nothing to free */
	icpSendERROR(fd, ICP_ERROR_INTERNAL, "error reading host id", usm);
    } else {
	/* Extract hostid. */
	memcpy(&usm->query_host, buf, sizeof(u_num32));
	usm->url = (char *) xstrdup(buf + sizeof(u_num32));
	usm->method = METHOD_GET;
	usm->request_hdr = NULL;

	safe_free(buf);

	/* Process request. */
	debug(12, 5, "icpProcessUrl: processing %s\n",
	    IcpOpcodeStr[header.opcode]);
	if (usm->header.opcode == ICP_OP_SEND) {
	    icp_hit_or_miss(fd, usm);
	} else if (usm->header.opcode == ICP_OP_SENDA) {
	    icpProcessMISS(fd, usm);
	} else if (usm->header.opcode == ICP_OP_QUERY) {
	    icpDoQuery(fd, usm);
	} else {
	    debug(12, 1, "icpProcessUrl: Invalid OPCODE: %d.\n",
		usm->header.opcode);
	}
    }
}

int icpProcessHeader(fd, buf_notused, size, flag, state)
     int fd;
     char *buf_notused;
     int size;
     int flag;
     icpStateData *state;
{
    int result = COMM_ERROR;
    icp_common_t *hp = NULL;
    int buf_size;
    char *buf = NULL;

    debug(12, 4, "icpProcessHeader: FD %d.\n", fd);

    if (flag || size < sizeof(icp_common_t)) {
	debug(12, 1, "icpProcessHeader: FD %d: header read failure.\n", fd);
	state->buf = state->ptr_to_4k_page = NULL;	/* Nothing to free */
	icpSendERROR(fd, ICP_ERROR_INTERNAL, "error reading header", state);
	result = COMM_ERROR;
    } else {
	short op = state->header.opcode;
	if (op == ICP_OP_SEND || op == ICP_OP_SENDA || op == ICP_OP_QUERY) {
	    /* Read query host id & url. */
	    hp = &state->header;
	    hp->opcode = op;
	    /* XXX Do these macros work ok in this fashion? */
	    hp->version = hp->version;
	    hp->length = ntohs(hp->length);
	    hp->reqnum = ntohl(hp->reqnum);
	    hp->shostid = ntohl(hp->shostid);

	    /* Allocate buffer for  hostid and url. */
	    buf_size = hp->length - sizeof(icp_common_t);
	    buf = xcalloc(buf_size, sizeof(char));

	    /* Schedule read of host id and url. */
	    (void) icpRead(fd,
		TRUE,
		buf,
		buf_size,
		30,
		icpProcessUrl,
		(void *) state);
	} else {
	    debug(12, 1, "icpProcessHeader: FD %d: invalid OPCODE: %d\n", fd, op);
	    state->buf = state->ptr_to_4k_page = NULL;	/* Nothing to free */
	    icpSendERROR(fd, ICP_ERROR_INTERNAL, "invalid opcode", state);
	    result = COMM_ERROR;
	}
    }
    return result;
}
#endif /* NOTUSED CODE */


int icpUdpReply(fd, queue)
     int fd;
     icpUdpData *queue;
{
    int result = COMM_OK;
    queue = UdpQueueHead;
    /* Disable handler, in case of errors. */
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	0,
	0);
    if (comm_udp_sendto(fd, &queue->address, sizeof(struct sockaddr_in),
	    queue->msg, queue->len) < 0) {
	debug(12, 1, "icpUdpReply: error sending\n");
	result = COMM_ERROR;
    }
    /* Reinstate handler if needed */
    if ((UdpQueueHead = UdpQueueHead->next)) {
	comm_set_select_handler(fd,
	    COMM_SELECT_WRITE,
	    (PF) icpUdpReply,
	    (void *) UdpQueueHead);
    }
    safe_free(queue->msg);
    safe_free(queue);
    return result;
}

int icpUdpMiss(fd, url, reqheaderp, from)
     int fd;
     char *url;
     icp_common_t *reqheaderp;
     struct sockaddr_in *from;
{
    char *buf = NULL;
    int buf_len = sizeof(icp_common_t) + strlen(url) + 1;
    icp_common_t *headerp = NULL;
    icpUdpData *data = (icpUdpData *) xmalloc(sizeof(icpUdpData));
    struct sockaddr_in our_socket_name;
    int sock_name_length = sizeof(our_socket_name);

    if (getsockname(fd, (struct sockaddr *) &our_socket_name,
	    &sock_name_length) == -1) {
	debug(12, 1, "icpUdpMiss: FD %d: getsockname failure: %s\n",
	    fd, xstrerror());
    }
    debug(12, 5, "icpUdpMiss: FD %d: %s: <URL:%s>\n", fd,
	inet_ntoa(our_socket_name.sin_addr), url);

    memset(data, '\0', sizeof(icpUdpData));
    memcpy(&data->address, from, sizeof(struct sockaddr_in));

    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) buf;
    headerp->opcode = ICP_OP_MISS;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqheaderp->reqnum);
/*  memcpy(headerp->auth, , ICP_AUTH_SIZE); */
    headerp->shostid = htonl(our_socket_name.sin_addr.s_addr);

    memcpy(buf + sizeof(icp_common_t), url, strlen(url) + 1);
    data->msg = buf;
    data->len = buf_len;
    AppendUdp(data);
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) icpUdpReply,
	(void *) data);
    return COMM_OK;
}

int icpUdpSend(fd, url, reqheaderp, to, opcode)
     int fd;
     char *url;
     icp_common_t *reqheaderp;
     struct sockaddr_in *to;
     icp_opcode opcode;
{
    char *buf = NULL;
    int buf_len = sizeof(icp_common_t) + strlen(url) + 1;
    icp_common_t *headerp = NULL;
    icpUdpData *data = (icpUdpData *) xmalloc(sizeof(icpUdpData));
    struct sockaddr_in our_socket_name;
    int sock_name_length = sizeof(our_socket_name);
    char *urloffset = NULL;

    if (getsockname(fd, (struct sockaddr *) &our_socket_name,
	    &sock_name_length) == -1) {
	debug(12, 1, "icpUdpSend: FD %d: getsockname failure: %s\n",
	    fd, xstrerror());
    }
    memset(data, '\0', sizeof(icpUdpData));
    memcpy(&data->address, to, sizeof(struct sockaddr_in));

    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);

    headerp = (icp_common_t *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqheaderp->reqnum);
/*  memcpy(headerp->auth, , ICP_AUTH_SIZE); */
    headerp->shostid = htonl(our_socket_name.sin_addr.s_addr);
    debug(12, 5, "icpUdpSend: headerp->reqnum = %d\n", headerp->reqnum);

    urloffset = buf + sizeof(icp_common_t);

    if (opcode == ICP_OP_QUERY)
	urloffset += sizeof(u_num32);
    /* it's already zero filled by xcalloc */
    memcpy(urloffset, url, strlen(url));
    data->msg = buf;
    data->len = buf_len;

    AppendUdp(data);
    debug(12, 4, "icpUdpSend: op %d: to %s: sz %d: <URL:%s>\n", opcode,
	inet_ntoa(to->sin_addr), buf_len, url);
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) icpUdpReply,
	(void *) data);
    return COMM_OK;
}

int icpHandleUdp(sock, not_used)
     int sock;
     void *not_used;
{

    int result = 0;
    struct sockaddr_in from;
    int from_len;
    static char buf[ICP_MAX_UDP_SIZE];
    int len;
    icp_common_t header;
    icp_common_t *headerp = NULL;
    StoreEntry *entry = NULL;
    char *url = NULL;
    char *key = NULL;

    from_len = sizeof(from);
    memset(&from, 0, from_len);
    /* zero filled to make sure url is terminated. */
    memset(buf, 0, ICP_MAX_UDP_SIZE);

    len = comm_udp_recv(sock, buf, ICP_MAX_UDP_SIZE - 1, &from, &from_len);
    if (len < 0) {
	debug(12, 1, "icpHandleUdp: FD %d: error receiving.\n", sock);
	comm_set_select_handler(sock, COMM_SELECT_READ, icpHandleUdp, 0);
	return result;
    }
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
    headerp = (icp_common_t *) buf;
    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
    /*  memcpy(headerp->auth, , ICP_AUTH_SIZE); */
    header.shostid = ntohl(headerp->shostid);
    debug(12, 5, "icpHandleUdp: header.reqnum = %d\n", header.reqnum);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
#ifdef OLD_CODE
	if (ip_access_check(from.sin_addr, proxy_ip_acl) == IP_DENY) {
#else
	if (!aclCheck(ICPAccessList,
		from.sin_addr,
		METHOD_GET,
		PROTO_NONE,	/* XXX need work here */
		NULL,		/* host */
		0,		/* port */
		NULL)) {	/* request */
#endif
	    debug(12, 2, "icpHandleUdp: Access Denied for %s.\n",
		inet_ntoa(from.sin_addr));
	    CacheInfo->log_append(CacheInfo,	/* UDP_DENIED */
		url,
		inet_ntoa(from.sin_addr),
		len,
		log_tags[LOG_UDP_DENIED],
		IcpOpcodeStr[header.opcode],
		0,
		0);
	    break;
	}
	/* The peer is allowed to use this cache */
	entry = storeGet(storeGeneratePublicKey(url, METHOD_GET));
	debug(12, 5, "icpHandleUdp: OPCODE %s\n", IcpOpcodeStr[header.opcode]);
	if (entry &&
	    (entry->status == STORE_OK) &&
	    ((entry->expires - UDP_HIT_THRESH) > cached_curtime)) {
	    /* Send "HIT" message. */
	    CacheInfo->log_append(CacheInfo,	/* UDP_HIT */
		entry->url,
		inet_ntoa(from.sin_addr),
		len,		/* entry->object_len, */
		log_tags[LOG_UDP_HIT],
		IcpOpcodeStr[header.opcode],
		0,
		0);
	    CacheInfo->proto_hit(CacheInfo,
		CacheInfo->proto_id(entry->url));
	    icpUdpSend(sock, url, &header, &from, ICP_OP_HIT);
	    break;
	}
	/* Send "MISS" message. */
	CacheInfo->log_append(CacheInfo,	/* UDP_MISS */
	    url,
	    inet_ntoa(from.sin_addr),
	    len,
	    log_tags[LOG_UDP_MISS],
	    IcpOpcodeStr[header.opcode],
	    0,
	    0);
	CacheInfo->proto_miss(CacheInfo,
	    CacheInfo->proto_id(url));
	icpUdpMiss(sock, url, &header, &from);
	break;

    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:

	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0, "icpHandleUdp: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0, "icpHandleUdp: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
	debug(12, 3, "icpHandleUdp: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (header.reqnum)
	    key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
	else
	    key = storeGeneratePublicKey(url, METHOD_GET);
	debug(12, 3, "icpHandleUdp: Looking for key '%s'\n", key);
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3, "icpHandleUdp: Ignoring %s for NULL Entry.\n",
		IcpOpcodeStr[header.opcode]);
	    break;
	}
	neighborsUdpAck(sock, url, &header, &from, entry);
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
int parseHttpRequest(icpState)
     icpStateData *icpState;
{
    char *inbuf = NULL;
    char *method = NULL;
    char *request = NULL;
    char *req_hdr = NULL;
    char *http_ver = NULL;
    char *token = NULL;
    char *t = NULL;
    char *ad = NULL;
    char *post_data = NULL;
    int free_request = 0;
    int content_length;
    int req_hdr_sz;
    int post_sz;

    /* Use xmalloc/memcpy instead of xstrdup because inbuf might
     * contain NULL bytes; especially for POST data  */
    inbuf = (char *) xmalloc(icpState->offset + 1);
    memcpy(inbuf, icpState->inbuf, icpState->offset);
    *(inbuf + icpState->offset) = '\0';

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

    if ((request = strtok(NULL, "\n\r\t ")) == NULL) {
	debug(12, 1, "parseHttpRequest: Missing URL\n");
	xfree(inbuf);
	return -1;
    }
    debug(12, 5, "parseHttpRequest: Request is '%s'\n", request);
    if ((http_ver = strtok(NULL, "\n\r\t ")) == NULL)
	debug(12, 3, "parseHttpRequest: Missing HTTP identifier\n");
    else
	debug(12, 5, "parseHttpRequest: HTTP version is '%s'\n", http_ver);

    if ((token = (char *) strtok(NULL, ""))) {
	req_hdr = token;
	while (*req_hdr == '\r' || *req_hdr == '\n')
	    req_hdr++;
	req_hdr_sz = icpState->offset - (req_hdr - inbuf);
	icpState->request_hdr = (char *) xmalloc(req_hdr_sz + 1);
	memcpy(icpState->request_hdr, req_hdr, req_hdr_sz);
	*(icpState->request_hdr + req_hdr_sz) = '\0';
    } else if (icpState->method == METHOD_POST) {
	debug(12, 3, "parseHttpRequest: Partial POST request\n");
	xfree(inbuf);
	return 0;		/* reschedule us after next read */
    }
    if (icpState->request_hdr)
	debug(12, 5, "parseHttpRequest: Request Header is\n---\n%s\n---\n",
	    icpState->request_hdr);
    else
	debug(12, 5, "parseHttpRequest: No Request Header present\n");

    if (icpState->method == METHOD_POST) {
	/* Expect Content-Length: and POST data after the headers */
	if ((t = mime_get_header(req_hdr, "Content-Length")) == NULL) {
	    xfree(inbuf);
	    return 0;		/* not a complete request */
	}
	content_length = atoi(t);
	debug(12, 3, "parseHttpRequest: Expecting POST Content-Length of %d\n",
	    content_length);
	if ((t = strstr(req_hdr, "\r\n\r\n"))) {
	    post_data = t + 4;
	} else if ((t = strstr(req_hdr, "\n\n"))) {
	    post_data = t + 2;
	} else {
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
	    request = t;
	    free_request = 1;
	    /* NOTE: We don't have to free the old request pointer
	     * because it points to inside xbuf. But
	     * do_append_domain() allocates memory so set a flag
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
	    sprintf(icpState->url, "http://%s%s",
		inet_ntoa(icpState->me.sin_addr), request);
	}
	BIT_SET(icpState->flags, REQ_ACCEL);
    } else {
	icpState->url = xstrdup(request);
	BIT_RESET(icpState->flags, REQ_ACCEL);
    }

    if (icpCachable(icpState))
	BIT_SET(icpState->flags, REQ_PUBLIC);

    debug(12, 5, "parseHttpRequest: Complete request received\n");
    if (free_request)
	safe_free(request);
    xfree(inbuf);
    return 1;
}

#ifdef OLD_CODE
ip_access_type second_ip_acl_check(fd_unused, astm)
     int fd_unused;
     icpStateData *astm;
{
    if (BIT_TEST(icpState->flags, REQ_ACCEL))
	return ip_access_check(astm->peer.sin_addr, accel_ip_acl);
    return ip_access_check(astm->peer.sin_addr, proxy_ip_acl);
}
#endif


/* Also rewrites URLs... */
static int check_valid_url(fd, astm)
     int fd;
     icpStateData *astm;
{
    static char proto[MAX_URL];
    static char host[MAX_URL];
    static char urlpath[MAX_URL];
    static char portbuf[32];
    char *t = NULL;
    protocol_t protocol;
    int port;
    proto[0] = host[0] = urlpath[0] = '\0';
    if (sscanf(astm->url, "%[^:]://%[^/]%s", proto, host, urlpath) != 3)
	return ERR_INVALID_URL;
    for (t = host; *t; t++)
	*t = tolower(*t);
    protocol = urlParseProtocol(proto);
    port = urlDefaultPort(protocol);
    if ((t = strchr(host, ':'))) {
	*t = '\0';
	port = atoi(t + 1);
    }
    portbuf[0] = '\0';
    if (port > 0 && port != urlDefaultPort(protocol))
	sprintf(portbuf, ":%d", port);

    if (!aclCheck(HTTPAccessList,
	    astm->peer.sin_addr,
	    astm->method,
	    protocol,
	    host,
	    port,
	    urlpath))
	return LOG_TCP_DENIED;
    sprintf(astm->url, "%s://%s%s%s", proto, host, portbuf, urlpath);
    return 0;
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
void asciiProcessInput(fd, buf, size, flag, astm)
     int fd;
     char *buf;
     int size;
     int flag;
     icpStateData *astm;
{
    static char client_msg[64];
    int parser_return_code = 0;
    int k;

    debug(12, 4, "asciiProcessInput: FD %d: reading request...\n", fd);
    debug(12, 4, "asciiProcessInput: size = %d\n", size);

    if (flag != COMM_OK) {
	/* connection closed by foreign host */
	icpCloseAndFree(fd, astm, __LINE__);
	return;
    }
    if (astm->offset + size >= astm->inbufsize) {
	if (astm->offset + size >= getMaxRequestSize()) {
	    /* The request is to large to handle */
	    debug(12, 0, "asciiProcessInput: Request won't fit in buffer.\n");
	    debug(12, 0, "-->     max size = %d\n", getMaxRequestSize());
	    debug(12, 0, "--> astm->offset = %d\n", astm->offset);
	    debug(12, 0, "-->         size = %d\n", size);
	    astm->buf = NULL;
	    astm->ptr_to_4k_page = NULL;
	    icpSendERROR(fd, ICP_ERROR_INTERNAL, "error reading request", astm);
	    return;
	} else {
	    /* Grow the request memory area to accomodate for a large request */
	    char *inbuf;
	    inbuf = xmalloc(astm->inbufsize + ASCII_INBUF_BLOCKSIZE);
	    memcpy(inbuf, astm->inbuf, astm->inbufsize);
	    safe_free(astm->inbuf);
	    astm->inbuf = inbuf;
	    astm->inbufsize += ASCII_INBUF_BLOCKSIZE;
	    debug(12, 2, "Handling a large request, inbufsize=%d\n",
		astm->inbufsize);
	}
    }
    astm->offset += size;

    parser_return_code = parseHttpRequest(astm);
    if (parser_return_code == 1) {
	switch (check_valid_url(fd, astm)) {
	case ERR_INVALID_URL:
	    debug(12, 5, "Invalid URL: %s\n", astm->url);
	    astm->log_type = ERR_INVALID_URL;
	    astm->http_code = 400;
	    astm->buf = xstrdup(cached_error_url(astm->url,
		    astm->method,
		    ERR_INVALID_URL,
		    fd_table[fd].ipaddr,
		    astm->http_code,
		    NULL));
	    astm->ptr_to_4k_page = NULL;
	    icpWrite(fd,
		astm->buf,
		strlen(astm->buf),
		30,
		icpSendERRORComplete,
		(void *) astm);
	    break;
	case LOG_TCP_DENIED:
	    debug(12, 5, "Access Denied: %s\n", astm->url);
	    astm->log_type = LOG_TCP_DENIED;
	    astm->http_code = 403;
	    astm->buf = xstrdup(access_denied_msg(astm->http_code,
		    astm->method,
		    astm->url,
		    fd_table[fd].ipaddr));
	    astm->ptr_to_4k_page = NULL;
	    icpWrite(fd,
		astm->buf,
		strlen(tmp_error_buf),
		30,
		icpSendERRORComplete,
		(void *) astm);
	    astm->log_type = LOG_TCP_DENIED;
	    break;
	default:
	    /* The request is good, let's go... */
	    sprintf(client_msg, "%16.16s %-4.4s %-40.40s",
		fd_note(fd, 0),
		RequestMethodStr[astm->method],
		astm->url);
	    fd_note(fd, client_msg);
	    icp_hit_or_miss(fd, astm);
	    break;
	}
    } else if (parser_return_code == 0) {
	/*
	 *    Partial request received; reschedule until parseAsciiUrl()
	 *    is happy with the input
	 */
	k = astm->inbufsize - 1 - astm->offset;
#ifdef NOT_NEEDED_CODE
	if (0 < astm->bytes_needed && astm->bytes_needed < k)
	    k = astm->bytes_needed;
#endif
	icpRead(fd,
	    FALSE,
	    astm->inbuf + astm->offset,
	    k,
	    30,
	    asciiProcessInput,
	    (void *) astm);
    } else {
	/* parser returned -1 */
	debug(12, 1, "asciiProcessInput: FD %d Invalid Request\n", fd);
	astm->log_type = ERR_INVALID_REQ;
	astm->http_code = 400;
	astm->buf = xstrdup(cached_error_request(astm->inbuf,
		ERR_INVALID_REQ,
		fd_table[fd].ipaddr,
		astm->http_code));
	icpWrite(fd,
	    astm->buf,
	    strlen(astm->buf),
	    30,
	    icpSendERRORComplete,
	    (void *) astm);
    }
}



/* general lifetime handler for ascii connection */
void asciiConnLifetimeHandle(fd, data)
     int fd;
     void *data;
{
    icpStateData *astm = (icpStateData *) data;
    PF handler;
    void *client_data;
    icpReadWriteData *rw_state = NULL;
    StoreEntry *entry = NULL;

    entry = astm->entry;

    debug(12, 2, "asciiConnLifetimeHandle: Socket: %d lifetime is expired. Free up data structure.\n", fd);

    /* If a write handler was installed, we were in the middle of an
     * icpWrite and we're going to need to deallocate the icpReadWrite
     * buffer.  These come from icpSendMoreData and from icpSendERROR, both
     * of which allocate 4k buffers. */

    handler = NULL;
    client_data = NULL;
    comm_get_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF *) & handler,
	(void **) &client_data);
    if ((handler != NULL) && (client_data != NULL)) {
	rw_state = (icpReadWriteData *) client_data;
	if (rw_state->buf)
	    put_free_4k_page(rw_state->buf);
	safe_free(rw_state);
    }
    /* If we have a read handler, we were reading in the get/post URL 
     * and don't have to deallocate the icpreadWrite buffer */
    handler = NULL;
    client_data = NULL;
    comm_get_select_handler(fd,
	COMM_SELECT_READ,
	(PF *) & handler,
	(void **) &client_data);
    if ((handler != NULL) && (client_data != NULL)) {
	rw_state = (icpReadWriteData *) client_data;
	/*
	 * the correct pointer for free is astm->url, NOT rw_state->buf
	 */
	safe_free(rw_state);
    }
    icpCloseAndFree(fd, astm, __LINE__);
    if (entry) {
	/* NOTE, this section used to be between free write & read */
	CheckQuickAbort(astm);
	storeUnregister(entry, fd);
	/* We are now detached from the store entry but not the
	 * DNS handler for it */
	if (astm->url) {
	    /* Unregister us from the dnsserver pending list and cause a DNS
	     * related storeAbort() for other attached clients.  If this
	     * doesn't succeed, then the fetch has already started for this
	     * URL. */
	    protoUndispatch(fd, astm->url, entry);
	}
	storeUnlockObject(entry);
    }
}

/* Handle a new connection on ascii input socket. */
int asciiHandleConn(sock, notused)
     int sock;
     void *notused;
{
    int fd = -1;
    int lft = -1;
    icpStateData *astm = NULL;
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
    nconn++;

    debug(12, 4, "asciiHandleConn: FD %d: accepted (lifetime %d).\n", fd, lft);
    fd_note(fd, inet_ntoa(peer.sin_addr));

    astm = (icpStateData *) xcalloc(1, sizeof(icpStateData));
    astm->start = current_time;

#ifdef OLD_CODE
    if (ip_access_check(peer.sin_addr, proxy_ip_acl) == IP_DENY
	&& ip_access_check(peer.sin_addr, accel_ip_acl) == IP_DENY) {
	debug(12, 2, "asciiHandleConn: %s: Access denied.\n",
	    inet_ntoa(peer.sin_addr));
	astm->log_type = LOG_TCP_DENIED;
	sprintf(tmp_error_buf,
	    "ACCESS DENIED\n\nYour IP address (%s) is not authorized to access cached at %s.\n\n",
	    inet_ntoa(peer.sin_addr),
	    getMyHostname());
	astm->buf = xstrdup(tmp_error_buf);
	astm->ptr_to_4k_page = NULL;
	icpWrite(fd,
	    astm->buf,
	    strlen(tmp_error_buf),
	    30,
	    icpSendERRORComplete,
	    (void *) astm);
    } else {
#endif
	astm->inbufsize = ASCII_INBUF_BLOCKSIZE;
	astm->inbuf = (char *) xcalloc(astm->inbufsize, 1);
	astm->header.shostid = htonl(peer.sin_addr.s_addr);
	astm->peer = peer;
	astm->me = me;
	comm_set_select_handler(fd,
	    COMM_SELECT_LIFETIME,
	    (PF) asciiConnLifetimeHandle,
	    (void *) astm);
	icpRead(fd,
	    FALSE,
	    astm->inbuf,
	    astm->inbufsize - 1,
	    30,
	    asciiProcessInput,
	    (void *) astm);
#ifdef OLD_CODE
    }
#endif
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

static void CheckQuickAbort(astm)
     icpStateData *astm;
{
    if (!getQuickAbort())
	return;
    if (BIT_TEST(astm->flags, REQ_PUBLIC))
	return;
    if (astm->entry->lock_count != 1)
	return;
    if (astm->entry->status == STORE_OK)
	return;
    BIT_SET(astm->entry->flag, CLIENT_ABORT_REQUEST);
    storeReleaseRequest(astm->entry);
    astm->log_type = ERR_CLIENT_ABORT;
}
