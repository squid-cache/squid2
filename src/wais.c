/* $Id$ */

/*
 * DEBUG: Section 24          wais
 */

#include "squid.h"

#define  WAIS_DELETE_GAP  (64*1024)

typedef struct {
    StoreEntry *entry;
    method_t method;
    char *relayhost;
    int relayport;
    char *mime_hdr;
    char request[MAX_URL];
} WaisStateData;

static int waisStateFree(fd, waisState)
     int fd;
     WaisStateData *waisState;
{
    if (waisState == NULL)
	return 1;
    storeUnlockObject(waisState->entry);
    xfree(waisState);
    return 0;
}

/* This will be called when timeout on read. */
static void waisReadReplyTimeout(fd, waisState)
     int fd;
     WaisStateData *waisState;
{
    StoreEntry *entry = NULL;

    entry = waisState->entry;
    debug(24, 4, "waisReadReplyTimeout: Timeout on %d\n url: %s\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    comm_set_select_handler(fd, COMM_SELECT_READ, 0, 0);
    comm_close(fd);
}

/* This will be called when socket lifetime is expired. */
void waisLifetimeExpire(fd, waisState)
     int fd;
     WaisStateData *waisState;
{
    StoreEntry *entry = NULL;

    entry = waisState->entry;
    debug(24, 4, "waisLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);
    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    comm_set_select_handler(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, 0, 0);
    comm_close(fd);
}




/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
void waisReadReply(fd, waisState)
     int fd;
     WaisStateData *waisState;
{
    static char buf[4096];
    int len;
    StoreEntry *entry = NULL;

    entry = waisState->entry;
    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    /* check if we want to defer reading */
	    if ((entry->mem_obj->e_current_len -
		    entry->mem_obj->e_lowest_offset) > WAIS_DELETE_GAP) {
		debug(24, 3, "waisReadReply: Read deferred for Object: %s\n",
		    entry->url);
		debug(24, 3, "                Current Gap: %d bytes\n",
		    entry->mem_obj->e_current_len -
		    entry->mem_obj->e_lowest_offset);
		/* reschedule, so it will automatically reactivated
		 * when Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) waisReadReply,
		    (void *) waisState);
		/* don't install read handler while we're above the gap */
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) NULL,
		    (void *) NULL,
		    (time_t) 0);
		/* dont try reading again for a while */
		comm_set_stall(fd, getStallDelay());
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    comm_close(fd);
	    return;
	}
    }
    len = read(fd, buf, 4096);
    debug(24, 5, "waisReadReply - fd: %d read len:%d\n", fd, len);

    if (len < 0) {
	debug(24, 1, "waisReadReply: FD %d: read failure: %s.\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) waisReadReply, (void *) waisState);
	    comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
		(PF) waisReadReplyTimeout, (void *) waisState, getReadTimeout());
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	entry->expires = squid_curtime;
	storeComplete(entry);
	comm_close(fd);
    } else if (((entry->mem_obj->e_current_len + len) > getWAISMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) waisReadReply,
	    (void *) waisState);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) waisReadReplyTimeout,
	    (void *) waisState,
	    getReadTimeout());
    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) waisReadReply,
	    (void *) waisState);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) waisReadReplyTimeout,
	    (void *) waisState,
	    getReadTimeout());
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
void waisSendComplete(fd, buf, size, errflag, waisState)
     int fd;
     char *buf;
     int size;
     int errflag;
     WaisStateData *waisState;
{
    StoreEntry *entry = NULL;
    entry = waisState->entry;
    debug(24, 5, "waisSendComplete - fd: %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
    } else {
	/* Schedule read reply. */
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) waisReadReply,
	    (void *) waisState);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) waisReadReplyTimeout,
	    (void *) waisState,
	    getReadTimeout());
    }
    safe_free(buf);		/* Allocated by waisSendRequest. */
}

/* This will be called when connect completes. Write request. */
void waisSendRequest(fd, waisState)
     int fd;
     WaisStateData *waisState;
{
    int len = strlen(waisState->request) + 4;
    char *buf = NULL;
    char *Method = RequestMethodStr[waisState->method];

    debug(24, 5, "waisSendRequest - fd: %d\n", fd);

    if (Method)
	len += strlen(Method);
    if (waisState->mime_hdr)
	len += strlen(waisState->mime_hdr);

    buf = xcalloc(1, len + 1);

    if (waisState->mime_hdr)
	sprintf(buf, "%s %s %s\r\n", Method, waisState->request,
	    waisState->mime_hdr);
    else
	sprintf(buf, "%s %s\r\n", Method, waisState->request);
    debug(24, 6, "waisSendRequest - buf:%s\n", buf);
    comm_write(fd,
	buf,
	len,
	30,
	waisSendComplete,
	(void *) waisState);
    if (BIT_TEST(waisState->entry->flag, CACHABLE))
	storeSetPublicKey(waisState->entry);		/* Make it public */
}

static void waisConnInProgress(fd, waisState)
     int fd;
     WaisStateData *waisState;
{
    StoreEntry *entry = waisState->entry;

    debug(11, 5, "waisConnInProgress: FD %d waisState=%p\n", fd, waisState);

    if (comm_connect(fd, waisState->relayhost, waisState->relayport) != COMM_OK) {
        debug(11, 5, "waisConnInProgress: FD %d: %s\n", fd, xstrerror());
        switch (errno) {
        case EINPROGRESS:
        case EALREADY:
            /* schedule this handler again */
            comm_set_select_handler(fd,
                COMM_SELECT_WRITE,
                (PF) waisConnInProgress,
                (void *) waisState);
            return;
        default:
            squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
            comm_close(fd);
            return;
        }
    }
    /* Call the real write handler, now that we're fully connected */
    comm_set_select_handler(fd, COMM_SELECT_WRITE,
        (PF) waisSendRequest, (void *) waisState);
}

int waisStart(unusedfd, url, method, mime_hdr, entry)
     int unusedfd;
     char *url;
     method_t method;
     char *mime_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    WaisStateData *waisState = NULL;

    debug(24, 3, "waisStart: \"%s %s\"\n",
	RequestMethodStr[method], url);
    debug(24, 4, "            header: %s\n", mime_hdr);

    if (!getWaisRelayHost()) {
	debug(24, 0, "waisStart: Failed because no relay host defined!\n");
	squid_error_entry(entry, ERR_NO_RELAY, NULL);
	return COMM_ERROR;
    }
    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, getTcpOutgoingAddr(), 0, url);
    if (sock == COMM_ERROR) {
	debug(24, 4, "waisStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    waisState = xcalloc(1, sizeof(WaisStateData));
    storeLockObject(waisState->entry = entry, NULL, NULL);
    waisState->method = method;
    waisState->relayhost = getWaisRelayHost();
    waisState->relayport = getWaisRelayPort();
    waisState->mime_hdr = mime_hdr;
    strncpy(waisState->request, url, MAX_URL);
    comm_add_close_handler(sock,
	(PF) waisStateFree,
	(void *) waisState);

    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(waisState->relayhost, 0)) {
	debug(24, 4, "waisstart: Called without IP entry in ipcache. OR lookup failed.\n");
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(sock);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, waisState->relayhost, waisState->relayport))) {
	if (status != EINPROGRESS) {
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(sock);
	    return COMM_ERROR;
	} else {
	    debug(24, 5, "waisStart: FD %d EINPROGRESS\n", sock);
            comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
                (PF) waisLifetimeExpire, (void *) waisState);
            comm_set_select_handler(sock, COMM_SELECT_WRITE,
                (PF) waisConnInProgress, (void *) waisState);
            return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) waisLifetimeExpire, (void *) waisState);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) waisSendRequest, (void *) waisState);
    return COMM_OK;
}
