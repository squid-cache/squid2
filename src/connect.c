/*
 *  $Id$ 
 *
 * DEBUG: Section 26                    connect
 */
#include "squid.h"

#define  CONNECT_BUFSIZE     (1<<14)
#define  CONNECT_DELETE_GAP  (64*1024)
#define  ConnectMaxObjSize   (4 << 20)	/* 4 MB */

typedef struct {
    StoreEntry *entry;
    request_t *request;
    char *mime_hdr;
    int len;
    int offset;
    char buf[CONNECT_BUFSIZE];
    int remote;
    int client;
    time_t timeout;
} ConnectData;

static char conn_established[] = "HTTP/1.0 200 Connection established\r\n\r\n";

static void connectLifetimeExpire _PARAMS((int fd, ConnectData * data));
static void connectReadRemote _PARAMS((int fd, ConnectData * data));
static void connectReadTimeout _PARAMS((int fd, ConnectData * data));
static void connectSendRemote _PARAMS((int fd, ConnectData * data));
static void connectReadClient _PARAMS((int fd, ConnectData * data));
static void connectConnected _PARAMS((int fd, ConnectData * data));
static void connectConnInProgress _PARAMS((int fd, ConnectData * data));

/* This will be called when socket lifetime is expired. */
static void connectLifetimeExpire(rfd, data)
     int rfd;
     ConnectData *data;
{
    StoreEntry *entry = data->entry;
    debug(26, 4, "connectLifeTimeExpire: FD %d: <URL:%s>\n",
	rfd, entry->url);
    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    comm_set_select_handler(rfd,
	COMM_SELECT_READ | COMM_SELECT_WRITE,
	NULL,
	NULL);
    comm_close(rfd);
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void connectReadRemote(rfd, data)
     int rfd;
     ConnectData *data;
{
    static char buf[CONNECT_BUFSIZE];
    int len;
    StoreEntry *entry = data->entry;

    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    /* check if we want to defer reading */
	    if ((entry->mem_obj->e_current_len -
		    entry->mem_obj->e_lowest_offset) > CONNECT_DELETE_GAP) {
		debug(26, 3, "connectReadRemote: Read deferred for Object: %s\n", entry->key);
		debug(26, 3, "                Current Gap: %d bytes\n",
		    entry->mem_obj->e_current_len -
		    entry->mem_obj->e_lowest_offset);
		/* reschedule, so it will automatically reactivated when Gap is big enough. */
		comm_set_select_handler(rfd,
		    COMM_SELECT_READ,
		    (PF) connectReadRemote,
		    (void *) data);
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    comm_close(rfd);
	    return;
	}
    }
    len = read(rfd, buf, CONNECT_BUFSIZE);
    debug(26, 5, "connectReadRemote FD %d read len:%d\n", rfd, len);

    if (len < 0) {
	debug(26, 1, "connectReadRemote: FD %d: read failure: %s.\n",
	    rfd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(rfd,
		COMM_SELECT_READ,
		(PF) connectReadRemote,
		(void *) data);
	    comm_set_select_handler_plus_timeout(rfd,
		COMM_SELECT_TIMEOUT,
		(PF) connectReadTimeout,
		(void *) data,
		data->timeout);
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(rfd);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	comm_close(rfd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	storeExpireNow(entry);
	storeComplete(entry);
	comm_close(rfd);
    } else if (((entry->mem_obj->e_current_len + len) > ConnectMaxObjSize) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(rfd,
	    COMM_SELECT_READ,
	    (PF) connectReadRemote,
	    (void *) data);
    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler_plus_timeout(rfd,
	    COMM_SELECT_TIMEOUT,
	    (PF) connectReadTimeout,
	    (void *) data,
	    data->timeout);
	comm_set_select_handler(rfd,
	    COMM_SELECT_READ,
	    (PF) connectReadRemote,
	    (void *) data);
    }
}

/* This will be called when connect completes. Write request. */
static void connectSendRemote(rfd, data)
     int rfd;
     ConnectData *data;
{
    int len;

    debug(26, 5, "connectSendRemote FD %d\n", rfd);

    len = write(rfd, data->buf + data->offset, data->len - data->offset);
    if (len < 0) {
	debug(26, 2, "connectSendRemote: FD %d: write failure: %s.\n",
	    rfd, xstrerror());
	comm_close(rfd);
	return;
    }
    if ((data->offset += len) >= data->len) {
	/* Done writing */
	comm_set_select_handler(data->client,
	    COMM_SELECT_READ,
	    (PF) connectReadClient,
	    (void *) data);
    } else {
	/* more to write */
	comm_set_select_handler(data->remote,
	    COMM_SELECT_WRITE,
	    (PF) connectSendRemote,
	    (void *) data);
    }
}

static void connectReadClient(cfd, data)
     int cfd;
     ConnectData *data;
{
    data->len = read(cfd, data->buf, CONNECT_BUFSIZE);
    debug(26, 2, "connectReadClient FD: %d read len: %d\n", cfd, data->len);
    if (data->len <= 0) {
	if (data->len < 0)
	    debug(26, 2, "connectReadClient: FD %d: read failure: %s.\n",
		cfd, xstrerror());
	comm_close(cfd);
	return;
    }
    if (!fdstat_isopen(data->remote))
	fatal_dump("connectReadClient called after remote side closed\n");
    data->offset = 0;
    comm_set_select_handler_plus_timeout(data->remote,
	COMM_SELECT_TIMEOUT,
	(PF) connectReadTimeout,
	(void *) data,
	data->timeout);
    comm_set_select_handler(data->remote,
	COMM_SELECT_WRITE,
	(PF) connectSendRemote,
	(void *) data);
}

static void connectReadTimeout(rfd, data)
     int rfd;
     ConnectData *data;
{
    if (rfd != data->remote)
	fatal_dump("connectReadTimeout: FD mismatch!\n");
    debug(26, 3, "connectReadTimeout: FD %d\n", rfd);
    squid_error_entry(data->entry, ERR_READ_TIMEOUT, NULL);
    comm_set_select_handler(data->remote,
	COMM_SELECT_READ | COMM_SELECT_WRITE,
	NULL,
	NULL);
    /* no matter which side times out, close the server side */
    comm_close(rfd);
}

static void connectConnected(rfd, data)
     int rfd;
     ConnectData *data;
{
    debug(26, 3, "connectConnected: FD %d data=%p\n", rfd, data);
    storeAppend(data->entry, conn_established, strlen(conn_established));
    comm_set_fd_lifetime(rfd, -1);	/* disable lifetime */
    comm_set_select_handler_plus_timeout(data->remote,
	COMM_SELECT_TIMEOUT,
	(PF) connectReadTimeout,
	(void *) data,
	data->timeout);
    comm_set_select_handler(data->remote,
	COMM_SELECT_READ,
	(PF) connectReadRemote,
	(void *) data);
    comm_set_select_handler(data->client,
	COMM_SELECT_READ,
	(PF) connectReadClient,
	(void *) data);
}


static int connectStateFree(rfd, connectState)
     int rfd;
     ConnectData *connectState;
{
    if (connectState == NULL)
	return 1;
    if (rfd != connectState->remote)
	fatal_dump("connectStateFree: FD mismatch!\n");
    comm_set_select_handler(connectState->client,
	COMM_SELECT_READ,
	NULL,
	NULL);
    memset(connectState, '\0', sizeof(ConnectData));
    safe_free(connectState);
    return 0;
}

static void connectConnInProgress(rfd, data)
     int rfd;
     ConnectData *data;
{
    request_t *req = data->request;
    debug(26, 5, "connectConnInProgress: FD %d data=%p\n", rfd, data);

    if (comm_connect(rfd, req->host, req->port) != COMM_OK) {
	debug(26, 5, "connectConnInProgress: FD %d: %s", rfd, xstrerror());
	switch (errno) {
#if EINPROGRESS != EALREADY
	case EINPROGRESS:
#endif
	case EALREADY:
	    /* We are not connectedd yet. schedule this handler again */
	    comm_set_select_handler(rfd, COMM_SELECT_WRITE,
		(PF) connectConnInProgress,
		(void *) data);
	    return;
	default:
	    squid_error_entry(data->entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(rfd);
	    return;
	}
    }
    /* We are now fully connected */
    connectConnected(rfd, data);
    return;
}


int connectStart(fd, url, request, mime_hdr, entry)
     int fd;
     char *url;
     request_t *request;
     char *mime_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    ConnectData *data = NULL;

    debug(26, 3, "connectStart: '%s %s'\n",
	RequestMethodStr[request->method], url);
    debug(26, 4, "            header: %s\n", mime_hdr);


    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(26, 4, "connectStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    data = (ConnectData *) xcalloc(1, sizeof(ConnectData));
    data->entry = entry;
    data->request = request;
    data->mime_hdr = mime_hdr;
    data->client = fd;
    data->timeout = getReadTimeout();
    data->remote = sock;
    comm_set_select_handler(sock,
	COMM_SELECT_CLOSE,
	(PF) connectStateFree,
	(void *) data);

#ifdef STAT_FD_ASSOC
    stat_fd_assoc(fd, sock);	/* XXX what is this? */
#endif

    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(request->host)) {
	debug(26, 4, "connectstart: Called without IP entry in ipcache. OR lookup failed.\n");
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(sock);
	return COMM_ERROR;
    }
    debug(26, 5, "connectStart: client=%d remote=%d\n", fd, sock);
    /* Install lifetime handler */
    comm_set_select_handler(sock,
	COMM_SELECT_LIFETIME,
	(PF) connectLifetimeExpire,
	(void *) data);
    /* Open connection. */
    if ((status = comm_connect(sock, request->host, request->port))) {
	if (status != EINPROGRESS) {
	    squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    comm_close(sock);
	    return COMM_ERROR;
	} else {
	    debug(26, 5, "connectStart: conn %d EINPROGRESS\n", sock);
	    /* The connection is in progress, install connect handler */
	    comm_set_select_handler(sock,
		COMM_SELECT_WRITE,
		(PF) connectConnInProgress,
		(void *) data);
	    return COMM_OK;
	}
    }
    /* We got immediately connected. (can this happen?) */
    connectConnected(sock, data);
    return COMM_OK;
}
