/*
 *  $Id$ 
 *
 * DEBUG: Section 26                    connect
 */
#include "squid.h"

#define  CONNECT_BUFSIZE     4096
#define  CONNECT_DELETE_GAP  (64*1024)
#define  CONNECT_PORT        443
#define  ConnectMaxObjSize   (4 << 20)	/* 4 MB */

typedef struct {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    int port;
    int method;
    char *mime_hdr;
    int len;
    int offset;
    char buf[CONNECT_BUFSIZE];
    int remote;
    int client;
    time_t timeout;
} ConnectData;

static char conn_established[] = "HTTP/1.0 200 Connection established\r\n\r\n";

static int connect_url_parser _PARAMS((char *url, ConnectData *));
static void connectLifetimeExpire _PARAMS((int fd, ConnectData * data));
static void connectReadRemote _PARAMS((int fd, ConnectData * data));
static void connectReadTimeout _PARAMS((int fd, ConnectData * data));
static void connectSendRemote _PARAMS((int fd, ConnectData * data));
static void connectReadClient _PARAMS((int fd, ConnectData * data));
static void connectConnected _PARAMS((int fd, ConnectData * data));
static void connectConnInProgress _PARAMS((int fd, ConnectData * data));
static void connectCloseAndFree _PARAMS((int fd, ConnectData * data));

extern intlist *connect_port_list;

static int connect_url_parser(url, connectData)
     char *url;
     ConnectData *connectData;
{
    char *host = connectData->host;
    char *t = NULL;
    /* initialize everything */
    connectData->port = CONNECT_PORT;
    strncpy(host, url, SQUIDHOSTNAMELEN);
    if ((t = strchr(host, ':')) && *(t + 1) != '\0') {
	*t = '\0';
	connectData->port = atoi(t + 1);
    }
    /* Fail if port is not in list of approved ports */
    if (!aclMatchInteger(connect_port_list, connectData->port))
	return -1;
    return 0;
}

/* This will be called when socket lifetime is expired. */
static void connectLifetimeExpire(fd, data)
     int fd;
     ConnectData *data;
{
    debug(26, 4, "connectLifeTimeExpire: FD %d: <URL:%s>\n", fd, data->entry->url);
    connectCloseAndFree(fd, data);
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void connectReadRemote(fd, data)
     int fd;
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
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) connectReadRemote,
		    (void *) data);
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    cached_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    connectCloseAndFree(fd, data);
	    return;
	}
    }
    len = read(fd, buf, CONNECT_BUFSIZE);
    debug(26, 5, "connectReadRemote FD %d read len:%d\n", fd, len);

    if (len < 0) {
	debug(26, 1, "connectReadRemote: FD %d: read failure: %s.\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd,
		COMM_SELECT_READ,
		(PF) connectReadRemote,
		(void *) data);
	    comm_set_select_handler_plus_timeout(fd,
		COMM_SELECT_TIMEOUT,
		(PF) connectReadTimeout,
		(void *) data,
		getReadTimeout());
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    storeReleaseRequest(entry);
	    cached_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    connectCloseAndFree(fd, data);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	cached_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	connectCloseAndFree(fd, data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	storeExpireNow(entry);
	storeComplete(entry);
	connectCloseAndFree(fd, data);
    } else if (((entry->mem_obj->e_current_len + len) > ConnectMaxObjSize) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) connectReadRemote,
	    (void *) data);
    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler_plus_timeout(data->client,
	    COMM_SELECT_TIMEOUT,
	    (PF) connectReadTimeout,
	    (void *) data,
	    data->timeout);
	comm_set_select_handler_plus_timeout(data->remote,
	    COMM_SELECT_TIMEOUT,
	    (PF) connectReadTimeout,
	    (void *) data,
	    data->timeout);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) connectReadRemote,
	    (void *) data);
    }
}

/* This will be called when connect completes. Write request. */
static void connectSendRemote(fd, data)
     int fd;
     ConnectData *data;
{
    int len;

    debug(26, 5, "connectSendRemote FD %d\n", fd);

    len = write(fd, data->buf + data->offset, data->len - data->offset);
    if (len < 0) {
	debug(26, 2, "connectSendRemote: FD %d: write failure: %s.\n",
	    fd, xstrerror());
	connectCloseAndFree(fd, data);
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

static void connectReadClient(fd, data)
     int fd;
     ConnectData *data;
{
    data->len = read(fd, data->buf, CONNECT_BUFSIZE);
    debug(26, 2, "connectReadClient FD: %d read len: %d\n", fd, data->len);
    if (data->len <= 0) {
	if (data->len < 0)
	    debug(26, 2, "connectReadClient: FD %d: read failure: %s.\n",
		fd, xstrerror());
	connectCloseAndFree(fd, data);
	return;
    }
    data->offset = 0;
    comm_set_select_handler_plus_timeout(data->client,
	COMM_SELECT_TIMEOUT,
	(PF) connectReadTimeout,
	(void *) data,
	data->timeout);
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

static void connectReadTimeout(fd, data)
     int fd;
     ConnectData *data;
{
    cached_error_entry(data->entry, ERR_READ_TIMEOUT, NULL);
    connectCloseAndFree(fd, data);
}

static void connectConnected(fd, data)
     int fd;
     ConnectData *data;
{
    storeAppend(data->entry, conn_established, strlen(conn_established));
    comm_set_fd_lifetime(fd, -1);	/* disable lifetime DPW */
    comm_set_select_handler_plus_timeout(data->remote, COMM_SELECT_TIMEOUT,
	(PF) connectReadTimeout, (void *) data, data->timeout);
    comm_set_select_handler(data->remote, COMM_SELECT_READ,
	(PF) connectReadRemote, (void *) data);
    comm_set_select_handler_plus_timeout(data->client, COMM_SELECT_TIMEOUT,
	(PF) connectReadTimeout, (void *) data, data->timeout);
    comm_set_select_handler(data->client, COMM_SELECT_READ,
	(PF) connectReadClient, (void *) data);
}


static void connectCloseAndFree(fd, data)
     int fd;
     ConnectData *data;
{
    if (fd >= 0) {
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    NULL,
	    NULL,
	    0);
	comm_close(data->remote);
    }
    safe_free(data);
}

void connectConnInProgress(fd, data)
     int fd;
     ConnectData *data;
{
    debug(26, 5, "connectConnInProgress: FD %d data=%p\n", fd, data);

    if (comm_connect(fd, data->host, data->port) != COMM_OK) {
	debug(26, 5, "connectConnInProgress: FD %d errno=%d", fd, errno);
	switch (errno) {
#if EINPROGRESS != EALREADY
	case EINPROGRESS:
#endif
	case EALREADY:
	    /* We are not connectedd yet. schedule this handler again */
	    comm_set_select_handler(fd, COMM_SELECT_WRITE,
		(PF) connectConnInProgress,
		(void *) data);
	    return;
	case EISCONN:
	    /* We are connected (doesn't comm_connect return
	     * COMM_OK on EISCONN?)
	     */
	    break;
	default:
	    cached_error_entry(data->entry, ERR_CONNECT_FAIL, xstrerror());
	    connectCloseAndFree(fd, data);
	    return;
	}
    }
    /* We are now fully connected */
    connectConnected(fd, data);
    return;
}


int connectStart(fd, url, method, mime_hdr, entry)
     int fd;
     char *url;
     int method;
     char *mime_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    ConnectData *data = (ConnectData *) xcalloc(1, sizeof(ConnectData));

    data->entry = entry;

    debug(26, 3, "connectStart: '%s %s'\n", RequestMethodStr[method], url);
    debug(26, 4, "            header: %s\n", mime_hdr);

    data->method = method;
    data->mime_hdr = mime_hdr;
    data->client = fd;
    data->timeout = getReadTimeout();

    /* Parse url. */
    if (connect_url_parser(url, data)) {
	cached_error_entry(entry, ERR_INVALID_URL, NULL);
	safe_free(data);
	return COMM_ERROR;
    }
    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(26, 4, "connectStart: Failed because we're out of sockets.\n");
	cached_error_entry(entry, ERR_NO_FDS, xstrerror());
	safe_free(data);
	return COMM_ERROR;
    }
    data->remote = sock;
#ifdef STAT_FD_ASSOC
    stat_fd_assoc(fd, sock);
#endif

    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(26, 4, "connectstart: Called without IP entry in ipcache. OR lookup failed.\n");
	cached_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	connectCloseAndFree(sock, data);
	return COMM_ERROR;
    }
    debug(26, 5, "connectStart: client=%d remote=%d\n", fd, sock);
    /* Install lifetime handler */
    comm_set_select_handler(sock,
	COMM_SELECT_LIFETIME,
	(PF) connectLifetimeExpire,
	(void *) data);
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    connectCloseAndFree(sock, data);
	    return COMM_ERROR;
	} else {
	    debug(26, 5, "connectStart: conn %d EINPROGRESS\n", sock);
	    /* The connection is in progress, install connect handler */
	    comm_set_select_handler(sock,
		COMM_SELECT_WRITE,
		(PF) connectConnInProgress,
		(void *) data);
	}
    }
    /* We got immediately connected. (can this happen?) */
    connectConnected(sock, data);
    return COMM_OK;
}
