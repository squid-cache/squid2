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
    char *type;
    char *mime_hdr;
    char type_id;
    int len;
    int offset;
    char buf[CONNECT_BUFSIZE];
    int remote;
    int client;
    time_t timeout;
} ConnectData;

static char conn_established[] = "HTTP/1.0 200 Connection established\r\n\r\n";

static int connect_url_parser _PARAMS((char *url, char *host, int *port, char *request));
static void connectLifetimeExpire _PARAMS((int fd, ConnectData * data));
static void connectReadRemote _PARAMS((int fd, ConnectData * data));
static void connectReadTimeout _PARAMS((int fd, ConnectData * data));
static void connectSendRemote _PARAMS((int fd, ConnectData * data));
static void connectReadClient _PARAMS((int fd, ConnectData * data));
static void connectConnectTimeout _PARAMS((int fd, ConnectData * data));
static void connectConnectRemote _PARAMS((int fd, ConnectData * data));
static void connectCloseAndFree _PARAMS((int fd, ConnectData * data));

extern intlist *connect_port_list;

static int connect_url_parser(url, host, port, request)
     char *url;
     char *host;
     int *port;
     char *request;
{
    static char hostbuf[MAX_URL];
    static char atypebuf[MAX_URL];
    int t;
    intlist *p = NULL;

    /* initialize everything */
    (*port) = 0;
    atypebuf[0] = hostbuf[0] = request[0] = host[0] = '\0';

    t = sscanf(url, "%[a-zA-Z]://%[^/]%s", atypebuf, hostbuf, request);
    if ((t < 2) || (strcasecmp(atypebuf, "conne") != 0)) {
	return -1;
    } else if (t == 2) {
	strcpy(request, "/");
    }
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = CONNECT_PORT;
    else {
	for (p = connect_port_list; p; p = p->next) {
	    if (*port == p->i)
		return 0;
	}
	return -1;
    }
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
	    storeReleaseRequest(entry, __FILE__,__LINE__);
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

static void connectConnectTimeout(fd, data)
     int fd;
     ConnectData *data;
{
    cached_error_entry(data->entry, ERR_CONNECT_FAIL, xstrerror());
    connectCloseAndFree(fd, data);
}

static void connectConnectRemote(fd, data)
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

int connectStart(fd, url, type, mime_hdr, entry)
     int fd;
     char *url;
     char *type;
     char *mime_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    ConnectData *data = (ConnectData *) xcalloc(1, sizeof(ConnectData));

    data->entry = entry;

    debug(26, 3, "connectStart: url:%s, type:%s\n", url, type);
    debug(26, 4, "            header: %s\n", mime_hdr);

    data->type = type;
    data->mime_hdr = mime_hdr;
    data->client = fd;
    data->timeout = getReadTimeout();

    /* Parse url. */
    if (connect_url_parser(url, data->host, &data->port, data->buf)) {
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
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    connectCloseAndFree(sock, data);
	    return COMM_ERROR;
	} else {
	    debug(26, 5, "connectStart: conn %d EINPROGRESS\n", sock);
	    return COMM_OK;
	}
    }
    data->remote = sock;
    /* Install connection complete handler. */
    debug(26, 5, "connectStart: client=%d remote=%d\n", fd, sock);
    comm_set_select_handler(sock,
	COMM_SELECT_LIFETIME,
	(PF) connectLifetimeExpire,
	(void *) data);
    comm_set_select_handler_plus_timeout(sock,
	COMM_SELECT_TIMEOUT,
	(PF) connectConnectTimeout,
	(void *) data,
	data->timeout);
    comm_set_select_handler(sock,
	COMM_SELECT_WRITE,
	(PF) connectConnectRemote,
	(void *) data);
    return COMM_OK;
}
