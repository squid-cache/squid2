/* $Id$ */

/*
 * DEBUG: Section 17          proto:
 */

#include "squid.h"

static int matchInsideFirewall _PARAMS((char *host));
static int matchLocalDomain _PARAMS((char *host));
static int protoCantFetchObject _PARAMS((int, StoreEntry *, char *));
static int protoNotImplemented _PARAMS((int fd_unused, char *url, StoreEntry * entry));
static int protoDNSError _PARAMS((int fd_unused, StoreEntry * entry));

#define OUTSIDE_FIREWALL 0
#define INSIDE_FIREWALL  1
#define NO_FIREWALL      2

/* for debugging */
static char *firewall_desc_str[] =
{
    "OUTSIDE_FIREWALL",
    "INSIDE_FIREWALL",
    "NO_FIREWALL"
};

char *IcpOpcodeStr[] =
{
    "ICP_INVALID",
    "ICP_QUERY",
    "ICP_HIT",
    "ICP_MISS",
    "ICP_ERR",
    "ICP_SEND",
    "ICP_SENDA",
    "ICP_DATABEG",
    "ICP_DATA",
    "ICP_DATAEND",
    "ICP_SECHO",
    "ICP_DECHO",
    "ICP_END"
};


extern int httpd_accel_mode;
extern ip_acl *local_ip_list;
extern time_t neighbor_timeout;
extern single_parent_bypass;
extern char *dns_error_message;

/* return 1 for cachable url
 * return 0 for uncachable url */
int proto_cachable(url, method, request_hdr)
     char *url;
     int method;
     char *request_hdr;
{
    if (url == (char *) NULL)
	return 0;

    if (!strncasecmp(url, "http://", 7))
	return httpCachable(url, method, request_hdr);
    if (!strncasecmp(url, "ftp://", 6))
	return ftpCachable(url);
    if (!strncasecmp(url, "gopher://", 9))
	return gopherCachable(url);
    if (!strncasecmp(url, "wais://", 7))
	return 0;
    if (!strncasecmp(url, "connect://", 8))
	return 0;
    if (!strncasecmp(url, "cache_object://", 15))
	return 0;
    return 1;
}

/* called when DNS lookup is done by ipcache. */
int protoDispatchDNSHandle(unused1, unused2, data)
     int unused1;		/* filedescriptor */
     struct hostent *unused2;
     void *data;
{
    edge *e = NULL;
    struct in_addr srv_addr;
    struct hostent *hp = NULL;
    StoreEntry *entry = NULL;
    protodispatch_data *protoData = (protodispatch_data *) data;

    /* NOTE: We get here after a DNS lookup, whether or not the
     * lookup was successful.  Even if the URL hostname is bad,
     * we might still ping the hierarchy */

    entry = protoData->entry;

    BIT_RESET(entry->flag, IP_LOOKUP_PENDING);

    if (protoData->direct_fetch == DIRECT_YES) {
	if (ipcache_gethostbyname(protoData->host) == NULL) {
	    protoDNSError(protoData->fd, entry);
	    safe_free(protoData);
	    return 0;
	}
	hierarchy_log_append(protoData->url, HIER_DIRECT, 0, protoData->host);
	getFromOrgSource(protoData->fd, entry);
	safe_free(protoData);
	return 0;
    }
    if (protoData->direct_fetch == DIRECT_MAYBE && local_ip_list) {
	if ((hp = ipcache_gethostbyname(protoData->host)) == NULL) {
	    debug(17, 1, "protoDispatchDNSHandle: Failure to lookup host: %s.\n",
		protoData->host);
	} else {
	    memcpy(&srv_addr, hp->h_addr_list[0], hp->h_length);
	    if (ip_access_check(srv_addr, local_ip_list) == IP_DENY) {
		hierarchy_log_append(protoData->url,
		    HIER_LOCAL_IP_DIRECT, 0,
		    protoData->host);
		getFromOrgSource(protoData->fd, entry);
		safe_free(protoData);
		return 0;
	    }
	}
    }
    if ((e = protoData->single_parent) &&
	(single_parent_bypass || protoData->direct_fetch == DIRECT_NO)) {
	/* Only one parent for this host, and okay to skip pinging stuff */
	hierarchy_log_append(protoData->url, HIER_SINGLE_PARENT, 0, e->host);
	getFromCache(protoData->fd, entry, e);
	safe_free(protoData);
	return 0;
    }
    if (protoData->n_edges == 0 && protoData->direct_fetch == DIRECT_NO) {
	hierarchy_log_append(protoData->url, HIER_NO_DIRECT_FAIL, 0, protoData->host);
	protoCantFetchObject(protoData->fd, entry,
	    "No neighbors or parents to query and the host is beyond your firewall.");
	safe_free(protoData);
	return 0;
    }
    if (!protoData->cachable && (e = getFirstParent(protoData->host))) {
	/* for uncachable objects we should not ping the hierarchy (because
	 * icpHandleUdp() won't properly deal with the ICP replies). */
	getFromCache(protoData->fd, entry, e);
	safe_free(protoData);
	return 0;
    } else if (neighborsUdpPing(protoData)) {
	/* call neighborUdpPing and start timeout routine */
	if ((entry->ping_status == DONE) || entry->status == STORE_OK) {
	    debug(17, 0, "Starting a source ping for a valid object %s!\n",
		storeToString(entry));
	    fatal_dump(NULL);
	}
	entry->ping_status = WAITING;
	comm_set_select_handler_plus_timeout(protoData->fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) getFromDefaultSource,
	    (void *) entry,
	    neighbor_timeout);
	safe_free(protoData);
	return 0;
    }
    if (protoData->direct_fetch == DIRECT_NO) {
	hierarchy_log_append(protoData->url, HIER_NO_DIRECT_FAIL, 0, protoData->host);
	protoCantFetchObject(protoData->fd, entry,
	    "No neighbors or parents were queried and the host is beyond your firewall.");
    } else {
	if (ipcache_gethostbyname(protoData->host) == NULL) {
	    protoDNSError(protoData->fd, entry);
	    safe_free(protoData);
	    return 0;
	}
	hierarchy_log_append(protoData->url, HIER_DIRECT, 0, protoData->host);
	getFromOrgSource(protoData->fd, entry);
    }
    safe_free(protoData);
    return 0;
}

int protoDispatch(fd, url, entry)
     int fd;
     char *url;
     StoreEntry *entry;
{
    static char junk[BUFSIZ];
    static char hostbuf[BUFSIZ];
    char *s = NULL;
    char *host = NULL;
    protodispatch_data *data = NULL;
    char *method;
    char *request_hdr;
    int n;

    method = RequestMethodStr[entry->method];
    request_hdr = entry->mem_obj->mime_hdr;

    debug(17, 5, "protoDispatch: %s URL: %s\n", method, url);
    debug(17, 10, "request_hdr: %s\n", request_hdr);

    /* Start retrieval process. */
    if (strncasecmp(url, "cache_object:", 13) == 0)
	return objcacheStart(fd, url, entry);

    /* Check for Proxy request in Accel mode */
    if (httpd_accel_mode &&
	strncmp(url, getAccelPrefix(), strlen(getAccelPrefix())) &&
	!getAccelWithProxy())
	return protoNotImplemented(fd, url, entry);

    data = (protodispatch_data *) xcalloc(1, sizeof(protodispatch_data));

    data->fd = fd;
    data->url = url;
    data->entry = entry;

    junk[0] = '\0';
    hostbuf[0] = '\0';
    sscanf(url, "%[^:]://%[^/]", junk, hostbuf);
    host = &hostbuf[0];
    if ((s = strchr(host, '@')))
	host = s + 1;
    if ((s = strchr(host, ':')))
	*s = '\0';
    strncpy(data->host, host, SQUIDHOSTNAMELEN);

    data->inside_firewall = matchInsideFirewall(host);
    data->cachable = proto_cachable(url, entry->method, request_hdr);
    data->single_parent = getSingleParent(host, &n);
    data->n_edges = n;

    debug(17, 2, "protoDispatch: inside_firewall = %d (%s)\n",
	data->inside_firewall,
	firewall_desc_str[data->inside_firewall]);
    debug(17, 2, "protoDispatch:        cachable = %d\n", data->cachable);
    debug(17, 2, "protoDispatch:         n_edges = %d\n", data->n_edges);
    debug(17, 2, "protoDispatch:   single_parent = %s\n",
	data->single_parent ? data->single_parent->host : "N/A");

    if (!data->inside_firewall) {
	/* There are firewall restrictsions, and this host is outside. */
	/* No DNS lookups, call protoDispatchDNSHandle() directly */
	BIT_RESET(data->entry->flag, IP_LOOKUP_PENDING);
	data->source_ping = 0;
	data->direct_fetch = DIRECT_NO;
	protoDispatchDNSHandle(fd, (struct hostent *) NULL, data);
    } else if (matchLocalDomain(host) || !data->cachable) {
	/* will fetch from source */
	data->direct_fetch = DIRECT_YES;
	ipcache_nbgethostbyname(data->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) data);
    } else if (data->n_edges == 0) {
	/* will fetch from source */
	data->direct_fetch = DIRECT_YES;
	ipcache_nbgethostbyname(data->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) data);
    } else if (local_ip_list) {
	/* Have to look up the url address so we can compare it */
	data->source_ping = getSourcePing();
	data->direct_fetch = DIRECT_MAYBE;
	ipcache_nbgethostbyname(data->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) data);
    } else if (data->single_parent && single_parent_bypass &&
	!(data->source_ping = getSourcePing())) {
	/* will fetch from single parent */
	data->direct_fetch = DIRECT_MAYBE;
	BIT_RESET(data->entry->flag, IP_LOOKUP_PENDING);
	protoDispatchDNSHandle(fd, (struct hostent *) NULL, data);
    } else {
	/* will use ping resolution */
	data->source_ping = getSourcePing();
	data->direct_fetch = DIRECT_MAYBE;
	ipcache_nbgethostbyname(data->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) data);
    }
    return 0;
}

/* Use to undispatch a particular url/fd from DNS pending list */
/* I have it here because the code that understand protocol/url */
/* should be here. */
int protoUndispatch(fd, url, entry)
     int fd;
     char *url;
     StoreEntry *entry;
{
    static char junk[BUFSIZ];
    static char hostbuf[BUFSIZ];
    char *s = NULL;
    char *host = NULL;

    debug(17, 5, "protoUndispatch FD %d <URL:%s>\n", fd, url);

    /* Cache objects don't need to be unregistered  */
    if (strncasecmp(url, "cache_object:", 13) == 0)
	return 0;

    hostbuf[0] = '\0';
    junk[0] = '\0';
    sscanf(url, "%[^:]://%[^/]", junk, hostbuf);
    host = &hostbuf[0];
    if ((s = strchr(host, '@')))
	host = s + 1;
    if ((s = strchr(host, ':')))
	*s = '\0';

    /* clean up DNS pending list for this name/fd look up here */
    if (*host) {
	if (!ipcache_unregister(host, fd)) {
	    debug(17, 5, "protoUndispatch: ipcache failed to unregister '%s'\n",
		host);
	    return 0;
	} else {
	    debug(17, 5, "protoUndispatch: the entry is stranded with a pending DNS event\n");
	    /* Have to force a storeabort() on this entry */
	    if (entry)
		protoDNSError(fd, entry);
	    return 1;
	}
    }
    return 0;
}

static void protoCancelTimeout(fd, entry)
     int fd;
     StoreEntry *entry;
{
    /* If fd = 0 then this thread was called from neighborsUdpAck and
     * we must look up the FD in the pending list. */
    if (!fd)
	fd = fd_of_first_client(entry);
    if (fd < 1) {
	debug(17, 1, "protoCancelTimeout: WARNING! Unable to locate a client FD\n");
	debug(17, 1, "--> <URL:%s>\n", entry->url);
	debug(17, 5, "%s\n", storeToString(entry));
	return;
    }
    debug(17, 2, "protoCancelTimeout: FD %d <URL:%s>\n", fd, entry->url);
    if (fdstat_type(fd) != Socket) {
	debug(17, 0, "FD %d: Someone called protoCancelTimeout() on a non-socket\n",
	    fd);
	fatal_dump(NULL);
    }
    /* cancel the timeout handler */
    comm_set_select_handler_plus_timeout(fd,
	COMM_SELECT_TIMEOUT | COMM_SELECT_READ,
	(PF) 0, (void *) 0, (time_t) 0);
}

/*
 *  Called from comm_select() if neighbor pings timeout or from
 *  neighborsUdpAck() if all parents and neighbors miss.
 */
int getFromDefaultSource(fd, entry)
     int fd;
     StoreEntry *entry;
{
    edge *e = NULL;
    static char junk[BUFSIZ];
    static char hostbuf[BUFSIZ];
    char *url = NULL;
    char *t = NULL;
    char *host = NULL;

    url = entry->url;

    /* if fd != 0 then we were called from comm_select() because the
     * timeout occured.  Otherwise we were called from neighborsUdpAck(). */

    if (fd) {
	entry->ping_status = TIMEOUT;
	debug(17, 5, "getFromDefaultSource: Timeout occured pinging for <URL:%s>\n",
	    url);
    }
    /* Check if someone forgot to disable the read timer */
    if (fd && BIT_TEST(entry->flag, ENTRY_DISPATCHED)) {
	if (entry->ping_status == TIMEOUT) {
	    debug(17, 0, "FD %d Someone forgot to disable the read timer.\n", fd);
	    debug(17, 0, "--> <URL:%s>\n", entry->url);
	} else {
	    debug(17, 0, "FD %d Someone is refetching this object.\n", fd);
	    debug(17, 0, "--> <URL:%s>\n", entry->url);
	}
	return 0;
    }
    BIT_SET(entry->flag, ENTRY_DISPATCHED);

    if ((e = entry->mem_obj->e_pings_first_miss)) {
	hierarchy_log_append(url, HIER_FIRST_PARENT_MISS, fd, e->host);
	return getFromCache(fd, entry, e);
    }
    if (sscanf(url, "%[^:]://%[^/]", junk, hostbuf) != 2) {
	debug(17, 0, "getFromDefaultSource: Invalid URL '%s'\n", url);
	debug(17, 0, "getFromDefaultSource: --> shouldn't have gotten this far!\n");
	return 0;
    }
    host = &hostbuf[0];
    if ((t = strchr(host, '@')))
	host = t + 1;
    if ((t = strchr(host, ':')))
	*t = '\0';
    if (matchInsideFirewall(host)) {
	if (ipcache_gethostbyname(host) == NULL) {
	    return protoDNSError(fd, entry);
	}
	hierarchy_log_append(url, HIER_DIRECT, fd, host);
	return getFromOrgSource(fd, entry);
    }
    if ((e = getSingleParent(host, NULL))) {
	/* last chance effort; maybe there was a single_parent and a ICP
	 * packet got lost */
	hierarchy_log_append(url, HIER_SINGLE_PARENT, fd, e->host);
	return getFromCache(fd, entry, e);
    }
    hierarchy_log_append(url, HIER_NO_DIRECT_FAIL, fd, host);
    protoCancelTimeout(fd, entry);
    protoCantFetchObject(fd, entry,
	"No ICP replies received and the host is beyond the firewall.");
    return 0;
}

int getFromOrgSource(fd, entry)
     int fd;
     StoreEntry *entry;
{
    return getFromCache(fd, entry, 0);
}


int getFromCache(fd, entry, e)
     int fd;
     StoreEntry *entry;
     edge *e;
{
    char *url = entry->url;
    char *request_hdr = entry->mem_obj->mime_hdr;

    debug(17, 5, "getFromCache: FD %d <URL:%s>\n", fd, entry->url);
    debug(17, 5, "getFromCache: --> type = %s\n",
	RequestMethodStr[entry->method]);
    debug(17, 5, "getFromCache: --> getting from '%s'\n", e ? e->host : "source");

    /*
     * If this is called from our neighbor detection, then we have to
     * reset the signal handler.  We probably need to check for a race
     * here on a previous close of the client connection.
     */
    protoCancelTimeout(fd, entry);

    if (e) {
	return proxyhttpStart(e, url, entry);
    } else if (strncasecmp(url, "http://", 7) == 0) {
	return httpStart(fd, url, entry->method, request_hdr, entry);
    } else if (strncasecmp(url, "gopher://", 9) == 0) {
	return gopherStart(fd, url, entry);
    } else if (strncasecmp(url, "news://", 7) == 0) {
	return protoNotImplemented(fd, url, entry);
    } else if (strncasecmp(url, "file://", 7) == 0) {
#ifndef NO_FTP_FOR_FILE
	return ftpStart(fd, url, entry);
#else
	return protoNotImplemented(fd, url, entry);
#endif
    } else if (strncasecmp(url, "ftp://", 6) == 0) {
	return ftpStart(fd, url, entry);
    } else if (strncasecmp(url, "wais://", 7) == 0) {
	return waisStart(fd, url, entry->method, request_hdr, entry);
    } else if (strncasecmp(url, "connect://", 8) == 0) {
	return connectStart(fd, url, entry->method, request_hdr, entry);
    } else if (strncasecmp(url, "dht://", 6) == 0) {
	return protoNotImplemented(fd, url, entry);
    } else {
	return protoNotImplemented(fd, url, entry);
    }
    /* NOTREACHED */
}


static int protoNotImplemented(fd, url, entry)
     int fd;
     char *url;
     StoreEntry *entry;
{
    static char buf[256];

    debug(17, 1, "protoNotImplemented: Cannot retrieve <URL:%s>\n", url);

    buf[0] = '\0';
    if (httpd_accel_mode)
	strcpy(buf, "cached is running in HTTPD accelerator mode, so it does not allow the normal URL syntax.");
    else
	sprintf(buf, "Your URL may be incorrect: '%s'\n", url);

    cached_error_entry(entry, ERR_NOT_IMPLEMENTED, NULL);
    return 0;
}

static int protoCantFetchObject(fd, entry, reason)
     int fd;
     StoreEntry *entry;
     char *reason;
{
    static char buf[2048];

    debug(17, 1, "protoCantFetchObject: FD %d %s\n", fd, reason);
    debug(17, 1, "--> <URL:%s>\n", entry->url);

    buf[0] = '\0';
    sprintf(buf, "%s\n\nThe cache administrator may need to double-check the cache configuration.",
	reason);
    cached_error_entry(entry, ERR_CANNOT_FETCH, buf);
    return 0;
}

static int protoDNSError(fd, entry)
     int fd;
     StoreEntry *entry;
{
    debug(17, 2, "protoDNSError: FD %d <URL:%s>\n", fd, entry->url);
    protoCancelTimeout(fd, entry);
    cached_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
    return 0;
}

/*
 * return 0 if the host is outside the firewall (no domains matched), and
 * return 1 if the host is inside the firewall or no domains at all.
 */
static int matchInsideFirewall(host)
     char *host;
{
    int offset;
    wordlist *s = getInsideFirewallList();;
    if (!s)
	/* no domains, all hosts are "inside" the firewall */
	return NO_FIREWALL;
    for (; s; s = s->next) {
	if (!strcasecmp(s->key, "none"))
	    /* no domains are inside the firewall, all domains are outside */
	    return OUTSIDE_FIREWALL;
	if ((offset = strlen(host) - strlen(s->key)) < 0)
	    continue;
	if (strcasecmp(s->key, host + offset) == 0)
	    /* a match, this host is inside the firewall */
	    return INSIDE_FIREWALL;
    }
    /* all through the list and no domains matched, this host must
     * not be inside the firewall, it must be outside */
    return OUTSIDE_FIREWALL;
}

static int matchLocalDomain(host)
     char *host;
{
    int offset;
    wordlist *s = NULL;
    for (s = getLocalDomainList(); s; s = s->next) {
	if ((offset = strlen(host) - strlen(s->key)) < 0)
	    continue;
	if (strcasecmp(s->key, host + offset) == 0)
	    /* a match */
	    return 1;
    }
    return 0;
}
