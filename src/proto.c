static char rcsid[] = "$Id$";
/*
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"		/* goes first */
#include <string.h>
#include <stdlib.h>

#include "ansihelp.h"		/* goes second */
#include "debug.h"
#include "comm.h"
#include "proto.h"		/* for  caddr_t */
#include "neighbors.h"
#include "store.h"
#include "cache_cf.h"
#include "ipcache.h"
#include "fdstat.h"
#include "stat.h"
#include "util.h"

int getFromCache _PARAMS((int fd, StoreEntry * entry, edge * e));
int getFromDefaultSource _PARAMS((int fd, StoreEntry * entry));
int getFromOrgSource _PARAMS((int fd, StoreEntry * entry));

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

extern int httpd_accel_mode;
extern ip_acl *local_ip_list;
extern char *tmp_error_buf;	/* main.c */
extern time_t neighbor_timeout;
extern stoplist *local_domain_list;
extern stoplist *inside_firewall_list;
extern single_parent_bypass;
extern char *dns_error_message;

extern int httpCachable _PARAMS((char *url, char *type, char *mime_hdr));
extern int ftpCachable _PARAMS((char *url, char *type, char *mime_hdr));
extern int gopherCachable _PARAMS((char *url, char *type, char *mime_hdr));
extern int objcacheStart _PARAMS((int fd, char *url, StoreEntry * entry));
extern int ipcache_unregister _PARAMS((char *name, int fd));
extern int proxyhttpStart _PARAMS((edge * e, char *url, StoreEntry * entry));
extern int httpStart _PARAMS((int unusedfd, char *url, char *type, char *mime_hdr, StoreEntry * entry));
extern int gopherStart _PARAMS((int unusedfd, char *url, StoreEntry * entry));
extern int ftpStart _PARAMS((int unusedfd, char *url, StoreEntry * entry));
#if USE_WAIS_RELAY
extern int waisStart _PARAMS((int unusedfd, char *url, char *type, char *mime_hdr, StoreEntry * entry));
#endif
extern char *storeToString _PARAMS((StoreEntry * e));
extern void fatal_dump _PARAMS((char *));

/* return 1 for cachable url
 * return 0 for uncachable url */
int proto_cachable(url, type, mime_hdr)
     char *url;
     char *type;
     char *mime_hdr;
{
    if (url == (char *) NULL)
	return 0;

    if (!strncasecmp(url, "http://", 7))
	return httpCachable(url, type, mime_hdr);
    if (!strncasecmp(url, "ftp://", 6))
	return ftpCachable(url, type, mime_hdr);
    if (!strncasecmp(url, "gopher://", 9))
	return gopherCachable(url, type, mime_hdr);
#if USE_WAIS_RELAY
    if (!strncasecmp(url, "wais://", 7))
	return 0;
#endif
    if (!strncasecmp(url, "cache_object://", 15))
	return 0;
    return 1;
}

/* called when DNS lookup is done by ipcache. */
int protoDispatchDNSHandle(fdunused, unused_hp, data)
     int fdunused;
     struct hostent *unused_hp;
     protodispatch_data *data;
{
    edge *e = NULL;
    struct in_addr srv_addr;
    struct hostent *hp = NULL;
    StoreEntry *entry = NULL;

    /* NOTE: We get here after a DNS lookup, whether or not the
     * lookup was successful.  Even if the URL hostname is bad,
     * we might still ping the hierarchy */

    entry = data->entry;

    BIT_RESET(entry->flag, IP_LOOKUP_PENDING);

    if (data->direct_fetch == DIRECT_YES) {
	if (ipcache_gethostbyname(data->host) == NULL) {
	    protoDNSError(data->fd, entry);
	    safe_free(data);
	    return 0;
	}
	hierarchy_log_append(data->url, HIER_DIRECT, 0, data->host);
	getFromOrgSource(data->fd, entry);
	safe_free(data);
	return 0;
    }
    if (data->direct_fetch == DIRECT_MAYBE && local_ip_list) {
	if ((hp = ipcache_gethostbyname(data->host)) == NULL) {
	    debug(1, "protoDispatchDNSHandle: Failure to lookup host: %s.\n",
		data->host);
	} else {
	    memcpy(&srv_addr, hp->h_addr_list[0], hp->h_length);
	    if (ip_access_check(srv_addr, local_ip_list) == IP_DENY) {
		hierarchy_log_append(data->url,
		    HIER_LOCAL_IP_DIRECT, 0,
		    data->host);
		getFromOrgSource(data->fd, entry);
		safe_free(data);
		return 0;
	    }
	}
    }
    if ((e = data->single_parent) &&
	(single_parent_bypass || data->direct_fetch == DIRECT_NO)) {
	/* Only one parent for this host, and okay to skip pinging stuff */
	hierarchy_log_append(data->url, HIER_SINGLE_PARENT, 0, e->host);
	getFromCache(data->fd, entry, e);
	safe_free(data);
	return 0;
    }
    if (data->n_edges == 0 && data->direct_fetch == DIRECT_NO) {
	hierarchy_log_append(data->url, HIER_NO_DIRECT_FAIL, 0, data->host);
	protoCantFetchObject(data->fd, entry,
	    "No neighbors or parents to query and the host is beyond your firewall.");
	safe_free(data);
	return 0;
    }
    if (!data->cachable && (e = getFirstParent(data->host))) {
	/* for uncachable objects we should not ping the hierarchy (because
	 * icpHandleUdp() won't properly deal with the ICP replies). */
	getFromCache(data->fd, entry, e);
	safe_free(data);
	return 0;
    } else if (neighborsUdpPing(data)) {
	/* call neighborUdpPing and start timeout routine */
	if ((entry->ping_status == DONE) || entry->status == STORE_OK) {
	    debug(0, "Starting a source ping for a valid object %s!\n",
		storeToString(entry));
	    fatal_dump(NULL);
	}
	entry->ping_status = WAITING;
	comm_set_select_handler_plus_timeout(data->fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) getFromDefaultSource,
	    (caddr_t) entry,
	    neighbor_timeout);
	safe_free(data);
	return 0;
    }
    if (data->direct_fetch == DIRECT_NO) {
	hierarchy_log_append(data->url, HIER_NO_DIRECT_FAIL, 0, data->host);
	protoCantFetchObject(data->fd, entry,
	    "No neighbors or parents were queried and the host is beyond your firewall.");
    } else {
	if (ipcache_gethostbyname(data->host) == NULL) {
	    protoDNSError(data->fd, entry);
	    safe_free(data);
	    return 0;
	}
	hierarchy_log_append(data->url, HIER_DIRECT, 0, data->host);
	getFromOrgSource(data->fd, entry);
    }
    safe_free(data);
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
    char *mime_hdr;
    int n;

    method = HTTP_OPS[entry->type_id];
    mime_hdr = store_mem_obj(entry, mime_hdr);

    debug(5, "protoDispatch: %s URL: %s\n", method, url);
    debug(10, "    mime_hdr: %s\n", mime_hdr);

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
    strncpy(data->host, host, HARVESTHOSTNAMELEN);

    data->inside_firewall = matchInsideFirewall(host);
    data->cachable = proto_cachable(url, method, mime_hdr);
    data->single_parent = getSingleParent(host, &n);
    data->n_edges = n;

    debug(2, "protoDispatch: inside_firewall = %d (%s)\n",
	data->inside_firewall,
	firewall_desc_str[data->inside_firewall]);
    debug(2, "protoDispatch:        cachable = %d\n", data->cachable);
    debug(2, "protoDispatch:         n_edges = %d\n", data->n_edges);
    debug(2, "protoDispatch:   single_parent = %s\n",
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
	ipcache_nbgethostbyname(data->host, fd, protoDispatchDNSHandle, data);
    } else if (data->n_edges == 0) {
	/* will fetch from source */
	data->direct_fetch = DIRECT_YES;
	ipcache_nbgethostbyname(data->host, fd, protoDispatchDNSHandle, data);
    } else if (local_ip_list) {
	/* Have to look up the url address so we can compare it */
	data->source_ping = getSourcePing();
	data->direct_fetch = DIRECT_MAYBE;
	ipcache_nbgethostbyname(data->host, fd, protoDispatchDNSHandle, data);
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
	ipcache_nbgethostbyname(data->host, fd, protoDispatchDNSHandle, data);
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

    debug(5, "protoUndispatch FD %d <URL:%s>\n", fd, url);

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
	    debug(5, "protoUndispatch: ipcache failed to unregister '%s'\n",
		host);
	    return 0;
	} else {
	    debug(5, "protoUndispatch: the entry is stranded with a pending DNS event\n");
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
	debug(1, "protoCancelTimeout: WARNING! Unable to locate a client FD\n");
	debug(1, "--> <URL:%s>\n", entry->url);
	debug(5, "%s\n", storeToString(entry));
	return;
    }
    debug(2, "protoCancelTimeout: FD %d <URL:%s>\n", fd, entry->url);
    if (fdstat_type(fd) != Socket) {
	debug(0, "FD %d: Someone called protoCancelTimeout() on a non-socket\n",
	    fd);
	fatal_dump(NULL);
    }
    /* cancel the timeout handler */
    comm_set_select_handler_plus_timeout(fd,
	COMM_SELECT_TIMEOUT | COMM_SELECT_READ,
	(PF) 0, (caddr_t) 0, (time_t) 0);
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
	debug(5, "getFromDefaultSource: Timeout occured pinging for <URL:%s>\n",
	    url);
    }
    /* Check if someone forgot to disable the read timer */
    if (fd && BIT_TEST(entry->flag, REQ_DISPATCHED)) {
	if (entry->ping_status == TIMEOUT) {
	    debug(0, "FD %d Someone forgot to disable the read timer.\n", fd);
	    debug(0, "--> <URL:%s>\n", entry->url);
	} else {
	    debug(0, "FD %d Someone is refetching this object.\n", fd);
	    debug(0, "--> <URL:%s>\n", entry->url);
	}
	return 0;
    }
    BIT_SET(entry->flag, REQ_DISPATCHED);

    if ((e = store_mem_obj(entry, e_pings_first_miss))) {
	hierarchy_log_append(url, HIER_FIRST_PARENT_MISS, fd, e->host);
	return getFromCache(fd, entry, e);
    }
    if (sscanf(url, "%[^:]://%[^/]", junk, hostbuf) != 2) {
	debug(0, "getFromDefaultSource: Invalid URL '%s'\n", url);
	debug(0, "getFromDefaultSource: --> shouldn't have gotten this far!\n");
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
    char *type = HTTP_OPS[entry->type_id];
    char *mime_hdr = store_mem_obj(entry, mime_hdr);

    debug(5, "getFromCache: FD %d <URL:%s>\n", fd, entry->url);
    debug(5, "getFromCache: --> type = %s\n", type);
    debug(5, "getFromCache: --> getting from '%s'\n", e ? e->host : "source");

    /*
     * If this is called from our neighbor detection, then we have to
     * reset the signal handler.  We probably need to check for a race
     * here on a previous close of the client connection.
     */
    protoCancelTimeout(fd, entry);

    if (e) {
	return proxyhttpStart(e, url, entry);
    } else if (strncasecmp(url, "http://", 7) == 0) {
	return httpStart(fd, url, type, mime_hdr, entry);
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
#if USE_WAIS_RELAY
    } else if (strncasecmp(url, "wais://", 7) == 0) {
	return waisStart(fd, url, type, mime_hdr, entry);
#endif
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

    debug(1, "protoNotImplemented: Cannot retrieve <URL:%s>\n", url);

    buf[0] = '\0';
    if (httpd_accel_mode)
	strcpy(buf, "cached is running in HTTPD accelerator mode, so it does not allow the normal URL syntax.");
    else
	sprintf(buf, "Your URL may be incorrect: '%s'\n", url);

    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"CACHE-PROTO",
	501,
	"Unsupported protocol",
	buf,
	HARVEST_VERSION,
	comm_hostname());
    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_501",		/* PROTO NOT IMPLEMENTED */
	"NULL");
#endif
    return 0;
}

static int protoCantFetchObject(fd, entry, reason)
     int fd;
     StoreEntry *entry;
     char *reason;
{
    static char buf[2048];

    debug(1, "protoCantFetchObject: FD %d %s\n", fd, reason);
    debug(1, "--> <URL:%s>\n", entry->url);

    buf[0] = '\0';
    sprintf(buf, "%s\n\nThe cache administrator may need to double-check the cache configuration.", reason);

    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"CACHE-PROTO",
	502,
	"Cache cannot fetch the requested object.",
	buf,
	HARVEST_VERSION,
	comm_hostname());
    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_502",		/* PROTO CANNOT FETCH */
	"NULL");
#endif
    return 0;
}

static int protoDNSError(fd, entry)
     int fd;
     StoreEntry *entry;
{
    debug(2, "protoDNSError: FD %d <URL:%s>\n", fd, entry->url);
    protoCancelTimeout(fd, entry);
    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"DNS",
	102,
	"DNS name lookup failure",
	dns_error_message,
	HARVEST_VERSION,
	comm_hostname());
    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_102",		/* PROTO DNS FAIL */
	"NULL");
#endif
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
    stoplist *s = NULL;
    if (!inside_firewall_list)
	/* no domains, all hosts are "inside" the firewall */
	return NO_FIREWALL;
    for (s = inside_firewall_list; s; s = s->next) {
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
    stoplist *s = NULL;
    for (s = local_domain_list; s; s = s->next) {
	if ((offset = strlen(host) - strlen(s->key)) < 0)
	    continue;
	if (strcasecmp(s->key, host + offset) == 0)
	    /* a match */
	    return 1;
    }
    return 0;
}
