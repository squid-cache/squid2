/*
 * $Id$
 *
 * DEBUG: section 17    Neighbor Selection
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

static int matchInsideFirewall _PARAMS((char *host));
static int matchLocalDomain _PARAMS((char *host));
static int protoCantFetchObject _PARAMS((int, StoreEntry *, char *));
static int protoNotImplemented _PARAMS((int fd_unused, char *url, StoreEntry * entry));
static int protoDNSError _PARAMS((int fd_unused, StoreEntry * entry));
static void protoDataFree _PARAMS((int fdunused, protodispatch_data *));

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
    "ICP_OP_UNUSED0",
    "ICP_OP_UNUSED1",
    "ICP_OP_UNUSED2",
    "ICP_OP_UNUSED3",
    "ICP_OP_UNUSED4",
    "ICP_OP_UNUSED5",
    "ICP_OP_UNUSED6",
    "ICP_OP_UNUSED7",
    "ICP_OP_UNUSED8",
    "ICP_RELOADING",	/* access denied while store is reloading */
    "ICP_DENIED",
    "ICP_HIT_OBJ",
    "ICP_END"
};


extern int httpd_accel_mode;
extern ip_acl *local_ip_list;
extern ip_acl *firewall_ip_list;
extern time_t neighbor_timeout;
extern single_parent_bypass;

static void protoDataFree(fdunused, protoData)
     int fdunused;
     protodispatch_data *protoData;
{
    requestUnlink(protoData->request);
    safe_free(protoData);
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
    protodispatch_data *protoData = (protodispatch_data *) data;
    StoreEntry *entry = protoData->entry;
    request_t *req = protoData->request;

    /* NOTE: We get here after a DNS lookup, whether or not the
     * lookup was successful.  Even if the URL hostname is bad,
     * we might still ping the hierarchy */

    BIT_RESET(entry->flag, IP_LOOKUP_PENDING);

    if (protoData->direct_fetch == DIRECT_YES) {
	if (ipcache_gethostbyname(req->host, 0) == NULL) {
	    protoDNSError(protoData->fd, entry);
	    return 0;
	}
	hierarchy_log_append(entry, HIER_DIRECT, 0, req->host);
	getFromCache(protoData->fd, entry, NULL, req);
	return 0;
    }
    if (protoData->direct_fetch == DIRECT_MAYBE && (local_ip_list || firewall_ip_list)) {
	if ((hp = ipcache_gethostbyname(req->host, 0)) == NULL) {
	    debug(17, 1, "Unknown host: %s\n", req->host);
	} else if (firewall_ip_list) {
	    xmemcpy(&srv_addr, hp->h_addr_list[0], hp->h_length);
	    if (ip_access_check(srv_addr, firewall_ip_list) == IP_DENY) {
		hierarchy_log_append(entry,
		    HIER_LOCAL_IP_DIRECT, 0,
		    req->host);
		getFromCache(protoData->fd, entry, NULL, req);
		return 0;
	    }
	} else if (local_ip_list) {
	    xmemcpy(&srv_addr, hp->h_addr_list[0], hp->h_length);
	    if (ip_access_check(srv_addr, local_ip_list) == IP_DENY) {
		hierarchy_log_append(entry,
		    HIER_LOCAL_IP_DIRECT, 0,
		    req->host);
		getFromCache(protoData->fd, entry, NULL, req);
		return 0;
	    }
	}
    }
    if ((e = protoData->single_parent) &&
	(single_parent_bypass || protoData->direct_fetch == DIRECT_NO)) {
	/* Only one parent for this host, and okay to skip pinging stuff */
	hierarchy_log_append(entry, HIER_SINGLE_PARENT, 0, e->host);
	getFromCache(protoData->fd, entry, e, req);
	return 0;
    }
    if (protoData->n_edges == 0 && protoData->direct_fetch == DIRECT_NO) {
	hierarchy_log_append(entry, HIER_NO_DIRECT_FAIL, 0, req->host);
	protoCantFetchObject(protoData->fd, entry,
	    "No neighbors or parents to query and the host is beyond your firewall.");
	return 0;
    }
    if (!neighbors_do_private_keys && !protoData->query_neighbors && (e = getFirstUpParent(req))) {
	/* for private objects we should just fetch directly (because
	 * icpHandleUdp() won't properly deal with the ICP replies). */
	hierarchy_log_append(entry, HIER_FIRSTUP_PARENT, 0, e->host);
	getFromCache(protoData->fd, entry, e, req);
	return 0;
    } else if (neighborsUdpPing(protoData)) {
	/* call neighborUdpPing and start timeout routine */
	if ((entry->ping_status == PING_DONE) || entry->store_status == STORE_OK) {
	    debug(17, 0, "Starting a source ping for a valid object %s!\n",
		storeToString(entry));
	    fatal_dump(NULL);
	}
	entry->ping_status = PING_WAITING;
	comm_set_select_handler_plus_timeout(protoData->fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) getFromDefaultSource,
	    (void *) entry,
	    neighbor_timeout);
	return 0;
    }
    if (protoData->direct_fetch == DIRECT_NO) {
	hierarchy_log_append(entry, HIER_NO_DIRECT_FAIL, 0, req->host);
	protoCantFetchObject(protoData->fd, entry,
	    "No neighbors or parents were queried and the host is beyond your firewall.");
    } else {
	if (ipcache_gethostbyname(req->host, 0) == NULL) {
	    protoDNSError(protoData->fd, entry);
	    return 0;
	}
	hierarchy_log_append(entry, HIER_DIRECT, 0, req->host);
	getFromCache(protoData->fd, entry, NULL, req);
    }
    return 0;
}

int protoDispatch(fd, url, entry, request)
     int fd;
     char *url;
     StoreEntry *entry;
     request_t *request;
{
    protodispatch_data *protoData = NULL;
    char *method;
    char *request_hdr;
    int n;

    method = RequestMethodStr[request->method];
    request_hdr = entry->mem_obj->mime_hdr;

    debug(17, 5, "protoDispatch: %s URL: %s\n", method, url);
    debug(17, 10, "request_hdr: %s\n", request_hdr);

    if (request->protocol == PROTO_CACHEOBJ)
	return getFromCache(fd, entry, NULL, request);
    if (request->protocol == PROTO_WAIS)
	return getFromCache(fd, entry, NULL, request);

    protoData = xcalloc(1, sizeof(protodispatch_data));
    protoData->fd = fd;
    protoData->url = url;
    protoData->entry = entry;
    protoData->request = requestLink(request);
    entry->mem_obj->request = requestLink(request);
    comm_add_close_handler(fd,
	(PF) protoDataFree,
	(void *) protoData);

    protoData->inside_firewall = matchInsideFirewall(request->host);
    protoData->query_neighbors = BIT_TEST(entry->flag, HIERARCHICAL);
    protoData->single_parent = getSingleParent(request, &n);
    protoData->n_edges = n;

    debug(17, 2, "protoDispatch: inside_firewall = %d (%s)\n",
	protoData->inside_firewall,
	firewall_desc_str[protoData->inside_firewall]);
    debug(17, 2, "protoDispatch: query_neighbors = %d\n", protoData->query_neighbors);
    debug(17, 2, "protoDispatch:         n_edges = %d\n", protoData->n_edges);
    debug(17, 2, "protoDispatch:   single_parent = %s\n",
	protoData->single_parent ? protoData->single_parent->host : "N/A");

    if (!protoData->inside_firewall) {
	/* There are firewall restrictsions, and this host is outside. */
	/* No DNS lookups, call protoDispatchDNSHandle() directly */
	BIT_RESET(protoData->entry->flag, IP_LOOKUP_PENDING);
	protoData->source_ping = 0;
	protoData->direct_fetch = DIRECT_NO;
	protoDispatchDNSHandle(fd, (struct hostent *) NULL, protoData);
    } else if (firewall_ip_list) {
	/* Have to look up the url address so we can compare it */
	protoData->source_ping = getSourcePing();
	protoData->direct_fetch = DIRECT_MAYBE;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (matchLocalDomain(request->host) || !protoData->query_neighbors) {
	/* will fetch from source */
	protoData->direct_fetch = DIRECT_YES;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (protoData->n_edges == 0) {
	/* will fetch from source */
	protoData->direct_fetch = DIRECT_YES;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (local_ip_list) {
	/* Have to look up the url address so we can compare it */
	protoData->source_ping = getSourcePing();
	protoData->direct_fetch = DIRECT_MAYBE;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (protoData->single_parent && single_parent_bypass &&
	!(protoData->source_ping = getSourcePing())) {
	/* will fetch from single parent */
	protoData->direct_fetch = DIRECT_MAYBE;
	BIT_RESET(protoData->entry->flag, IP_LOOKUP_PENDING);
	protoDispatchDNSHandle(fd, (struct hostent *) NULL, protoData);
    } else {
	/* will use ping resolution */
	protoData->source_ping = getSourcePing();
	protoData->direct_fetch = DIRECT_MAYBE;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    }
    return 0;
}

/* Use to undispatch a particular url/fd from DNS pending list */
/* I have it here because the code that understand protocol/url */
/* should be here. */
int protoUndispatch(fd, url, entry, request)
     int fd;
     char *url;
     StoreEntry *entry;
     request_t *request;
{
    debug(17, 5, "protoUndispatch FD %d <URL:%s>\n", fd, url);

    /* Cache objects don't need to be unregistered  */
    if (request->protocol == PROTO_CACHEOBJ)
	return 0;

    /* clean up DNS pending list for this name/fd look up here */
    if (!ipcache_unregister(request->host, fd)) {
	debug(17, 5, "protoUndispatch: ipcache failed to unregister '%s'\n",
	    request->host);
	return 0;
    }
    /* The pending DNS lookup was cleared, now have to junk the entry */
    debug(17, 5, "protoUndispatch: the entry is stranded with a pending DNS event\n");
    if (entry)
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
    return 1;
}

void protoCancelTimeout(fd, entry)
     int fd;
     StoreEntry *entry;
{
    /* If fd = 0 then this thread was called from neighborsUdpAck and
     * we must look up the FD in the pending list. */
    if (!fd)
	fd = fd_of_first_client(entry);
    if (fd < 1) {
	debug(17, 1, "protoCancelTimeout: No client for '%s'\n", entry->url);
	return;
    }
    debug(17, 2, "protoCancelTimeout: FD %d <URL:%s>\n", fd, entry->url);
    if (fdstat_type(fd) != FD_SOCKET) {
	debug(17, 0, "FD %d: Someone called protoCancelTimeout() on a non-socket\n",
	    fd);
	fatal_dump(NULL);
    }
    /* cancel the timeout handler */
    comm_set_select_handler_plus_timeout(fd,
	COMM_SELECT_TIMEOUT,
	NULL,
	NULL,
	0);
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
    char *url = NULL;
    request_t *request = entry->mem_obj->request;

    url = entry->url;

    /* if fd != 0 then we were called from comm_select() because the
     * timeout occured.  Otherwise we were called from neighborsUdpAck(). */

    if (fd) {
	entry->ping_status = PING_TIMEOUT;
	debug(17, 5, "getFromDefaultSource: Timeout occured pinging for <URL:%s>\n",
	    url);
    }
    /* Check if someone forgot to disable the read timer */
    if (fd && BIT_TEST(entry->flag, ENTRY_DISPATCHED)) {
	if (entry->ping_status == PING_TIMEOUT) {
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
	hierarchy_log_append(entry, HIER_FIRST_PARENT_MISS, fd, e->host);
	return getFromCache(fd, entry, e, request);
    }
    if (matchInsideFirewall(request->host)) {
	if (ipcache_gethostbyname(request->host, 0) == NULL) {
	    return protoDNSError(fd, entry);
	}
	hierarchy_log_append(entry, HIER_DIRECT, fd, request->host);
	return getFromCache(fd, entry, NULL, request);
    }
    if ((e = getSingleParent(request, NULL))) {
	/* last chance effort; maybe there was a single_parent and a ICP
	 * packet got lost */
	hierarchy_log_append(entry, HIER_SINGLE_PARENT, fd, e->host);
	return getFromCache(fd, entry, e, request);
    }
    if ((e = getFirstUpParent(request))) {
	hierarchy_log_append(entry, HIER_FIRSTUP_PARENT, fd, e->host);
	return getFromCache(fd, entry, e, request);
    }
    hierarchy_log_append(entry, HIER_NO_DIRECT_FAIL, fd, request->host);
    protoCancelTimeout(fd, entry);
    protoCantFetchObject(fd, entry,
	"No ICP replies received and the host is beyond the firewall.");
    return 0;
}

int getFromCache(fd, entry, e, request)
     int fd;
     StoreEntry *entry;
     edge *e;
     request_t *request;
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
	e->stats.fetches++;
	return proxyhttpStart(e, url, entry);
    } else if (request->protocol == PROTO_HTTP) {
	return httpStart(fd, url, request, request_hdr, entry);
    } else if (request->protocol == PROTO_GOPHER) {
	return gopherStart(fd, url, entry);
    } else if (request->protocol == PROTO_FTP) {
	return ftpStart(fd, url, request, entry);
    } else if (request->protocol == PROTO_WAIS) {
	return waisStart(fd, url, entry->method, request_hdr, entry);
    } else if (request->protocol == PROTO_CACHEOBJ) {
	return objcacheStart(fd, url, entry);
    } else if (entry->method == METHOD_CONNECT) {
	fatal_dump("getFromCache() should not be handling CONNECT");
	return 0;
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

    squid_error_entry(entry, ERR_NOT_IMPLEMENTED, NULL);
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
    squid_error_entry(entry, ERR_CANNOT_FETCH, buf);
    return 0;
}

static int protoDNSError(fd, entry)
     int fd;
     StoreEntry *entry;
{
    debug(17, 2, "protoDNSError: FD %d <URL:%s>\n", fd, entry->url);
    protoCancelTimeout(fd, entry);
    squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
    return 0;
}

/*
 * return 0 if the host is outside the firewall (no domains matched), and
 * return 1 if the host is inside the firewall or no domains at all.
 */
static int matchInsideFirewall(host)
     char *host;
{
    wordlist *s = getInsideFirewallList();
    char *key = NULL;
    int result;
    if (!s)
	/* no domains, all hosts are "inside" the firewall */
	return NO_FIREWALL;
    for (; s; s = s->next) {
	key = s->key;
	if (!strcasecmp(key, "none"))
	    /* no domains are inside the firewall, all domains are outside */
	    return OUTSIDE_FIREWALL;
	if (*key == '!') {
	    key++;
	    result = OUTSIDE_FIREWALL;
	} else {
	    result = INSIDE_FIREWALL;
	}
	if (matchDomainName(key, host))
	    return result;
    }
    /* all through the list and no domains matched, this host must
     * not be inside the firewall, it must be outside */
    return OUTSIDE_FIREWALL;
}

static int matchLocalDomain(host)
     char *host;
{
    wordlist *s = NULL;
    for (s = getLocalDomainList(); s; s = s->next) {
	if (matchDomainName(s->key, host))
	    return 1;
    }
    return 0;
}
