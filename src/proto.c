
/*
 * $Id$
 *
 * DEBUG: section 17    Neighbor Selection
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
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

static int matchLocalDomain _PARAMS((const char *));
static int protoCantFetchObject _PARAMS((int, StoreEntry *, char *));
static int protoNotImplemented _PARAMS((int, const char *, StoreEntry *));
static int protoDNSError _PARAMS((int, StoreEntry *));
static void protoDataFree _PARAMS((int, protodispatch_data *));
static void protoDispatchDNSHandle _PARAMS((int, const ipcache_addrs *, void *));

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
    "ICP_MISS_NOFETCH",
    "ICP_DENIED",
    "ICP_HIT_OBJ",
    "ICP_END"
};

#if DELAY_HACK
extern int _delay_fetch;
#endif

static void
protoDataFree(int fdunused, protodispatch_data * protoData)
{
    if (protoData->ip_lookup_pending)
	ipcache_unregister(protoData->request->host, protoData->fd);
    requestUnlink(protoData->request);
    safe_free(protoData);
}

/* called when DNS lookup is done by ipcache. */
static void
protoDispatchDNSHandle(int unused1, const ipcache_addrs * ia, void *data)
{
    peer *e = NULL;
    struct in_addr srv_addr;
    protodispatch_data *protoData = (protodispatch_data *) data;
    StoreEntry *entry = protoData->entry;
    request_t *req = protoData->request;

    /* NOTE: We get here after a DNS lookup, whether or not the
     * lookup was successful.  Even if the URL hostname is bad,
     * we might still ping the hierarchy */

    protoData->ip_lookup_pending = 0;
    if (protoData->direct_fetch == DIRECT_YES) {
	if (ia == NULL) {
	    protoDNSError(protoData->fd, entry);
	    return;
	}
	hierarchyNote(req, HIER_DIRECT, 0, req->host);
	protoStart(protoData->fd, entry, NULL, req);
	return;
    }
    if (protoData->direct_fetch == DIRECT_MAYBE && (Config.local_ip_list || Config.firewall_ip_list)) {
	if (ia == NULL) {
	    debug(17, 3, "Unknown host: %s\n", req->host);
	    protoData->direct_fetch = DIRECT_NO;
	} else if (Config.firewall_ip_list) {
	    srv_addr = ia->in_addrs[ia->cur];
	    if (ip_access_check(srv_addr, Config.firewall_ip_list) == IP_DENY) {
		hierarchyNote(req, HIER_FIREWALL_IP_DIRECT, 0, req->host);
		protoStart(protoData->fd, entry, NULL, req);
		return;
	    } else {
#ifdef NOT_SURE
		/* Even though the address is NOT in firewall_ip_list,
		 * we might still be able to go direct, depending on if
		 * there are any peers to query, etc.  If this is set to
		 * DIRECT_NO then requests will fail if the host matches
		 * inside_firewall but not firewall_ip_list. */
		protoData->direct_fetch = DIRECT_MAYBE;
#endif
		protoData->direct_fetch = DIRECT_NO;
	    }
	} else if (Config.local_ip_list) {
	    srv_addr = ia->in_addrs[ia->cur];
	    if (ip_access_check(srv_addr, Config.local_ip_list) == IP_DENY) {
		hierarchyNote(req, HIER_LOCAL_IP_DIRECT, 0, req->host);
		protoStart(protoData->fd, entry, NULL, req);
		return;
	    }
	}
    }
    if ((e = protoData->single_parent) && Config.singleParentBypass) {
	/* Don't execute this block simply because direct == NO, we
	 * might have some DOWN peers and still need to ping them */
	/* Only one parent for this host, and okay to skip pinging stuff */
	hierarchyNote(req, HIER_SINGLE_PARENT, 0, e->host);
	protoStart(protoData->fd, entry, e, req);
	return;
    }
    if (protoData->n_peers == 0 && protoData->direct_fetch == DIRECT_NO) {
	if ((e = protoData->default_parent)) {
	    hierarchyNote(req, HIER_DEFAULT_PARENT, 0, e->host);
	    protoStart(protoData->fd, entry, e, req);
	} else if ((e = getFirstUpParent(protoData->request))) {
	    hierarchyNote(req, HIER_FIRSTUP_PARENT, 0, e->host);
	    protoStart(protoData->fd, entry, e, req);
	} else {
	    hierarchyNote(req, HIER_NO_DIRECT_FAIL, 0, req->host);
	    protoCantFetchObject(protoData->fd, entry, "No peers to query and the host is beyond your firewall.");
	}
	return;
    }
    if (!neighbors_do_private_keys && !protoData->hierarchical &&
	(e = getFirstUpParent(req))) {
	/* for private objects we should just fetch directly (because
	 * icpHandleUdp() won't properly deal with the ICP replies). */
	hierarchyNote(req, HIER_FIRSTUP_PARENT, 0, e->host);
	protoStart(protoData->fd, entry, e, req);
	return;
    } else if (protoData->direct_fetch == DIRECT_MAYBE && ia
	&& netdbHops(ia->in_addrs[ia->cur]) <= Config.minDirectHops) {
	hierarchyNote(req, HIER_DIRECT, 0, req->host);
	protoStart(protoData->fd, entry, NULL, req);
	return;
    } else if (neighborsUdpPing(protoData)) {
	/* call neighborUdpPing and start timeout routine */
	if (entry->ping_status != PING_NONE)
	    fatal_dump("protoDispatchDNSHandle: bad ping_status");
	if (entry->store_status != STORE_PENDING)
	    fatal_dump("protoDispatchDNSHandle: bad store_status");
	entry->ping_status = PING_WAITING;
	commSetSelect(protoData->fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) getFromDefaultSource,
	    (void *) entry,
	    Config.neighborTimeout);
#ifdef DELAY_HACK
	if (protoData->delay_fetch && entry->mem_obj)
	    entry->mem_obj->e_pings_n_pings++;
#endif
	return;
    }
    if ((e = protoData->default_parent)) {
	hierarchyNote(req, HIER_DEFAULT_PARENT, 0, e->host);
	protoStart(protoData->fd, entry, e, req);
    } else if ((e = getRoundRobinParent(req))) {
	hierarchyNote(req, HIER_ROUNDROBIN_PARENT, 0, e->host);
	protoStart(protoData->fd, entry, e, req);
    } else if (protoData->direct_fetch == DIRECT_NO) {
	hierarchyNote(req, HIER_NO_DIRECT_FAIL, 0, req->host);
	protoCantFetchObject(protoData->fd, entry,
	    "No neighbors or parents were queried and the host is beyond your firewall.");
    } else if (ia == NULL) {
	protoDNSError(protoData->fd, entry);
    } else {
	hierarchyNote(req, HIER_DIRECT, 0, req->host);
	protoStart(protoData->fd, entry, NULL, req);
    }
}

int
protoDispatch(int fd, char *url, StoreEntry * entry, request_t * request)
{
    protodispatch_data *protoData = NULL;
    const char *method;
    char *request_hdr;

    method = RequestMethodStr[request->method];
    request_hdr = entry->mem_obj->mime_hdr;

    debug(17, 5, "protoDispatch: %s URL: %s\n", method, url);
    debug(17, 10, "request_hdr: %s\n", request_hdr);

    if (request->protocol == PROTO_CACHEOBJ)
	return protoStart(fd, entry, NULL, request);
    if (request->protocol == PROTO_WAIS)
	return protoStart(fd, entry, NULL, request);
    netdbPingSite(request->host);
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
    protoData->hierarchical = BIT_TEST(entry->flag, HIERARCHICAL) ? 1 : 0;
    protoData->single_parent = getSingleParent(request);
    protoData->default_parent = getDefaultParent(request);
    protoData->n_peers = neighborsCount(request);
#ifdef DELAY_HACK
    protoData->delay_fetch = _delay_fetch;
#endif

    debug(17, 2, "protoDispatch: inside_firewall = %d (%s)\n",
	protoData->inside_firewall,
	firewall_desc_str[protoData->inside_firewall]);
    debug(17, 2, "protoDispatch:    hierarchical = %d\n", protoData->hierarchical);
    debug(17, 2, "protoDispatch:         n_peers = %d\n", protoData->n_peers);
    debug(17, 2, "protoDispatch:   single_parent = %s\n",
	protoData->single_parent ? protoData->single_parent->host : "N/A");
    debug(17, 2, "protoDispatch:  default_parent = %s\n",
	protoData->default_parent ? protoData->default_parent->host : "N/A");

    if (Config.firewall_ip_list) {
	/* Have to look up the url address so we can compare it */
	protoData->source_ping = Config.sourcePing;
	protoData->direct_fetch = DIRECT_MAYBE;
        protoData->ip_lookup_pending = 1;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (!protoData->inside_firewall) {
	/* There are firewall restrictions, and this host is outside. */
	/* No DNS lookups, call protoDispatchDNSHandle() directly */
	protoData->source_ping = 0;
	protoData->direct_fetch = DIRECT_NO;
	protoDispatchDNSHandle(fd,
	    NULL,
	    (void *) protoData);
    } else if (matchLocalDomain(request->host) || !protoData->hierarchical) {
	/* will fetch from source */
	protoData->direct_fetch = DIRECT_YES;
        protoData->ip_lookup_pending = 1;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (protoData->n_peers == 0) {
	/* will fetch from source */
	protoData->direct_fetch = DIRECT_YES;
        protoData->ip_lookup_pending = 1;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (Config.local_ip_list) {
	/* Have to look up the url address so we can compare it */
	protoData->source_ping = Config.sourcePing;
	protoData->direct_fetch = DIRECT_MAYBE;
        protoData->ip_lookup_pending = 1;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    } else if (protoData->single_parent && Config.singleParentBypass &&
	!(protoData->source_ping = Config.sourcePing)) {
	/* will fetch from single parent */
	protoData->direct_fetch = DIRECT_MAYBE;
	protoDispatchDNSHandle(fd,
	    NULL,
	    (void *) protoData);
    } else {
	/* will use ping resolution */
	protoData->source_ping = Config.sourcePing;
	protoData->direct_fetch = DIRECT_MAYBE;
        protoData->ip_lookup_pending = 1;
	ipcache_nbgethostbyname(request->host,
	    fd,
	    protoDispatchDNSHandle,
	    (void *) protoData);
    }
    return 0;
}

int
protoUnregister(int fd, StoreEntry * entry, request_t * request, struct in_addr src_addr)
{
    char *url = entry ? entry->url : NULL;
    protocol_t proto = request ? request->protocol : PROTO_NONE;
    debug(17, 5, "protoUnregister FD %d '%s'\n", fd, url ? url : "NULL");
    if (proto == PROTO_CACHEOBJ)
	return 0;
    if (url)
	redirectUnregister(url, fd);
    if (src_addr.s_addr != inaddr_none)
	fqdncacheUnregister(src_addr, fd);
    if (entry == NULL)
	return 0;
    if (BIT_TEST(entry->flag, ENTRY_DISPATCHED))
	return 0;
    if (entry->store_status != STORE_PENDING)
	return 0;
    protoCancelTimeout(fd, entry);
    squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
    return 1;
}

void
protoCancelTimeout(int fd, StoreEntry * entry)
{
    /* If fd = 0 then this thread was called from neighborsUdpAck and
     * we must look up the FD in the pending list. */
    if (!fd)
	fd = storeFirstClientFD(entry->mem_obj);
    if (fd < 1) {
	debug(17, 1, "protoCancelTimeout: No client for '%s'\n", entry->url);
	return;
    }
    debug(17, 2, "protoCancelTimeout: FD %d '%s'\n", fd, entry->url);
    if (fdstatGetType(fd) != FD_SOCKET) {
	debug_trap("protoCancelTimeout: called on non-socket");
	return;
    }
    /* cancel the timeout handler */
    commSetSelect(fd,
	COMM_SELECT_TIMEOUT,
	NULL,
	NULL,
	0);
}

/*
 *  Called from comm_select() if neighbor pings timeout
 *  or from neighborsUdpAck() if all neighbors miss.
 */
int
getFromDefaultSource(int fd, StoreEntry * entry)
{
    peer *e = NULL;
    char *url = NULL;
    request_t *request = entry->mem_obj->request;
    int myrtt;
    url = entry->url;

    /* if fd != 0 then we were called from comm_select() because the
     * timeout occured.  Otherwise we were called from neighborsUdpAck(). */

    if (fd) {
	entry->ping_status = PING_TIMEOUT;
	debug(17, 5, "getFromDefaultSource: Timeout occured pinging for '%s'\n",
	    url);
    }
    /* Check if someone forgot to disable the read timer */
    if (BIT_TEST(entry->flag, ENTRY_DISPATCHED))
	fatal_dump("getFromDefaultSource: object already being fetched");
    if ((e = entry->mem_obj->e_pings_closest_parent)) {
	myrtt = netdbHostRtt(request->host);
	if (myrtt && myrtt < entry->mem_obj->p_rtt) {
	    hierarchyNote(request, HIER_CLOSEST_DIRECT, fd, request->host);
	    return protoStart(fd, entry, NULL, request);
	} else {
	    hierarchyNote(request, HIER_CLOSEST_PARENT_MISS, fd, e->host);
	    return protoStart(fd, entry, e, request);
	}
    }
    if ((e = entry->mem_obj->e_pings_first_miss)) {
	hierarchyNote(request, HIER_FIRST_PARENT_MISS, fd, e->host);
	return protoStart(fd, entry, e, request);
    }
    if (matchInsideFirewall(request->host)) {
	if (ipcache_gethostbyname(request->host, 0) == NULL)
	    return protoDNSError(fd, entry);
	hierarchyNote(request, HIER_DIRECT, fd, request->host);
	return protoStart(fd, entry, NULL, request);
    }
    if ((e = getDefaultParent(request))) {
	hierarchyNote(request, HIER_DEFAULT_PARENT, fd, e->host);
	return protoStart(fd, entry, e, request);
    }
    if ((e = getSingleParent(request))) {
	hierarchyNote(request, HIER_SINGLE_PARENT, fd, e->host);
	return protoStart(fd, entry, e, request);
    }
    if ((e = getRoundRobinParent(request))) {
	hierarchyNote(request, HIER_ROUNDROBIN_PARENT, fd, e->host);
	return protoStart(fd, entry, e, request);
    }
    if ((e = getFirstUpParent(request))) {
	hierarchyNote(request, HIER_FIRSTUP_PARENT, fd, e->host);
	return protoStart(fd, entry, e, request);
    }
    hierarchyNote(request, HIER_NO_DIRECT_FAIL, fd, request->host);
    protoCancelTimeout(fd, entry);
    protoCantFetchObject(fd, entry,
	"No ICP replies received and the host is beyond the firewall.");
    return 0;
}

int
protoStart(int fd, StoreEntry * entry, peer * e, request_t * request)
{
    char *url = entry->url;
    char *request_hdr = entry->mem_obj->mime_hdr;
    int request_hdr_sz = entry->mem_obj->mime_hdr_sz;
    debug(17, 5, "protoStart: FD %d: Fetching '%s %s' from %s\n",
	fd,
	RequestMethodStr[request->method],
	entry->url,
	e ? e->host : "source");
    if (BIT_TEST(entry->flag, ENTRY_DISPATCHED))
	fatal_dump("protoStart: object already being fetched");
    if (entry->ping_status == PING_WAITING)
	debug_trap("protoStart: ping_status is PING_WAITING");
    BIT_SET(entry->flag, ENTRY_DISPATCHED);
    protoCancelTimeout(fd, entry);
    netdbPingSite(request->host);
#ifdef LOG_ICP_NUMBERS
    request->hierarchy.n_recv = entry->mem_obj->e_pings_n_acks;
    if (entry->mem_obj->start_ping.tv_sec)
	request->hierarchy.delay = tvSubMsec(entry->mem_obj->start_ping, current_time);
#endif
    if (e) {
	e->stats.fetches++;
	return proxyhttpStart(url, request, entry, e);
    } else if (request->protocol == PROTO_HTTP) {
	return httpStart(url, request, request_hdr, request_hdr_sz, entry);
    } else if (request->protocol == PROTO_GOPHER) {
	return gopherStart(fd, url, entry);
    } else if (request->protocol == PROTO_FTP) {
	return ftpStart(fd, url, request, entry);
    } else if (request->protocol == PROTO_WAIS) {
	return waisStart(fd, url, request->method, request_hdr, entry);
    } else if (request->protocol == PROTO_CACHEOBJ) {
	return objcacheStart(fd, url, entry);
    } else if (request->method == METHOD_CONNECT) {
	fatal_dump("protoStart() should not be handling CONNECT");
	return 0;
    } else {
	return protoNotImplemented(fd, url, entry);
    }
    /* NOTREACHED */
}

static int
protoNotImplemented(int fd, const char *url, StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);

    debug(17, 1, "protoNotImplemented: Cannot retrieve '%s'\n", url);

    buf[0] = '\0';
    if (httpd_accel_mode)
	strcpy(buf, "cached is running in HTTPD accelerator mode, so it does not allow the normal URL syntax.");
    else
	sprintf(buf, "Your URL may be incorrect: '%s'\n", url);

    squid_error_entry(entry, ERR_NOT_IMPLEMENTED, NULL);
    return 0;
}

static int
protoCantFetchObject(int fd, StoreEntry * entry, char *reason)
{
    LOCAL_ARRAY(char, buf, 2048);

    debug(17, 1, "protoCantFetchObject: FD %d %s\n", fd, reason);
    debug(17, 1, "--> '%s'\n", entry->url);

    buf[0] = '\0';
    sprintf(buf, "%s\n\nThe cache administrator may need to double-check the cache configuration.",
	reason);
    squid_error_entry(entry, ERR_CANNOT_FETCH, buf);
    return 0;
}

static int
protoDNSError(int fd, StoreEntry * entry)
{
    debug(17, 2, "protoDNSError: FD %d '%s'\n", fd, entry->url);
    protoCancelTimeout(fd, entry);
    squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
    return 0;
}

/*
 * return 0 if the host is outside the firewall (no domains matched), and
 * return 1 if the host is inside the firewall or no domains at all.
 */
int
matchInsideFirewall(const char *host)
{
    const wordlist *s = Config.inside_firewall_list;
    const char *key = NULL;
    int result = NO_FIREWALL;
    struct in_addr addr;
    if (!s && !Config.firewall_ip_list)
	/* no firewall goop, all hosts are "inside" the firewall */
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
    /* Check for dotted-quads */
    if (Config.firewall_ip_list) {
	if ((addr.s_addr = inet_addr(host)) != inaddr_none) {
	    if (ip_access_check(addr, Config.firewall_ip_list) == IP_DENY)
		return INSIDE_FIREWALL;
	}
    }
    /* all through the list and no domains matched, this host must
     * not be inside the firewall, it must be outside */
    return OUTSIDE_FIREWALL;
}

static int
matchLocalDomain(const char *host)
{
    const wordlist *s = NULL;
    for (s = Config.local_domain_list; s; s = s->next) {
	if (matchDomainName(s->key, host))
	    return 1;
    }
    return 0;
}
