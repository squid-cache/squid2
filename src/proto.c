
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

typedef struct {
    int fd;
    StoreEntry *entry;
    request_t *request;
} pctrl_t;

static void protoDispatchComplete(peer * p, void *data);
static void protoDispatchFail(peer * p, void *data);
static void protoStart(int, StoreEntry *, peer *, request_t *);

static void
protoDispatchComplete(peer * p, void *data)
{
    pctrl_t *pctrl = data;
    if (!storeUnlockObject(pctrl->entry))
	return;
    protoStart(pctrl->fd, pctrl->entry, p, pctrl->request);
    requestUnlink(pctrl->request);
    cbdataFree(pctrl);
}

static void
protoDispatchFail(peer * peernotused, void *data)
{
    pctrl_t *pctrl = data;
    ErrorState *err;
    if (!storeUnlockObject(pctrl->entry))
	return;
    err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE);
    err->request = requestLink(pctrl->request);
    errorAppendEntry(pctrl->entry, err);
    requestUnlink(pctrl->request);
    cbdataFree(pctrl);
}

static void
protoStart(int fd, StoreEntry * entry, peer * e, request_t * request)
{
    debug(17, 5) ("protoStart: FD %d: Fetching '%s %s' from %s\n",
	fd,
	RequestMethodStr[request->method],
	storeUrl(entry),
	e ? e->host : "source");
    assert(!EBIT_TEST(entry->flag, ENTRY_DISPATCHED));
    assert(entry->ping_status != PING_WAITING);
    EBIT_SET(entry->flag, ENTRY_DISPATCHED);
    netdbPingSite(request->host);
#if defined(LOG_ICP_NUMBERS)
    request->hierarchy.n_recv = entry->mem_obj->e_pings_n_acks;
    if (entry->mem_obj->start_ping.tv_sec)
	request->hierarchy.delay = tvSubUsec(entry->mem_obj->start_ping, current_time);
#endif
    if (e) {
	e->stats.fetches++;
	httpStart(request, entry, e);
    } else {
	switch (request->protocol) {
	case PROTO_HTTP:
	    httpStart(request, entry, NULL);
	    break;
	case PROTO_GOPHER:
	    gopherStart(entry);
	    break;
	case PROTO_FTP:
	    ftpStart(request, entry);
	    break;
	case PROTO_WAIS:
	    waisStart(request, entry);
	    break;
	case PROTO_CACHEOBJ:
	    cachemgrStart(fd, request, entry);
	    break;
	case PROTO_URN:
	    urnStart(request, entry);
	    break;
	case PROTO_WHOIS:
	    whoisStart(request, entry);
	    break;
	case PROTO_INTERNAL:
	    internalStart(request, entry);
	    break;
	default:
	    if (request->method == METHOD_CONNECT) {
		ErrorState *err;
		debug(17, 1) ("protoStart: Cannot retrieve '%s'\n",
		    storeUrl(entry));
		err = errorCon(ERR_UNSUP_REQ, HTTP_BAD_REQUEST);
		err->request = requestLink(request);
		errorAppendEntry(entry, err);
	    }
	}
    }
}

/* PUBLIC FUNCTIONS */

int
protoUnregister(StoreEntry * entry, request_t * request)
{
    const char *url = entry ? storeUrl(entry) : NULL;
    protocol_t proto = request ? request->protocol : PROTO_NONE;
    ErrorState *err;
    debug(17, 5) ("protoUnregister '%s'\n", url ? url : "NULL");
    if (proto == PROTO_CACHEOBJ)
	return 0;
    if (entry == NULL)
	return 0;
    if (EBIT_TEST(entry->flag, ENTRY_DISPATCHED))
	return 0;
    if (entry->mem_status != NOT_IN_MEMORY)
	return 0;
    if (entry->store_status != STORE_PENDING)
	return 0;
    err = errorCon(ERR_CLIENT_ABORT, HTTP_INTERNAL_SERVER_ERROR);
    err->request = request;
    errorAppendEntry(entry, err);
    return 1;
}

void
protoDispatch(int fd, StoreEntry * entry, request_t * request)
{
    pctrl_t *pctrl;
    debug(17, 3) ("protoDispatch: '%s'\n", storeUrl(entry));
    entry->mem_obj->request = requestLink(request);
    switch (request->protocol) {
    case PROTO_CACHEOBJ:
    case PROTO_WAIS:
    case PROTO_INTERNAL:
	protoStart(fd, entry, NULL, request);
	return;
    default:
	break;
    }
    pctrl = xcalloc(1, sizeof(pctrl_t));
    cbdataAdd(pctrl, MEM_NONE);
    pctrl->entry = entry;
    pctrl->fd = fd;
    pctrl->request = requestLink(request);
    /* Keep the StoreEntry locked during peer selection phase */
    storeLockObject(entry);
    peerSelect(request,
	entry,
	protoDispatchComplete,
	protoDispatchFail,
	pctrl);
}

/* This is called before reading data from the server side to
 * decide if the server side should abort the fetch.
 * XXX This probably breaks quick_abort!
 * When to abort?
 * - NOT if there are clients reading
 * - YES if we don't know the content length
 * - YES if we do know the content length and we don't have the
 * whole object
 */
int
protoAbortFetch(StoreEntry * entry)
{
    MemObject *mem;
    const HttpReply *reply;
    if (storeClientWaiting(entry))
	return 0;
    mem = entry->mem_obj;
    reply = mem->reply;
    if (reply->content_length < 0)
	return 1;
    if (mem->inmem_hi < reply->content_length + reply->hdr_sz)
	return 1;
    return 0;
}

int
protoCheckDeferRead(int fdnotused, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
    if (mem->inmem_hi - storeLowestMemReaderOffset(e) < READ_AHEAD_GAP)
	return 0;
    return 1;
}
