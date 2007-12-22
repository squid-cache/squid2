
/*
 * $Id$
 *
 * DEBUG: section 20    Storage Manager
 * AUTHOR: Henrik Nordstrom <henrik@henriknordstrom.net>
 *
 * Copyright (C) 2007 Henrik Nordstrom <henrik@henriknordstrom.net>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

/* Update the on-disk representation of the object to match
 * current in-memory representation. This requires rewriting
 * the object headers (bot meta and http) which isn't supported
 * by the store layer today, so we rewrite the full object.
 */

/* Local state */
typedef struct {
    StoreEntry *oldentry;
    StoreEntry *newentry;
    store_client *sc;
    squid_off_t offset;
} StoreUpdateState;

CBDATA_TYPE(StoreUpdateState);

static void
free_StoreUpdateState(void *data)
{
    StoreUpdateState *state = data;
    if (state->sc)
	storeClientUnregister(state->sc, state->oldentry, state);
    if (state->oldentry)
	storeUnlockObject(state->oldentry);
    if (state->newentry) {
	/* Set to NULL on completion, so we only get here in abnormal situations */
	storeRelease(state->newentry);
	storeUnlockObject(state->newentry);
    }
}

static void
storeUpdateDone(StoreUpdateState * state)
{
    if (state->sc) {
	store_client *sc = state->sc;
	state->sc = NULL;
	storeClientUnregister(sc, state->oldentry, state);
    }
    cbdataFree(state);
}
static void
storeUpdateAbort(void *data)
{
    StoreUpdateState *state = data;
    storeUpdateDone(state);
}

static void
storeUpdateCopy(void *data, mem_node_ref nr, ssize_t size)
{
    const char *buf = NULL;
    StoreUpdateState *state = data;
    assert(size <= nr.node->len - nr.offset);

    if (EBIT_TEST(state->newentry->flags, ENTRY_ABORTED)) {
	debug(20, 1) ("storeUpdateCopy: Aborted at %d (%d)\n", (int) state->offset, (int) size);
	/* the abort callback deals with the needed cleanup */
	goto finish;
    }
    if (EBIT_TEST(state->newentry->flags, KEY_PRIVATE) && state->newentry->mem_obj->nclients == 0) {
	debug(20, 2) ("storeUpdateCopy: Gone stale with no clients, skip copying of the rest\n");
	storeUpdateDone(state);
	goto finish;
    }
    if (size < 0) {
	debug(20, 1) ("storeUpdateCopy: Error at %d (%d)\n", (int) state->offset, (int) size);
	storeUpdateDone(state);
	goto finish;
    }
    if (size > 0) {
	buf = nr.node->data + nr.offset;
	storeAppend(state->newentry, buf, size);
	if (EBIT_TEST(state->newentry->flags, ENTRY_ABORTED)) {
	    debug(20, 1) ("storeUpdateCopy: Aborted on write at %d (%d)\n", (int) state->offset, (int) size);
	    goto finish;
	}
	state->offset += size;
	storeClientRef(state->sc, state->oldentry, state->offset, state->offset, SM_PAGE_SIZE, storeUpdateCopy, state);
	goto finish;
    } else {
	storeComplete(state->newentry);
	storeUnlockObject(state->newentry);
	state->newentry = NULL;
	storeUpdateDone(state);
    }

  finish:
    buf = NULL;
    stmemNodeUnref(&nr);
}

void
storeUpdate(StoreEntry * entry, request_t * request)
{
    StoreUpdateState *state;
    request_flags flags = null_request_flags;
    const char *vary;

    if (!request)
	request = entry->mem_obj->request;

    if (EBIT_TEST(entry->flags, KEY_PRIVATE))
	return;			/* Nothing to do here... */

    if (!Config.onoff.update_headers)
	return;			/* Disabled */

    CBDATA_INIT_TYPE_FREECB(StoreUpdateState, free_StoreUpdateState);

    if (entry->mem_obj)
	entry->mem_obj->refresh_timestamp = 0;
    state = cbdataAlloc(StoreUpdateState);
    state->oldentry = entry;
    storeLockObject(state->oldentry);
    flags.cachable = 1;
    state->newentry = storeCreateEntry(storeUrl(entry), flags, entry->mem_obj->method);
    storeRegisterAbort(state->newentry, storeUpdateAbort, state);
    state->sc = storeClientRegister(state->oldentry, state);
    state->offset = entry->mem_obj->reply->hdr_sz;
    storeBuffer(state->newentry);
    httpReplySwapOut(httpReplyClone(entry->mem_obj->reply), state->newentry);
    state->newentry->timestamp = entry->timestamp;
    state->newentry->lastref = entry->lastref;
    state->newentry->expires = entry->expires;
    state->newentry->lastmod = entry->lastmod;
    state->newentry->refcount = entry->refcount;
    if (request) {
	state->newentry->mem_obj->request = requestLink(request);
	vary = httpMakeVaryMark(request, state->newentry->mem_obj->reply);
	if (vary) {
	    state->newentry->mem_obj->vary_headers = xstrdup(vary);
	    if (strBuf(request->vary_encoding))
		entry->mem_obj->vary_encoding = xstrdup(strBuf(request->vary_encoding));
	}
    } else {
	if (entry->mem_obj->vary_headers)
	    state->newentry->mem_obj->vary_headers = xstrdup(entry->mem_obj->vary_headers);
	if (entry->mem_obj->vary_encoding)
	    state->newentry->mem_obj->vary_encoding = xstrdup(entry->mem_obj->vary_encoding);
    }
    storeSetPublicKey(state->newentry);
    storeBufferFlush(state->newentry);
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	/*
	 * the above storeBufferFlush() call could ABORT this entry,
	 * in that case, there's nothing for us to do.
	 */
	debug(20, 1) ("storeUpdate: Aborted on write\n");
	return;
    }
    storeClientRef(state->sc, state->oldentry, state->offset, state->offset, SM_PAGE_SIZE, storeUpdateCopy, state);
    return;
}
