
/*
 * $Id$
 *
 * DEBUG: section 85    Client-side Routines - Store URL Rewriter
 * AUTHOR: Duane Wessels; Adrian Chadd
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


/* Local functions */

void
clientStoreURLRewriteAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    http->acl_checklist = NULL;
    if (answer == ACCESS_ALLOWED)
	storeurlStart(http, clientStoreURLRewriteDone, http);
    else
	clientStoreURLRewriteDone(http, NULL);
}

void
clientStoreURLRewriteStart(clientHttpRequest * http)
{
    debug(85, 5) ("clientStoreURLRewriteStart: '%s'\n", http->uri);
    if (Config.Program.store_rewrite.command == NULL) {
	clientStoreURLRewriteDone(http, NULL);
	return;
    }
    if (Config.accessList.storeurl_rewrite) {
	http->acl_checklist = clientAclChecklistCreate(Config.accessList.storeurl_rewrite, http);
	aclNBCheck(http->acl_checklist, clientStoreURLRewriteAccessCheckDone, http);
    } else {
	storeurlStart(http, clientStoreURLRewriteDone, http);
    }
}

void
clientStoreURLRewriteDone(void *data, char *result)
{
    clientHttpRequest *http = data;

    debug(85, 3) ("clientStoreURLRewriteDone: '%s' result=%s\n", http->uri,
	result ? result : "NULL");
#if 0
    assert(http->redirect_state == REDIRECT_PENDING);
    http->redirect_state = REDIRECT_DONE;
#endif

    if (result) {
	http->request->store_url = xstrdup(result);
	debug(85, 3) ("Rewrote to %s\n", http->request->store_url);
	/* XXX is this actually the right spot to do this? How about revalidation? */
	//storeEntrySetStoreUrl(http->entry, result);
    }
    /* This is the final part of the rewrite chain - this should be broken out! */
    clientInterpretRequestHeaders(http);
#if HEADERS_LOG
    headersLog(0, 1, request->method, request);
#endif
    clientAccessCheck2(http);
}
