
/*
 * $Id$
 *
 * DEBUG: section 33    Client-side Routines - URL Rewriter
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
clientRedirectAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    http->acl_checklist = NULL;
    if (answer == ACCESS_ALLOWED)
	redirectStart(http, clientRedirectDone, http);
    else
	clientRedirectDone(http, NULL);
}

void
clientRedirectStart(clientHttpRequest * http)
{
    debug(33, 5) ("clientRedirectStart: '%s'\n", http->uri);
    if (Config.Program.url_rewrite.command == NULL) {
	clientRedirectDone(http, NULL);
	return;
    }
    if (Config.accessList.url_rewrite) {
	http->acl_checklist = clientAclChecklistCreate(Config.accessList.url_rewrite, http);
	aclNBCheck(http->acl_checklist, clientRedirectAccessCheckDone, http);
    } else {
	redirectStart(http, clientRedirectDone, http);
    }
}

void
clientRedirectDone(void *data, char *result)
{
    clientHttpRequest *http = data;
    request_t *new_request = NULL;
    request_t *old_request = http->request;
    const char *urlgroup = http->conn->port->urlgroup;
    debug(33, 5) ("clientRedirectDone: '%s' result=%s\n", http->uri,
	result ? result : "NULL");
    assert(http->redirect_state == REDIRECT_PENDING);
    http->redirect_state = REDIRECT_DONE;
    if (result) {
	http_status status;
	if (*result == '!') {
	    char *t;
	    if ((t = strchr(result + 1, '!')) != NULL) {
		urlgroup = result + 1;
		*t++ = '\0';
		result = t;
	    } else {
		debug(33, 1) ("clientRedirectDone: bad input: %s\n", result);
	    }
	}
	status = (http_status) atoi(result);
	if (status == HTTP_MOVED_PERMANENTLY
	    || status == HTTP_MOVED_TEMPORARILY
	    || status == HTTP_SEE_OTHER
	    || status == HTTP_TEMPORARY_REDIRECT) {
	    char *t = result;
	    if ((t = strchr(result, ':')) != NULL) {
		http->redirect.status = status;
		http->redirect.location = xstrdup(t + 1);
		goto redirect_parsed;
	    } else {
		debug(33, 1) ("clientRedirectDone: bad input: %s\n", result);
	    }
	} else if (strcmp(result, http->uri))
	    new_request = urlParse(old_request->method, result);
    }
  redirect_parsed:
    if (new_request) {
	safe_free(http->uri);
	http->uri = xstrdup(urlCanonical(new_request));
	new_request->http_ver = old_request->http_ver;
	httpHeaderAppend(&new_request->header, &old_request->header);
	new_request->client_addr = old_request->client_addr;
	new_request->client_port = old_request->client_port;
#if FOLLOW_X_FORWARDED_FOR
	new_request->indirect_client_addr = old_request->indirect_client_addr;
#endif /* FOLLOW_X_FORWARDED_FOR */
	new_request->my_addr = old_request->my_addr;
	new_request->my_port = old_request->my_port;
	new_request->flags = old_request->flags;
	new_request->flags.redirected = 1;
	if (old_request->auth_user_request) {
	    new_request->auth_user_request = old_request->auth_user_request;
	    authenticateAuthUserRequestLock(new_request->auth_user_request);
	}
	if (old_request->body_reader) {
	    new_request->body_reader = old_request->body_reader;
	    new_request->body_reader_data = old_request->body_reader_data;
	    old_request->body_reader = NULL;
	    old_request->body_reader_data = NULL;
	}
	new_request->content_length = old_request->content_length;
	if (strBuf(old_request->extacl_log))
	    new_request->extacl_log = stringDup(&old_request->extacl_log);
	if (old_request->extacl_user)
	    new_request->extacl_user = xstrdup(old_request->extacl_user);
	if (old_request->extacl_passwd)
	    new_request->extacl_passwd = xstrdup(old_request->extacl_passwd);
	requestUnlink(old_request);
	http->request = requestLink(new_request);
    } else {
	/* Don't mess with urlgroup on internal request */
	if (old_request->flags.internal)
	    urlgroup = NULL;
    }
    safe_free(http->request->urlgroup);		/* only paranoia. should not happen */
    if (urlgroup && *urlgroup)
	http->request->urlgroup = xstrdup(urlgroup);
    clientInterpretRequestHeaders(http);
    /* XXX This really should become a ref-counted string type pointer, not a copy! */
    fd_note(http->conn->fd, http->uri);

    clientStoreURLRewriteStart(http);
}
