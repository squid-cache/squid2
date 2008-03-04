
/*
 * $Id$
 *
 * DEBUG: section 85   Store URL Redirector
 * AUTHOR: Adrian Chadd; based on redirect.c by Duane Wessels
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

typedef struct {
    void *data;
    char *orig_url;
    struct in_addr client_addr;
    const char *client_ident;
    const char *method_s;
    RH *handler;
} redirectStateData;

static HLPCB redirectHandleReply;
static void redirectStateFree(redirectStateData * r);
static helper *redirectors = NULL;
static OBJH redirectStats;
static int n_bypassed = 0;
CBDATA_TYPE(redirectStateData);

static void
redirectHandleReply(void *data, char *reply)
{
    redirectStateData *r = data;
    int valid;
    char *t;
    debug(61, 5) ("redirectHandleRead: {%s}\n", reply ? reply : "<NULL>");
    if (reply) {
	if ((t = strchr(reply, ' ')))
	    *t = '\0';
	if (*reply == '\0')
	    reply = NULL;
    }
    valid = cbdataValid(r->data);
    cbdataUnlock(r->data);
    if (valid)
	r->handler(r->data, reply);
    redirectStateFree(r);
}

static void
redirectStateFree(redirectStateData * r)
{
    safe_free(r->orig_url);
    cbdataFree(r);
}

static void
redirectStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Redirector Statistics:\n");
    helperStats(sentry, redirectors);
    if (Config.onoff.redirector_bypass)
	storeAppendPrintf(sentry, "\nNumber of requests bypassed "
	    "because all redirectors were busy: %d\n", n_bypassed);
}

/**** PUBLIC FUNCTIONS ****/

void
redirectStart(clientHttpRequest * http, RH * handler, void *data)
{
    ConnStateData *conn = http->conn;
    redirectStateData *r = NULL;
    const char *fqdn;
    char *urlgroup = conn->port->urlgroup;
    char buf[8192];
    char claddr[20];
    char myaddr[20];
    assert(http);
    assert(handler);
    debug(61, 5) ("redirectStart: '%s'\n", http->uri);
    if (Config.onoff.redirector_bypass && redirectors->stats.queue_size) {
	/* Skip redirector if there is one request queued */
	n_bypassed++;
	handler(data, NULL);
	return;
    }
    r = cbdataAlloc(redirectStateData);
    r->orig_url = xstrdup(http->uri);
    r->client_addr = conn->log_addr;
    r->client_ident = NULL;
    if (http->request->auth_user_request)
	r->client_ident = authenticateUserRequestUsername(http->request->auth_user_request);
    else if (http->request->extacl_user) {
	r->client_ident = http->request->extacl_user;
    }
    if (!r->client_ident && conn->rfc931[0])
	r->client_ident = conn->rfc931;
#if USE_SSL
    if (!r->client_ident)
	r->client_ident = sslGetUserEmail(fd_table[conn->fd].ssl);
#endif
    if (!r->client_ident)
	r->client_ident = dash_str;
    r->method_s = RequestMethods[http->request->method].str;
    r->handler = handler;
    r->data = data;
    cbdataLock(r->data);
    if ((fqdn = fqdncache_gethostbyaddr(r->client_addr, 0)) == NULL)
	fqdn = dash_str;
    xstrncpy(claddr, inet_ntoa(r->client_addr), 20);
    xstrncpy(myaddr, inet_ntoa(http->request->my_addr), 20);
    snprintf(buf, 8191, "%s %s/%s %s %s %s myip=%s myport=%d",
	r->orig_url,
	claddr,
	fqdn,
	r->client_ident[0] ? rfc1738_escape(r->client_ident) : dash_str,
	r->method_s,
	urlgroup ? urlgroup : "-",
	myaddr,
	http->request->my_port);
    debug(61, 6) ("redirectStart: sending '%s' to the helper\n", buf);
    strcat(buf, "\n");
    helperSubmit(redirectors, buf, redirectHandleReply, r);
}

void
redirectInit(void)
{
    static int init = 0;
    if (!Config.Program.url_rewrite.command)
	return;
    if (redirectors == NULL)
	redirectors = helperCreate("url_rewriter");
    redirectors->cmdline = Config.Program.url_rewrite.command;
    redirectors->n_to_start = Config.Program.url_rewrite.children;
    redirectors->concurrency = Config.Program.url_rewrite.concurrency;
    redirectors->ipc_type = IPC_STREAM;
    helperOpenServers(redirectors);
    if (!init) {
	cachemgrRegister("url_rewriter",
	    "URL Rewriter Stats",
	    redirectStats, 0, 1);
	init = 1;
	CBDATA_INIT_TYPE(redirectStateData);
    }
}

void
redirectShutdown(void)
{
    if (!redirectors)
	return;
    helperShutdown(redirectors);
    if (!shutting_down)
	return;
    helperFree(redirectors);
    redirectors = NULL;
}

/*
 * Redirect
 */
typedef struct _tokendesc {
    const char *fmt;
    rewrite_token_type type;
} tokendesc;

static const tokendesc tokendescs[] =
{
    {">a", RFT_CLIENT_IPADDRESS},
    {"la", RFT_LOCAL_IPADDRESS},
    {"lp", RFT_LOCAL_PORT},
    {"ts", RFT_EPOCH_SECONDS},
    {"tu", RFT_TIME_SUBSECONDS},
    {"un", RFT_USERNAME},
    {"ul", RFT_USERLOGIN},
    {"ui", RFT_USERIDENT},
    {"us", RFT_USERSSL},
    {"ue", RFT_EXTERNALACL_USER},
    {"rm", RFT_METHOD},
    {"ru", RFT_URL},
    {"rp", RFT_URLPATH},
    {"rP", RFT_PROTOCOL},
    {"rh", RFT_URLHOST},
    {"rH", RFT_HDRHOST},
    {"ea", RFT_EXTERNALACL_LOGSTR},
    {NULL, RFT_UNKNOWN}
};

static const char *const tokenNames[] =
{
    "RFT_UNKNOWN",
    "RFT_STRING",
    "RFT_CLIENT_IPADDRESS",
    "RFT_LOCAL_IPADDRESS",
    "RFT_LOCAL_PORT",
    "RFT_EPOCH_SECONDS",
    "RFT_TIME_SUBSECONDS",
    "RFT_REQUEST_HEADER",
    "RFT_USERNAME",
    "RFT_USERLOGIN",
    "RFT_USERIDENT",
    "RFT_USERSSL",
    "RFT_EXTERNALACL_USER",
    "RFT_METHOD",
    "RFT_PROTOCOL",
    "RFT_URL",
    "RFT_URLPATH",
    "RFT_URLHOST",
    "RFT_HDRHOST",
    "RFT_EXTERNALACL_TAG",
    "RFT_EXTERNALACL_LOGSTR"
};

static const tokendesc *
findToken(const char *str)
{
    int16_t token = *(int16_t *) str;
    const tokendesc *ptoken = tokendescs;
    for (; ptoken->fmt != NULL; ++ptoken)
	if (*(int16_t *) ptoken->fmt == token)
	    break;
    if (ptoken->fmt == NULL)
	return NULL;
    return ptoken;
}

static rewritetoken *
newRedirectTokenStr(rewrite_token_type type, const char *str, size_t str_len,
    int urlEncode)
{
    debug(85, 3) ("newRedirectTokenStr(%s, '%s', %u)\n",
	tokenNames[type], str, (unsigned) str_len);
    rewritetoken *dev = (rewritetoken *) xmalloc(sizeof(*dev));
    dev->type = type;
    dev->str = str;
    dev->str_len = str_len;
    dev->urlEncode = urlEncode;
    dev->next = NULL;
    return dev;
}

static rewritetoken *
newRedirectToken(const char **str, int urlEncode)
{
    debug(85, 5) ("newRedirectToken(%s)\n", *str);
    const tokendesc *ptoken = findToken(*str);
    if (ptoken == NULL) {
	debug(85, 3) ("newRedirectToken: %s => NULL\n", *str);
	return NULL;
    }
    debug(85, 5) ("newRedirectToken: %s => %s\n", *str, tokenNames[ptoken->type]);
    rewritetoken *dev = newRedirectTokenStr(ptoken->type, NULL, 0, urlEncode);
    *str += 2;
    return dev;
}

rewritetoken *
rewriteURLCompile(const char *urlfmt)
{
    rewritetoken *head = NULL;
    rewritetoken **tail = &head;
    rewritetoken *_new = NULL;
    debug(85, 3) ("rewriteURLCompile(%s)\n", urlfmt);
    const char *stt = urlfmt;
    while (*urlfmt != '\0') {
	while (*urlfmt != '\0' && *urlfmt != '%')
	    ++urlfmt;
	if (urlfmt != stt) {
	    _new = newRedirectTokenStr(RFT_STRING,
		xstrndup(stt, urlfmt - stt + 1), urlfmt - stt, 0);
	    *tail = _new;
	    tail = &_new->next;
	    if (*urlfmt == '\0')
		break;
	    stt = ++urlfmt;
	}
	int urlEncode = 0;
	switch (urlfmt[0]) {
	case '#':
	    stt = ++urlfmt;
	    urlEncode = 1;
	    break;
	case '%':
	    stt = ++urlfmt;
	    _new = newRedirectTokenStr(RFT_STRING, xstrdup("%"), 1, 0);
	    *tail = _new;
	    tail = &_new->next;
	    continue;
	    break;
	}
	_new = newRedirectToken(&urlfmt, urlEncode);
	*tail = _new;
	tail = &_new->next;
	stt = urlfmt;
    }
    return head;
}

static char *
xreacat(char *str, size_t * len,
    const char *append, size_t applen)
{
    //TODO: garana: move xreacat to lib/util.c
    if (!applen)
	applen = strlen(append);
    if (str == NULL)
	assert((*len) == 0);
    str = (char *) xrealloc(str, *len + applen + 1);
    strncpy(str + *len, append, applen);
    *len += applen;
    str[*len] = 0;
    return str;
}

#if UNUSED_CODE
static char *
xreacatUL(char *str, size_t * len, unsigned long x)
{
    //TODO: garana: move xreacatUL to lib/util.c
    char tmpstr[12];
    snprintf(tmpstr, sizeof(tmpstr), "%lu", x);
    tmpstr[11] = '\0';
    return xreacat(str, len, tmpstr, strlen(tmpstr));
}
#endif

char *
internalRedirectProcessURL(clientHttpRequest * req, rewritetoken * head)
{
    char *dev = NULL;
    size_t len = 0;
    debug(85, 5) ("internalRedirectProcessURL: start\n");
    for (; head != NULL; head = head->next) {
	const char *str = NULL;	/* string to append */
	size_t str_len = 0;
	int do_ulong = 0;
	unsigned long ulong = 0;
	const char *ulong_fmt = "%lu";
	debug(85, 5) ("internalRedirectProcessURL: token=%s str=%s urlEncode=%s\n",
	    tokenNames[head->type], head->str, head->urlEncode ? "true" : "false");
	switch (head->type) {
	case RFT_STRING:
	    str = head->str;
	    str_len = head->str_len;
	    break;
	case RFT_CLIENT_IPADDRESS:
	    str = inet_ntoa(req->conn->peer.sin_addr);
	    break;
	case RFT_LOCAL_IPADDRESS:
	    str = inet_ntoa(req->conn->me.sin_addr);
	    break;
	case RFT_LOCAL_PORT:
	    ulong = ntohs(req->conn->me.sin_port);
	    do_ulong = 1;
	    break;
	case RFT_EPOCH_SECONDS:
	    ulong = current_time.tv_sec;
	    do_ulong = 1;
	    break;
	case RFT_TIME_SUBSECONDS:
	    ulong = current_time.tv_usec / 1000;
	    do_ulong = 1;
	    ulong_fmt = "%03lu";
	    break;
	case RFT_USERNAME:
	    if (req->request->auth_user_request)
		str = authenticateUserUsername(req->request->auth_user_request->auth_user);

	    if (!str || !*str)
		str = req->conn->rfc931;

#ifdef USE_SSL
	    if ((!str || !*str) && req->conn != NULL)
		str = sslGetUserEmail(fd_table[req->conn->fd].ssl);
#endif

	    if (!str || !*str)
		str = req->request->extacl_user;

	    break;
	case RFT_USERLOGIN:
	    str = req->request->login;
	    break;
	case RFT_USERIDENT:
	    str = req->conn->rfc931;
	    break;
	case RFT_USERSSL:
#ifdef USE_SSL
	    if (req->conn != NULL)
		str = sslGetUserEmail(fd_table[req->conn->fd].ssl);
#endif
	    break;
	case RFT_EXTERNALACL_USER:
	    str = req->request->extacl_user;
	    break;
	case RFT_METHOD:
	    str = RequestMethods[req->request->method].str;
	    break;
	case RFT_PROTOCOL:
	    str = ProtocolStr[req->request->protocol];
	    break;
	case RFT_URL:
	    str = req->uri;
	    break;
	case RFT_URLPATH:
	    str = req->request->urlpath.buf;
	    break;
	case RFT_URLHOST:
	    str = req->request->host;
	    break;
	case RFT_HDRHOST:
	    str = httpHeaderGetStr(&req->request->header, HDR_HOST);
	    break;
	case RFT_EXTERNALACL_LOGSTR:
	    str = req->request->extacl_log.buf;
	    break;
	default:
	    assert(0 && "Invalid rewrite token type");
	    break;
	}

	if (do_ulong) {
	    char tmpstr[12];
	    int nbytes = snprintf(tmpstr, 12, "%lu", ulong);
	    assert(nbytes > 0);
	    dev = xreacat(dev, &len, tmpstr, nbytes);
	} else {
	    if ((str == NULL) || (*str == '\0'))
		str = "-";

	    if (str_len == 0)
		str_len = strlen(str);

	    if (head->urlEncode) {
		str = rfc1738_escape_part(str);
		str_len = strlen(str);
	    }
	    dev = xreacat(dev, &len, str, str_len);
	}
    }
    debug(85, 5) ("internalRedirectProcessURL: done: %s\n", dev);
    return dev;
}
