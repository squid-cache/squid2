
/*
 * $Id$
 *
 * DEBUG: section 23    URL Parsing
 * AUTHOR: Duane Wessels
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

struct rms {
    method_t method;
    int string_len;
};

/*
 * It is currently VERY, VERY IMPORTANT that these be in order of their
 * definition in the method_code_t enum.
 */
static struct rms request_methods[] =
{
    {
	{METHOD_NONE, "NONE",
	    {0, 0}}, 4},
    {
	{METHOD_GET, "GET",
	    {1, 0}}, 3},
    {
	{METHOD_POST, "POST",
	    {0, 1}}, 4},
    {
	{METHOD_PUT, "PUT",
	    {0, 1}}, 3},
    {
	{METHOD_HEAD, "HEAD",
	    {1, 0}}, 4},
    {
	{METHOD_CONNECT, "CONNECT",
	    {0, 0}}, 7},
    {
	{METHOD_TRACE, "TRACE",
	    {0, 0}}, 5},
    {
	{METHOD_PURGE, "PURGE",
	    {0, 1}}, 5},
    {
	{METHOD_OPTIONS, "OPTIONS",
	    {0, 0}}, 7},
    {
	{METHOD_DELETE, "DELETE",
	    {0, 1}}, 6},
    {
	{METHOD_PROPFIND, "PROPFIND",
	    {0, 0}}, 8},
    {
	{METHOD_PROPPATCH, "PROPPATCH",
	    {0, 1}}, 9},
    {
	{METHOD_MKCOL, "MKCOL",
	    {0, 1}}, 5},
    {
	{METHOD_COPY, "COPY",
	    {0, 0}}, 4},
    {
	{METHOD_MOVE, "MOVE",
	    {0, 1}}, 4},
    {
	{METHOD_LOCK, "LOCK",
	    {0, 0}}, 4},
    {
	{METHOD_UNLOCK, "UNLOCK",
	    {0, 0}}, 6},
    {
	{METHOD_BMOVE, "BMOVE",
	    {0, 1}}, 5},
    {
	{METHOD_BDELETE, "BDELETE",
	    {0, 1}}, 7},
    {
	{METHOD_BPROPFIND, "BPROPFIND",
	    {0, 0}}, 9},
    {
	{METHOD_BPROPPATCH, "BPROPPATCH",
	    {0, 0}}, 10},
    {
	{METHOD_BCOPY, "BCOPY",
	    {0, 0}}, 5},
    {
	{METHOD_SEARCH, "SEARCH",
	    {0, 0}}, 6},
    {
	{METHOD_SUBSCRIBE, "SUBSCRIBE",
	    {0, 0}}, 9},
    {
	{METHOD_UNSUBSCRIBE, "UNSUBSCRIBE",
	    {0, 0}}, 11},
    {
	{METHOD_POLL, "POLL",
	    {0, 0}}, 4},
    {
	{METHOD_REPORT, "REPORT",
	    {0, 0}}, 6},
    {
	{METHOD_MKACTIVITY, "MKACTIVITY",
	    {0, 0}}, 10},
    {
	{METHOD_CHECKOUT, "CHECKOUT",
	    {0, 0}}, 8},
    {
	{METHOD_MERGE, "MERGE",
	    {0, 0}}, 5},
    {
	{METHOD_OTHER, NULL,
	    {0, 0}}, 0},
};

const char *ProtocolStr[] =
{
    "NONE",
    "http",
    "ftp",
    "gopher",
    "wais",
    "cache_object",
    "icp",
#if USE_HTCP
    "htcp",
#endif
    "urn",
    "whois",
    "internal",
    "https",
    "TOTAL"
};

static request_t *urnParse(method_t * method, char *urn);
static const char valid_hostname_chars_u[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789-._";
static const char valid_hostname_chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789-.";

/* convert %xx in url string to a character 
 * Allocate a new string and return a pointer to converted string */

char *
url_convert_hex(char *org_url, int allocate)
{
    static char code[] = "00";
    char *url = NULL;
    char *s = NULL;
    char *t = NULL;
    url = allocate ? (char *) xstrdup(org_url) : org_url;
    if ((int) strlen(url) < 3 || !strchr(url, '%'))
	return url;
    for (s = t = url; *s; s++) {
	if (*s == '%' && *(s + 1) && *(s + 2)) {
	    code[0] = *(++s);
	    code[1] = *(++s);
	    *t++ = (char) strtol(code, NULL, 16);
	} else {
	    *t++ = *s;
	}
    }
    do {
	*t++ = *s;
    } while (*s++);
    return url;
}

void
urlInitialize(void)
{
    debug(23, 5) ("urlInitialize: Initializing...\n");
    assert(sizeof(ProtocolStr) == (PROTO_MAX + 1) * sizeof(char *));
    memset(&null_request_flags, '\0', sizeof(null_request_flags));
    /*
     * These test that our matchDomainName() function works the
     * way we expect it to.
     */
    assert(0 == matchDomainName("foo.com", "foo.com"));
    assert(0 == matchDomainName(".foo.com", "foo.com"));
    assert(0 == matchDomainName("foo.com", ".foo.com"));
    assert(0 == matchDomainName(".foo.com", ".foo.com"));
    assert(0 == matchDomainName("x.foo.com", ".foo.com"));
    assert(0 != matchDomainName("x.foo.com", "foo.com"));
    assert(0 != matchDomainName("foo.com", "x.foo.com"));
    assert(0 != matchDomainName("bar.com", "foo.com"));
    assert(0 != matchDomainName(".bar.com", "foo.com"));
    assert(0 != matchDomainName(".bar.com", ".foo.com"));
    assert(0 != matchDomainName("bar.com", ".foo.com"));
    assert(0 < matchDomainName("zzz.com", "foo.com"));
    assert(0 > matchDomainName("aaa.com", "foo.com"));
    assert(0 == matchDomainName("FOO.com", "foo.COM"));
    assert(0 < matchDomainName("bfoo.com", "afoo.com"));
    assert(0 > matchDomainName("afoo.com", "bfoo.com"));
    assert(0 < matchDomainName("x-foo.com", ".foo.com"));
    /* more cases? */
}

method_t *
urlMethodGetKnown(const char *s, int len)
{
    struct rms *rms;

    for (rms = request_methods; rms->string_len != 0; rms++) {
	if (len != rms->string_len) {
	    continue;
	}
	if (strncasecmp(s, rms->method.string, len) == 0) {
	    return (&rms->method);
	}
    }

    return (NULL);
}

method_t *
urlMethodGet(const char *s, int len)
{
    method_t *method;

    method = urlMethodGetKnown(s, len);
    if (method != NULL) {
	return (method);
    }
    method = xmalloc(sizeof(method_t));
    method->code = METHOD_OTHER;
    method->string = xstrndup(s, len + 1);
    method->flags.cachable = 0;
    method->flags.purges_all = 1;

    return (method);
}

method_t *
urlMethodGetKnownByCode(method_code_t code)
{
    if (code < 0 || code >= METHOD_OTHER) {
	return (NULL);
    }
    return (&request_methods[code].method);
}

method_t *
urlMethodDup(method_t * orig)
{
    method_t *method;

    if (orig == NULL) {
	return (NULL);
    }
    if (orig->code != METHOD_OTHER) {
	return (orig);
    }
    method = xmalloc(sizeof(method_t));
    method->code = orig->code;
    method->string = xstrdup(orig->string);
    method->flags.cachable = orig->flags.cachable;
    method->flags.purges_all = orig->flags.purges_all;

    return (method);
}

void
urlMethodFree(method_t * method)
{

    if (method == NULL) {
	return;
    }
    if (method->code != METHOD_OTHER) {
	return;
    }
    xfree((char *) method->string);
    xfree(method);
}

protocol_t
urlParseProtocol(const char *s)
{
    /* test common stuff first */
    if (strcasecmp(s, "http") == 0)
	return PROTO_HTTP;
    if (strcasecmp(s, "ftp") == 0)
	return PROTO_FTP;
    if (strcasecmp(s, "https") == 0)
	return PROTO_HTTPS;
    if (strcasecmp(s, "file") == 0)
	return PROTO_FTP;
    if (strcasecmp(s, "gopher") == 0)
	return PROTO_GOPHER;
    if (strcasecmp(s, "wais") == 0)
	return PROTO_WAIS;
    if (strcasecmp(s, "cache_object") == 0)
	return PROTO_CACHEOBJ;
    if (strcasecmp(s, "urn") == 0)
	return PROTO_URN;
    if (strcasecmp(s, "whois") == 0)
	return PROTO_WHOIS;
    if (strcasecmp(s, "internal") == 0)
	return PROTO_INTERNAL;
    return PROTO_NONE;
}


int
urlDefaultPort(protocol_t p)
{
    switch (p) {
    case PROTO_HTTP:
	return 80;
    case PROTO_HTTPS:
	return 443;
    case PROTO_FTP:
	return 21;
    case PROTO_GOPHER:
	return 70;
    case PROTO_WAIS:
	return 210;
    case PROTO_CACHEOBJ:
    case PROTO_INTERNAL:
	return CACHE_HTTP_PORT;
    case PROTO_WHOIS:
	return 43;
    default:
	return 0;
    }
}

/*
 * This routine parses a URL. Its assumed that the URL is complete -
 * ie, the end of the string is the end of the URL. Don't pass a partial
 * URL here as this routine doesn't have any way of knowing whether
 * its partial or not (ie, it handles the case of no trailing slash as
 * being "end of host with implied path of /".
 */
request_t *
urlParse(method_t * method, char *url)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, login, MAX_URL);
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, urlpath, MAX_URL);
    request_t *request = NULL;
    char *t = NULL;
    char *q = NULL;
    int port;
    protocol_t protocol = PROTO_NONE;
    int l;
    int i;
    const char *src;
    char *dst;
    proto[0] = host[0] = urlpath[0] = login[0] = '\0';

    if ((l = strlen(url)) + Config.appendDomainLen > (MAX_URL - 1)) {
	/* terminate so it doesn't overflow other buffers */
	*(url + (MAX_URL >> 1)) = '\0';
	debug(23, 1) ("urlParse: URL too large (%d bytes)\n", l);
	return NULL;
    }
    if (method->code == METHOD_CONNECT) {
	port = CONNECT_PORT;
	if (sscanf(url, "%[^:]:%d", host, &port) < 1)
	    return NULL;
    } else if (!strncmp(url, "urn:", 4)) {
	return urnParse(method, url);
    } else {
	/* Parse the URL: */
	src = url;
	i = 0;
	/* Find first : - everything before is protocol */
	for (i = 0, dst = proto; i < l && *src != ':'; i++, src++, dst++) {
	    *dst = *src;
	}
	if (i >= l)
	    return NULL;
	*dst = '\0';

	/* Then its :// */
	/* (XXX yah, I'm not checking we've got enough data left before checking the array..) */
	if (*src != ':' || *(src + 1) != '/' || *(src + 2) != '/')
	    return NULL;
	i += 3;
	src += 3;

	/* Then everything until first /; thats host (and port; which we'll look for here later) */
	/* bug 1881: If we don't get a "/" then we imply it was there */
	for (dst = host; i < l && *src != '/' && src != '\0'; i++, src++, dst++) {
	    *dst = *src;
	}
	/* 
	 * We can't check for "i >= l" here because we could be at the end of the line
	 * and have a perfectly valid URL w/ no trailing '/'. In this case we assume we've
	 * been -given- a valid URL and the path is just '/'.
	 */
	if (i > l)
	    return NULL;
	*dst = '\0';

	/* Then everything from / (inclusive) until \r\n or \0 - thats urlpath */
	for (dst = urlpath; i < l && *src != '\r' && *src != '\n' && *src != '\0'; i++, src++, dst++) {
	    *dst = *src;
	}
	/* We -could- be at the end of the buffer here */
	if (i > l)
	    return NULL;
	/* If the URL path is empty we set it to be "/" */
	if (dst == urlpath) {
	    *(dst++) = '/';
	}
	*dst = '\0';

	protocol = urlParseProtocol(proto);
	port = urlDefaultPort(protocol);
	/* Is there any login informaiton? (we should eventually parse it above) */
	if ((t = strrchr(host, '@'))) {
	    strcpy((char *) login, (char *) host);
	    t = strrchr(login, '@');
	    *t = 0;
	    strcpy((char *) host, t + 1);
	}
	/* Is there any host information? (we should eventually parse it above) */
	if ((t = strrchr(host, ':'))) {
	    *t++ = '\0';
	    if (*t != '\0')
		port = atoi(t);
	}
    }
    for (t = host; *t; t++)
	*t = xtolower(*t);
    if (stringHasWhitespace(host)) {
	if (URI_WHITESPACE_STRIP == Config.uri_whitespace) {
	    t = q = host;
	    while (*t) {
		if (!xisspace(*t))
		    *q++ = *t;
		t++;
	    }
	    *q = '\0';
	}
    }
    if (Config.onoff.check_hostnames && strspn(host, Config.onoff.allow_underscore ? valid_hostname_chars_u : valid_hostname_chars) != strlen(host)) {
	debug(23, 1) ("urlParse: Illegal character in hostname '%s'\n", host);
	return NULL;
    }
    if (Config.appendDomain && !strchr(host, '.'))
	strncat(host, Config.appendDomain, SQUIDHOSTNAMELEN - strlen(host) - 1);
    /* remove trailing dots from hostnames */
    while ((l = strlen(host)) > 0 && host[--l] == '.')
	host[l] = '\0';
    /* reject duplicate or leading dots */
    if (strstr(host, "..") || *host == '.') {
	debug(23, 1) ("urlParse: Illegal hostname '%s'\n", host);
	return NULL;
    }
    if (port < 1 || port > 65535) {
	debug(23, 3) ("urlParse: Invalid port '%d'\n", port);
	return NULL;
    }
#ifdef HARDCODE_DENY_PORTS
    /* These ports are filtered in the default squid.conf, but
     * maybe someone wants them hardcoded... */
    if (port == 7 || port == 9 || port == 19) {
	debug(23, 0) ("urlParse: Deny access to port %d\n", port);
	return NULL;
    }
#endif
    if (stringHasWhitespace(urlpath)) {
	debug(23, 2) ("urlParse: URI has whitespace: {%s}\n", url);
	switch (Config.uri_whitespace) {
	case URI_WHITESPACE_DENY:
	    return NULL;
	case URI_WHITESPACE_ALLOW:
	    break;
	case URI_WHITESPACE_ENCODE:
	    t = rfc1738_escape_unescaped(urlpath);
	    xstrncpy(urlpath, t, MAX_URL);
	    break;
	case URI_WHITESPACE_CHOP:
	    *(urlpath + strcspn(urlpath, w_space)) = '\0';
	    break;
	case URI_WHITESPACE_STRIP:
	default:
	    t = q = urlpath;
	    while (*t) {
		if (!xisspace(*t))
		    *q++ = *t;
		t++;
	    }
	    *q = '\0';
	}
    }
    request = requestCreate(method, protocol, urlpath);
    xstrncpy(request->host, host, SQUIDHOSTNAMELEN);
    xstrncpy(request->login, login, MAX_LOGIN_SZ);
    request->port = (u_short) port;
    return request;
}

static request_t *
urnParse(method_t * method, char *urn)
{
    debug(50, 5) ("urnParse: %s\n", urn);
    return requestCreate(method, PROTO_URN, urn + 4);
}

const char *
urlCanonical(request_t * request)
{
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, urlbuf, MAX_URL);
    if (request->canonical)
	return request->canonical;
    if (request->protocol == PROTO_URN) {
	snprintf(urlbuf, MAX_URL, "urn:%s", strBuf(request->urlpath));
    } else {
	switch (request->method->code) {
	case METHOD_CONNECT:
	    snprintf(urlbuf, MAX_URL, "%s:%d", request->host, request->port);
	    break;
	default:
	    portbuf[0] = '\0';
	    if (request->port != urlDefaultPort(request->protocol))
		snprintf(portbuf, 32, ":%d", request->port);
	    snprintf(urlbuf, MAX_URL, "%s://%s%s%s%s%s",
		ProtocolStr[request->protocol],
		request->login,
		*request->login ? "@" : null_string,
		request->host,
		portbuf,
		strBuf(request->urlpath));
	    break;
	}
    }
    return (request->canonical = xstrdup(urlbuf));
}

/*
 * Test if a URL is relative.
 *
 * RFC 2396, Section 5 (Page 17) implies that in a relative URL, a '/' will
 * appear before a ':'.
 */
int
urlIsRelative(const char *url)
{
    const char *p;

    if (url == NULL) {
	return (0);
    }
    if (*url == '\0') {
	return (0);
    }
    for (p = url; *p != '\0' && *p != ':' && *p != '/'; p++);

    if (*p == ':') {
	return (0);
    }
    return (1);
}

/*
 * Convert a relative URL to an absolute URL using the context of a given
 * request.
 *
 * It is assumed that you have already ensured that the URL is relative.
 *
 * If NULL is returned it is an indication that the method in use in the
 * request does not distinguish between relative and absolute and you should
 * use the url unchanged.
 *
 * If non-NULL is returned, it is up to the caller to free the resulting
 * memory using safe_free().
 */
char *
urlMakeAbsolute(request_t * req, const char *relUrl)
{
    char *urlbuf;
    const char *path, *last_slash;
    size_t urllen, pathlen;

    if (req->method->code == METHOD_CONNECT) {
	return (NULL);
    }
    urlbuf = (char *) xmalloc(MAX_URL * sizeof(char));

    if (req->protocol == PROTO_URN) {
	snprintf(urlbuf, MAX_URL, "urn:%s", strBuf(req->urlpath));
	return (urlbuf);
    }
    if (req->port != urlDefaultPort(req->protocol)) {
	urllen = snprintf(urlbuf, MAX_URL, "%s://%s%s%s:%d",
	    ProtocolStr[req->protocol],
	    req->login,
	    *req->login ? "@" : null_string,
	    req->host,
	    req->port
	    );
    } else {
	urllen = snprintf(urlbuf, MAX_URL, "%s://%s%s%s",
	    ProtocolStr[req->protocol],
	    req->login,
	    *req->login ? "@" : null_string,
	    req->host
	    );
    }

    if (relUrl[0] == '/') {
	strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
    } else {
	path = strBuf(req->urlpath);
	last_slash = strrchr(path, '/');
	if (last_slash == NULL) {
	    urlbuf[urllen++] = '/';
	    strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
	} else {
	    last_slash++;
	    pathlen = last_slash - path;
	    if (pathlen > MAX_URL - urllen - 1) {
		pathlen = MAX_URL - urllen - 1;
	    }
	    strncpy(&urlbuf[urllen], path, pathlen);
	    urllen += pathlen;
	    if (urllen + 1 < MAX_URL) {
		strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
	    }
	}
    }

    return (urlbuf);
}

/*
 * Eventually the request_t strings should be String entries which
 * have in-built length. Eventually we should just take a buffer and
 * do our magic inside that to eliminate that copy.
 */
char *
urlCanonicalClean(const request_t * request)
{
    LOCAL_ARRAY(char, buf, MAX_URL);
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, loginbuf, MAX_LOGIN_SZ + 1);
    char *t;
    int i;
    const char *s;
    static const char ts[] = "://";

    if (request->protocol == PROTO_URN) {
	snprintf(buf, MAX_URL, "urn:%s", strBuf(request->urlpath));
    } else {
	switch (request->method->code) {
	case METHOD_CONNECT:
	    snprintf(buf, MAX_URL, "%s:%d", request->host, request->port);
	    break;
	default:
	    portbuf[0] = '\0';
	    if (request->port != urlDefaultPort(request->protocol))
		snprintf(portbuf, 32, ":%d", request->port);
	    loginbuf[0] = '\0';
	    if ((int) strlen(request->login) > 0) {
		strcpy(loginbuf, request->login);
		if ((t = strchr(loginbuf, ':')))
		    *t = '\0';
		strcat(loginbuf, "@");
	    }
	    /*
	     * This stuff would be better if/when each of these strings is a String with
	     * a known length..
	     */
	    s = ProtocolStr[request->protocol];
	    for (i = 0; i < MAX_URL && *s != '\0'; i++, s++) {
		buf[i] = *s;
	    }
	    s = ts;
	    for (; i < MAX_URL && *s != '\0'; i++, s++) {
		buf[i] = *s;
	    }
	    s = loginbuf;
	    for (; i < MAX_URL && *s != '\0'; i++, s++) {
		buf[i] = *s;
	    }
	    s = request->host;
	    for (; i < MAX_URL && *s != '\0'; i++, s++) {
		buf[i] = *s;
	    }
	    s = portbuf;
	    for (; i < MAX_URL && *s != '\0'; i++, s++) {
		buf[i] = *s;
	    }
	    s = strBuf(request->urlpath);
	    for (; i < MAX_URL && *s != '\0'; i++, s++) {
		buf[i] = *s;
	    }
	    if (i >= (MAX_URL - 1)) {
		buf[MAX_URL - 1] = '\0';
	    } else {
		buf[i] = '\0';
	    }

	    /*
	     * strip arguments AFTER a question-mark
	     */
	    if (Config.onoff.strip_query_terms)
		if ((t = strchr(buf, '?')))
		    *(++t) = '\0';
	    break;
	}
    }
    if (stringHasCntl(buf))
	xstrncpy(buf, rfc1738_escape_unescaped(buf), MAX_URL);
    return buf;
}

/*
 * matchDomainName() compares a hostname with a domainname according
 * to the following rules:
 * 
 *    HOST          DOMAIN        MATCH?
 * ------------- -------------    ------
 *    foo.com       foo.com         YES
 *   .foo.com       foo.com         YES
 *  x.foo.com       foo.com          NO
 *    foo.com      .foo.com         YES
 *   .foo.com      .foo.com         YES
 *  x.foo.com      .foo.com         YES
 *
 *  We strip leading dots on hosts (but not domains!) so that
 *  ".foo.com" is is always the same as "foo.com".
 *
 *  Return values:
 *     0 means the host matches the domain
 *     1 means the host is greater than the domain
 *    -1 means the host is less than the domain
 */

int
matchDomainName(const char *h, const char *d)
{
    int dl;
    int hl;
    while ('.' == *h)
	h++;
    hl = strlen(h);
    dl = strlen(d);
    /*
     * Start at the ends of the two strings and work towards the
     * beginning.
     */
    while (xtolower(h[--hl]) == xtolower(d[--dl])) {
	if (hl == 0 && dl == 0) {
	    /*
	     * We made it all the way to the beginning of both
	     * strings without finding any difference.
	     */
	    return 0;
	}
	if (0 == hl) {
	    /* 
	     * The host string is shorter than the domain string.
	     * There is only one case when this can be a match.
	     * If the domain is just one character longer, and if
	     * that character is a leading '.' then we call it a
	     * match.
	     */
	    if (1 == dl && '.' == d[0])
		return 0;
	    else
		return -1;
	}
	if (0 == dl) {
	    /*
	     * The domain string is shorter than the host string.
	     * This is a match only if the first domain character
	     * is a leading '.'.
	     */
	    if ('.' == d[0])
		return 0;
	    else
		return 1;
	}
    }
    /*
     * We found different characters in the same position (from the end).
     */
    /*
     * If one of those character is '.' then its special.  In order
     * for splay tree sorting to work properly, "x-foo.com" must
     * be greater than ".foo.com" even though '-' is less than '.'.
     */
    if ('.' == d[dl])
	return 1;
    if ('.' == h[hl])
	return -1;
    return (xtolower(h[hl]) - xtolower(d[dl]));
}

int
urlCheckRequest(const request_t * r)
{
    int rc = 0;
    /* protocol "independent" methods */
    if (r->method->code == METHOD_CONNECT)
	return 1;
    if (r->method->code == METHOD_TRACE)
	return 1;
    if (r->method->code == METHOD_PURGE)
	return 1;
    /* does method match the protocol? */
    switch (r->protocol) {
    case PROTO_URN:
    case PROTO_HTTP:
    case PROTO_INTERNAL:
    case PROTO_CACHEOBJ:
	rc = 1;
	break;
    case PROTO_FTP:
	if (r->method->code == METHOD_PUT)
	    rc = 1;
    case PROTO_GOPHER:
    case PROTO_WAIS:
    case PROTO_WHOIS:
	if (r->method->code == METHOD_GET)
	    rc = 1;
	else if (r->method->code == METHOD_HEAD)
	    rc = 1;
	break;
    case PROTO_HTTPS:
#ifdef USE_SSL
	rc = 1;
	break;
#else
	/*
	 * Squid can't originate an SSL connection, so it should
	 * never receive an "https:" URL.  It should always be
	 * CONNECT instead.
	 */
	rc = 0;
#endif
    default:
	break;
    }
    return rc;
}

/*
 * Quick-n-dirty host extraction from a URL.  Steps:
 *      Look for a colon
 *      Skip any '/' after the colon
 *      Copy the next SQUID_MAXHOSTNAMELEN bytes to host[]
 *      Look for an ending '/' or ':' and terminate
 *      Look for login info preceeded by '@'
 */
char *
urlHostname(const char *url)
{
    LOCAL_ARRAY(char, host, SQUIDHOSTNAMELEN);
    char *t;
    host[0] = '\0';
    if (NULL == (t = strchr(url, ':')))
	return NULL;
    t++;
    while (*t != '\0' && *t == '/')
	t++;
    xstrncpy(host, t, SQUIDHOSTNAMELEN);
    if ((t = strchr(host, '/')))
	*t = '\0';
    if ((t = strchr(host, ':')))
	*t = '\0';
    if ((t = strrchr(host, '@'))) {
	t++;
	xmemmove(host, t, strlen(t) + 1);
    }
    return host;
}
