
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

rms_t RequestMethods[] =
{
    {(char *) "NONE", 4},
    {(char *) "GET", 3},
    {(char *) "POST", 4},
    {(char *) "PUT", 3},
    {(char *) "HEAD", 4},
    {(char *) "CONNECT", 7},
    {(char *) "TRACE", 5},
    {(char *) "PURGE", 5},
    {(char *) "OPTIONS", 7},
    {(char *) "DELETE", 6},
    {(char *) "PROPFIND", 8},
    {(char *) "PROPPATCH", 9},
    {(char *) "MKCOL", 5},
    {(char *) "COPY", 4},
    {(char *) "MOVE", 4},
    {(char *) "LOCK", 4},
    {(char *) "UNLOCK", 6},
    {(char *) "BMOVE", 5},
    {(char *) "BDELETE", 7},
    {(char *) "BPROPFIND", 9},
    {(char *) "BPROPPATCH", 10},
    {(char *) "BCOPY", 5},
    {(char *) "SEARCH", 6},
    {(char *) "SUBSCRIBE", 9},
    {(char *) "UNSUBSCRIBE", 11},
    {(char *) "POLL", 4},
    {(char *) "REPORT", 6},
    {(char *) "%EXT00", 6},
    {(char *) "%EXT01", 6},
    {(char *) "%EXT02", 6},
    {(char *) "%EXT03", 6},
    {(char *) "%EXT04", 6},
    {(char *) "%EXT05", 6},
    {(char *) "%EXT06", 6},
    {(char *) "%EXT07", 6},
    {(char *) "%EXT08", 6},
    {(char *) "%EXT09", 6},
    {(char *) "%EXT10", 6},
    {(char *) "%EXT11", 6},
    {(char *) "%EXT12", 6},
    {(char *) "%EXT13", 6},
    {(char *) "%EXT14", 6},
    {(char *) "%EXT15", 6},
    {(char *) "%EXT16", 6},
    {(char *) "%EXT17", 6},
    {(char *) "%EXT18", 6},
    {(char *) "%EXT19", 6},
    {(char *) "ERROR", 5},
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

static request_t *urnParse(method_t method, char *urn);
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

method_t
urlParseMethod(const char *s, int len)
{
    method_t method = METHOD_NONE;
    /*
     * This check for '%' makes sure that we don't
     * match one of the extension method placeholders,
     * which have the form %EXT[0-9][0-9]
     */
    if (*s == '%')
	return METHOD_NONE;
    for (method++; method < METHOD_ENUM_END; method++) {
	if (len == RequestMethods[method].len && 0 == strncasecmp(s, RequestMethods[method].str, len))
	    return method;
    }
    return METHOD_NONE;
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
urlParse(method_t method, char *url)
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
    if (method == METHOD_CONNECT) {
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
urnParse(method_t method, char *urn)
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
	switch (request->method) {
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
	switch (request->method) {
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
    if (r->method == METHOD_CONNECT)
	return 1;
    if (r->method == METHOD_TRACE)
	return 1;
    if (r->method == METHOD_PURGE)
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
	if (r->method == METHOD_PUT)
	    rc = 1;
    case PROTO_GOPHER:
    case PROTO_WAIS:
    case PROTO_WHOIS:
	if (r->method == METHOD_GET)
	    rc = 1;
	else if (r->method == METHOD_HEAD)
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

static void
urlExtMethodAdd(const char *mstr)
{
    method_t method = 0;
    for (method++; method < METHOD_ENUM_END; method++) {
	if (0 == strcmp(mstr, RequestMethods[method].str)) {
	    debug(23, 2) ("Extension method '%s' already exists\n", mstr);
	    return;
	}
	if (0 != strncmp("%EXT", RequestMethods[method].str, 4))
	    continue;
	/* Don't free statically allocated "%EXTnn" string */
	if (0 == strncmp("%EXT_", RequestMethods[method].str, 5))
	    safe_free(RequestMethods[method].str);
	RequestMethods[method].str = xstrdup(mstr);
	RequestMethods[method].len = strlen(mstr);
	debug(23, 1) ("Extension method '%s' added, enum=%d\n", mstr, (int) method);
	return;
    }
    debug(23, 1) ("WARNING: Could not add new extension method '%s' due to lack of array space\n", mstr);
}

void
parse_extension_method(rms_t(*foo)[])
{
    char *token;
    char *t = strtok(NULL, "");
    while ((token = strwordtok(NULL, &t))) {
	urlExtMethodAdd(token);
    }
}

void
free_extension_method(rms_t(*foo)[])
{
    method_t method;
    for (method = METHOD_EXT00; method < METHOD_ENUM_END; method++) {
	if (RequestMethods[method].str[0] != '%') {
	    char buf[32];
	    snprintf(buf, sizeof(buf), "%%EXT_%02d", method - METHOD_EXT00);
	    safe_free(RequestMethods[method].str);
	    RequestMethods[method].str = xstrdup(buf);
	    RequestMethods[method].len = strlen(buf);
	}
    }
}

void
dump_extension_method(StoreEntry * entry, const char *name, rms_t * methods)
{
    method_t method;
    for (method = METHOD_EXT00; method < METHOD_ENUM_END; method++) {
	if (RequestMethods[method].str[0] != '%') {
	    storeAppendPrintf(entry, "%s %s\n", name, RequestMethods[method].str);
	}
    }
}
