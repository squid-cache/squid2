
/*
 * $Id$
 *
 * DEBUG: section 74    HTTP Message
 * AUTHOR: Alex Rousskov
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

int
httpMsgParseRequestHeader(request_t * req, HttpMsgBuf * hmsg)
{
    const char *s, *e;
    s = hmsg->buf + hmsg->h_start;
    e = hmsg->buf + hmsg->h_end + 1;
    return httpHeaderParse(&req->header, s, e);
}

/* find end of headers */
int
httpMsgIsolateHeaders(const char **parse_start, int l, const char **blk_start, const char **blk_end)
{
    /*
     * parse_start points to the first line of HTTP message *headers*,
     * not including the request or status lines
     */
    int end = headersEnd(*parse_start, l);
    int nnl;
    if (end) {
	*blk_start = *parse_start;
	*blk_end = *parse_start + end - 1;
	/*
	 * leave blk_end pointing to the first character after the
	 * first newline which terminates the headers
	 */
	assert(**blk_end == '\n');
	while (*(*blk_end - 1) == '\r')
	    (*blk_end)--;
	assert(*(*blk_end - 1) == '\n');
	*parse_start += end;
	return 1;
    }
    /*
     * If we didn't find the end of headers, and parse_start does
     * NOT point to a CR or NL character, then return failure
     */
    if (**parse_start != '\r' && **parse_start != '\n')
	return 0;		/* failure */
    /*
     * If we didn't find the end of headers, and parse_start does point
     * to an empty line, then we have empty headers.  Skip all CR and
     * NL characters up to the first NL.  Leave parse_start pointing at
     * the first character after the first NL.
     */
    *blk_start = *parse_start;
    *blk_end = *blk_start;
    for (nnl = 0; nnl == 0; (*parse_start)++) {
	if (**parse_start == '\r')
	    (void) 0;
	else if (**parse_start == '\n')
	    nnl++;
	else
	    break;
    }
    return 1;
}

/* returns true if connection should be "persistent" 
 * after processing this message */
int
httpMsgIsPersistent(http_version_t http_ver, const HttpHeader * hdr)
{
    if (httpHeaderHasConnDir(hdr, "close"))
	return 0;
#if WHEN_SQUID_IS_HTTP1_1
    if ((http_ver.major >= 1) && (http_ver.minor >= 1)) {
	/*
	 * for modern versions of HTTP: persistent unless there is
	 * a "Connection: close" header.
	 */
	return 1;
    } else {
#else
    {
#endif
	/*
	 * Persistent connections in Netscape 3.x are allegedly broken,
	 * return false if it is a browser connection.  If there is a
	 * VIA header, then we assume this is NOT a browser connection.
	 */
	const char *agent = httpHeaderGetStr(hdr, HDR_USER_AGENT);
	if (agent && !httpHeaderHas(hdr, HDR_VIA)) {
	    if (!strncasecmp(agent, "Mozilla/3.", 10))
		return 0;
	    if (!strncasecmp(agent, "Netscape/3.", 11))
		return 0;
	}
	/* for old versions of HTTP: persistent if has "keep-alive" */
	return httpHeaderHasConnDir(hdr, "keep-alive");
    }
}

/* Adrian's replacement message buffer code to parse the request/reply line */

void
HttpMsgBufInit(HttpMsgBuf * hmsg, const char *buf, size_t size)
{
    hmsg->buf = buf;
    hmsg->size = size;
    hmsg->req_start = hmsg->req_end = -1;
    hmsg->h_start = hmsg->h_end = -1;
    hmsg->r_len = hmsg->u_len = hmsg->m_len = hmsg->v_len = hmsg->h_len = 0;
}

void
httpMsgBufDone(HttpMsgBuf * hmsg)
{
    (void) 0;
}


/*
 * Attempt to parse the request line.
 *
 * This will set the values in hmsg that it determines. One may end up 
 * with a partially-parsed buffer; the return value tells you whether
 * the values are valid or not.
 *
 * @return 1 if parsed correctly, 0 if more is needed, -1 if error
 *
 * TODO:
 *   * have it indicate "error" and "not enough" as two separate conditions!
 *   * audit this code as off-by-one errors are probably everywhere!
 */
int
httpMsgParseRequestLine(HttpMsgBuf * hmsg)
{
    int i = 0;
    int retcode;
    int maj = -1, min = -1;
    int last_whitespace = -1, line_end = -1;
    const char *t;

    /* Find \r\n - end of URL+Version (and the request) */
    t = memchr(hmsg->buf, '\n', hmsg->size);
    if (!t) {
	retcode = 0;
	goto finish;
    }
    /* XXX this should point to the -end- of the \r\n, \n, etc. */
    hmsg->req_end = t - hmsg->buf;
    i = 0;

    /* Find first non-whitespace - beginning of method */
    for (; i < hmsg->req_end && (xisspace(hmsg->buf[i])); i++);
    if (i >= hmsg->req_end) {
	retcode = 0;
	goto finish;
    }
    hmsg->m_start = i;
    hmsg->req_start = i;
    hmsg->r_len = hmsg->req_end - hmsg->req_start + 1;

    /* Find first whitespace - end of method */
    for (; i < hmsg->req_end && (!xisspace(hmsg->buf[i])); i++);
    if (i >= hmsg->req_end) {
	retcode = -1;
	goto finish;
    }
    hmsg->m_end = i - 1;
    hmsg->m_len = hmsg->m_end - hmsg->m_start + 1;

    /* Find first non-whitespace - beginning of URL+Version */
    for (; i < hmsg->req_end && (xisspace(hmsg->buf[i])); i++);
    if (i >= hmsg->req_end) {
	retcode = -1;
	goto finish;
    }
    hmsg->u_start = i;

    /* Find \r\n or \n - thats the end of the line. Keep track of the last whitespace! */
    for (; i <= hmsg->req_end; i++) {
	/* If \n - its end of line */
	if (hmsg->buf[i] == '\n') {
	    line_end = i;
	    break;
	}
	/* we know for sure that there is at least a \n following.. */
	if (hmsg->buf[i] == '\r' && hmsg->buf[i + 1] == '\n') {
	    line_end = i;
	    break;
	}
	/* If its a whitespace, note it as it'll delimit our version */
	if (hmsg->buf[i] == ' ' || hmsg->buf[i] == '\t') {
	    last_whitespace = i;
	}
    }
    if (i > hmsg->req_end) {
	retcode = -1;
	goto finish;
    }
    /* At this point we don't need the 'i' value; so we'll recycle it for version parsing */

    /* 
     * At this point: line_end points to the first eol char (\r or \n);
     * last_whitespace points to the last whitespace char in the URL.
     * We know we have a full buffer here!
     */
    if (last_whitespace == -1) {
	maj = 0;
	min = 9;
	hmsg->u_end = line_end - 1;
	assert(hmsg->u_end >= hmsg->u_start);
    } else {
	/* Find the first non-whitespace after last_whitespace */
	/* XXX why <= vs < ? I do need to really re-audit all of this .. */
	for (i = last_whitespace; i <= hmsg->req_end && xisspace(hmsg->buf[i]); i++);
	if (i > hmsg->req_end) {
	    retcode = -1;
	    goto finish;
	}
	/* is it http/ ? if so, we try parsing. If not, the URL is the whole line; version is 0.9 */
	if (i + 5 >= hmsg->req_end || (strncasecmp(&hmsg->buf[i], "HTTP/", 5) != 0)) {
	    maj = 0;
	    min = 9;
	    hmsg->u_end = line_end - 1;
	    assert(hmsg->u_end >= hmsg->u_start);
	} else {
	    /* Ok, lets try parsing! Yes, this needs refactoring! */
	    hmsg->v_start = i;
	    i += 5;

	    /* next should be 1 or more digits */
	    maj = 0;
	    for (; i < hmsg->req_end && (xisdigit(hmsg->buf[i])); i++) {
		maj = maj * 10;
		maj = maj + (hmsg->buf[i]) - '0';
	    }
	    if (i >= hmsg->req_end) {
		retcode = -1;
		goto finish;
	    }
	    /* next should be .; we -have- to have this as we have a whole line.. */
	    if (hmsg->buf[i] != '.') {
		retcode = 0;
		goto finish;
	    }
	    if (i + 1 >= hmsg->req_end) {
		retcode = -1;
		goto finish;
	    }
	    /* next should be one or more digits */
	    i++;
	    min = 0;
	    for (; i < hmsg->req_end && (xisdigit(hmsg->buf[i])); i++) {
		min = min * 10;
		min = min + (hmsg->buf[i]) - '0';
	    }

	    /* Find whitespace, end of version */
	    hmsg->v_end = i;
	    hmsg->v_len = hmsg->v_end - hmsg->v_start + 1;
	    hmsg->u_end = last_whitespace - 1;
	}
    }
    hmsg->u_len = hmsg->u_end - hmsg->u_start + 1;

    /* 
     * Rightio - we have all the schtuff. Return true; we've got enough.
     */
    retcode = 1;
    assert(maj != -1);
    assert(min != -1);
  finish:
    hmsg->v_maj = maj;
    hmsg->v_min = min;
    debug(1, 2) ("Parser: retval %d: from %d->%d: method %d->%d; url %d->%d; version %d->%d (%d/%d)\n",
	retcode, hmsg->req_start, hmsg->req_end,
	hmsg->m_start, hmsg->m_end,
	hmsg->u_start, hmsg->u_end,
	hmsg->v_start, hmsg->v_end, maj, min);
    return retcode;
}

/*
 * A temporary replacement for headersEnd() in this codebase.
 * This routine searches for the end of the headers in a HTTP request
 * (obviously anything > HTTP/0.9.)
 *
 * It returns buffer length on success or 0 on failure.
 */
int
httpMsgFindHeadersEnd(HttpMsgBuf * hmsg)
{
    int e = 0;
    int state = 1;
    const char *mime = hmsg->buf;
    int l = hmsg->size;
    int he = -1;

    /* Always succeed HTTP/0.9 - it means we've already parsed the buffer for the request */
    if (hmsg->v_maj == 0 && hmsg->v_min == 9)
	return 1;

    while (e < l && state < 3) {
	switch (state) {
	case 0:
	    if ('\n' == mime[e]) {
		he = e;
		state = 1;
	    }
	    break;
	case 1:
	    if ('\r' == mime[e])
		state = 2;
	    else if ('\n' == mime[e])
		state = 3;
	    else
		state = 0;
	    break;
	case 2:
	    if ('\n' == mime[e])
		state = 3;
	    else
		state = 0;
	    break;
	default:
	    break;
	}
	e++;
    }
    if (3 == state) {
	hmsg->h_end = he;
	hmsg->h_start = hmsg->req_end + 1;
	hmsg->h_len = hmsg->h_end - hmsg->h_start;
	return e;
    }
    return 0;

}
