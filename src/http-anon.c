
/*
 * $Id$
 *
 * DEBUG: 
 * AUTHOR: Lutz Donnerhacke <lutz@iks-jena.de>
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
 * References:
 *    http://www.fitug.de/archiv/dokus/allgemeines/anonymizer.html
 *    http://www.iks-jena.de/mitarb/lutz/anon/web.en.html
 *
 * This file contains an field of all header strings of HTTP which
 * should pass the proxy. Any other field is removed from the redirected
 * request to keep the sender anonymous.
 * 
 * 20.2.1997 wessels
 *  - removed #ifdefs, code is always compiled in and controlled with
 *    'http_anonymizer' in the config file.
 * 
 * v0.2 - 6.2.1997:
 *  - Authorization: is moved from 'bad' to 'good' meaning to enable passwords
 *  - ANONYMIZER_PARANOIC switch added to select a paranoic/normal filtering
 *
 *
 * v0.1 - 5.12.1996:
 *  - made static and following naming conventions of 1.1beta28
 *  - switched to new entry point in http.c (httpAppendRequestHeader)
 *
 * v0.0 - 5.9.1996:
 *  - just filtering headers
 * 
 * todo:
 *  - Make this field run time configurable.
 *  - MIME Multipart encoding is not scanned.
 *  - examining Content of special headers
 */

#include "squid.h"

#if OLD_CODE
struct http_anon_struct_header {
    const char *name;
    size_t len;
};
#endif

/* Allowed Headers
 *
 * If 'http_anonymizer' is set to 'paranoid' then only these headers
 * will be passed, all others (including HDR_OTHER) will be removed
 */
static HttpHeaderMask HttpAllowedHeadersMask;
static http_hdr_type HttpAllowedHeadersArr[] =
{
    HDR_ALLOW, HDR_AUTHORIZATION, HDR_CACHE_CONTROL, HDR_CONTENT_ENCODING,
    HDR_CONTENT_LENGTH, HDR_CONTENT_TYPE, HDR_DATE, HDR_EXPIRES, HDR_HOST,
    HDR_IF_MODIFIED_SINCE, HDR_LAST_MODIFIED, HDR_LOCATION, 
    HDR_PRAGMA,
    HDR_ACCEPT, HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE,
    HDR_CONTENT_LANGUAGE, HDR_MIME_VERSION, HDR_RETRY_AFTER, HDR_TITLE,
    HDR_CONNECTION, HDR_PROXY_CONNECTION
};
/* Note: HDR_URI is deprecated in RFC 2068 */
    
/* Denied Headers
 *
 * If 'http_anonymizer' is set to 'standard' then these headers
 * will be removed, all others will be passed.
 */
static HttpHeaderMask HttpDeniedHeadersMask;
static http_hdr_type HttpDeniedHeadersArr[] =
{
    HDR_FROM, HDR_REFERER, HDR_SERVER,
    HDR_USER_AGENT,       /* filtering violates HTTP */
    HDR_WWW_AUTHENTICATE, /* filtering violates HTTP */
    HDR_LINK
};

void
httpAnonInitModule()
{
    httpHeaderMaskInit(&HttpAllowedHeadersMask);
    httpHeaderCalcMask(&HttpAllowedHeadersMask, (const int *) HttpAllowedHeadersArr, countof(HttpAllowedHeadersArr));
    httpHeaderMaskInit(&HttpDeniedHeadersMask);
    httpHeaderCalcMask(&HttpDeniedHeadersMask, (const int *) HttpDeniedHeadersArr, countof(HttpDeniedHeadersArr));
}

#if OLD_CODE
/* Return 1 if 'line' is found in the 'header_field' list */
static int
httpAnonSearchHeaderField(const struct http_anon_struct_header *header_field,
    const char *line)
{
    const struct http_anon_struct_header *ppc;
    for (ppc = header_field; ppc->len; ppc++)
	if (strncasecmp(line, ppc->name, ppc->len) == 0)
	    return 1;
    return 0;
}
int
httpAnonAllowed(const char *line)
{
    if (*line == '\0')		/* the terminating empty line */
	return 1;
    return httpAnonSearchHeaderField(http_anon_allowed_header, line);
}

int
httpAnonDenied(const char *line)
{
    if (*line == '\0')		/* the terminating empty line */
	return 0;
    return httpAnonSearchHeaderField(http_anon_denied_header, line);
}
#endif

int
httpAnonHdrAllowed(http_hdr_type hdr_id)
{
    return hdr_id != HDR_OTHER && CBIT_TEST(HttpAllowedHeadersMask, hdr_id);
}

int
httpAnonHdrDenied(http_hdr_type hdr_id)
{
    return hdr_id != HDR_OTHER && CBIT_TEST(HttpDeniedHeadersMask, hdr_id);
}
