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

struct http_anon_struct_header {
    const char *name;
    size_t len;
};

/* Allowed Headers
 *
 * If 'http_anonymizer' is set to 'paranoid' then only the request
 * lines in this file will be passed, all others will be removed
 */
static struct http_anon_struct_header http_anon_allowed_header[] =
{
    {"GET ", 4},
    {"POST ", 5},
    {"HEAD ", 5},
    {"Allow:", 6},
    {"Authorization:", 14},
    {"Cache-control:", 14},
    {"Content-Encoding:", 17},
    {"Content-Length:", 15},
    {"Content-Type:", 13},
    {"Date:", 5},
    {"Expires:", 8},
    {"Host:", 5},
    {"If-Modified-Since:", 18},
    {"Last-Modified:", 14},
    {"Location:", 9},
    {"Pragma:", 7},		/* examining content */
    {"Accept:", 7},
    {"Accept-Charset:", 15},
    {"Accept-Encoding:", 16},
    {"Accept-Language:", 16},
    {"Content-Language:", 17},
    {"MIME-Version:", 13},
    {"Retry-After:", 12},
    {"Title:", 6},
    {"URI:", 4},
    {"Connection:", 11},
    {"Proxy-Connection:", 17},
    {NULL, 0}
};

/* Denied Headers
 *
 * If 'http_anonymizer' is set to 'standard' then these headers
 * will be removed, all others will be passed.
 */
static struct http_anon_struct_header http_anon_denied_header[] =
{
    {"From:", 5},
    {"Referer:", 8},
    {"Server:", 7},
    {"User-Agent:", 11},	/* filtering violates HTTP */
    {"WWW-Authenticate:", 17},	/* filtering violates HTTP */
    {"Link:", 5},
    {NULL, 0}
};

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
