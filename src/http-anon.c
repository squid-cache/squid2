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
 *
 * This file contains an field of all header strings of HTTP which
 * should pass the proxy. Any other field is removed from the redirected
 * request to keep the sender anonymous.
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

struct http_anon_struct_header {
    const char *name;
    size_t len;
};

/* list of allowed headers */
const struct http_anon_struct_header http_anon_allowed_header[] =
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
    {NULL, 0}
};

/* list of headers known to definitly compromise privacy */
const struct http_anon_struct_header http_anon_denied_header[] =
{
    {"From:", 5},
    {"Referer:", 8},
    {"Server:", 7},
    {"User-Agent:", 11},	/* filtering violates HTTP */
    {"WWW-Authenticate:", 17},	/* filtering violates HTTP */
    {"Link:", 5},
    {NULL, 0}
};

/* any other header is undefined by HTTP 1.0 and droped */
static const char *
httpAnonSearchHeaderField(const struct http_anon_struct_header *header_field,
    const char *line)
{
    const struct http_anon_struct_header *ppc;
    if (*line == '\0')
	return line;
    for (ppc = header_field; ppc->len; ppc++) {
	if (strncasecmp(line, ppc->name, ppc->len) == 0)
#ifdef USE_PARANOID_ANONYMIZER
	    return ppc->name;
    }
    return NULL;
#else
	    return NULL;
    }
    return line;
#endif
}
