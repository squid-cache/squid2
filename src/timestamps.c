
/*
 * $Id$
 *
 * DEBUG: section 22    Timestamp Calculations
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#include "squid.h"


void
timestampsSet(StoreEntry * entry)
{
    time_t x = 0;
    time_t last_modified = -1;
    time_t expires = -1;
    time_t their_date = -1;
    time_t served_date = -1;
    struct _http_reply *reply = entry->mem_obj->reply;
    /* these are case-insensitive compares */
    if (reply->last_modified[0]) {
	if ((x = parse_rfc1123(reply->last_modified)) > -1)
	    last_modified = x;
    }
    if (reply->date[0]) {
	if ((x = parse_rfc1123(reply->date)) > -1)
	    their_date = x;
    }
    served_date = their_date > -1 ? their_date : squid_curtime;
    if (reply->expires[0]) {
	/*
	 * The HTTP/1.0 specs says that robust implementations should
	 * consider bad or malformed Expires header as equivalent to
	 * "expires immediately."
	 */
	expires = ((x = parse_rfc1123(reply->expires)) > -1) ? x : served_date;
    }
    entry->expires = expires;
    entry->lastmod = last_modified > -1 ? last_modified : served_date;
    entry->timestamp = served_date;
}
