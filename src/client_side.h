
/*
 * $Id$
 *
 * AUTHOR: Duane Wessels
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

#ifndef CLIENT_SIDE_H
#define CLIENT_SIDE_H

extern void clientAccessCheck(icpStateData *, void (*)_PARAMS((icpStateData *, int)));
extern void clientAccessCheckDone _PARAMS((icpStateData *, int answer));
extern void icpProcessExpired _PARAMS((int fd, void *));
extern int modifiedSince _PARAMS((StoreEntry *, request_t *));
extern char *clientConstructTraceEcho _PARAMS((icpStateData *));
extern void clientPurgeRequest _PARAMS((icpStateData *));

#if USE_PROXY_AUTH
const char *proxyAuthenticate(const char *headers);
#endif /* USE_PROXY_AUTH */

#endif /* CLIENT_SIDE_H */
