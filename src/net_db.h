
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

#ifndef NET_DB_H
#define NET_DB_H

typedef struct _net_db_name {
    char *name;
    struct _net_db_name *next;
} net_db_name;

typedef struct _net_db_peer {
    char *peername;
    double hops;
    double rtt;
    time_t expires;
} net_db_peer;

typedef struct _net_db {
    char *key;
    struct _net_db *next;
    char network[16];
    int pings_sent;
    int pings_recv;
    double hops;
    double rtt;
    time_t next_ping_time;
    time_t last_use_time;
    int link_count;
    net_db_name *hosts;
    net_db_peer *peers;
    int n_peers_alloc;
    int n_peers;
} netdbEntry;

extern void netdbHandlePingReply _PARAMS((const struct sockaddr_in * from, int hops, int rtt));
extern void netdbPingSite _PARAMS((const char *hostname));
extern void netdbInit _PARAMS((void));
extern void netdbDump _PARAMS((StoreEntry *));
extern int netdbHops _PARAMS((struct in_addr));
extern void netdbFreeMemory _PARAMS((void));
extern int netdbHostHops _PARAMS((const char *host));
extern int netdbHostRtt _PARAMS((const char *host));
extern void netdbUpdatePeer _PARAMS((request_t *, peer * e, int rtt, int hops));
extern void netdbDeleteAddrNetwork _PARAMS((struct in_addr));

#endif /* NET_DB_H */
