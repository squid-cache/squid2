
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

#ifndef PEER_SELECT_H
#define PEER_SELECT_H

typedef enum {
    HIER_NONE,
    HIER_DIRECT,
    HIER_SIBLING_HIT,
    HIER_PARENT_HIT,
    HIER_DEFAULT_PARENT,
    HIER_SINGLE_PARENT,
    HIER_FIRSTUP_PARENT,
    HIER_NO_PARENT_DIRECT,
    HIER_BEST_PARENT_MISS,
    HIER_NO_DIRECT_FAIL,
    HIER_SOURCE_FASTEST,
    HIER_SIBLING_UDP_HIT_OBJ,
    HIER_PARENT_UDP_HIT_OBJ,
    HIER_PASS_PARENT,
    HIER_SSL_PARENT,
    HIER_ROUNDROBIN_PARENT,
    HIER_MAX
} hier_code;

typedef void (*PSC) _PARAMS((peer *, void *));

typedef struct {
    struct timeval start;
    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;
    int w_rtt;
} icp_ping_data;

typedef struct {
    request_t *request;
    StoreEntry *entry;
    int always_direct;
    int never_direct;
    PSC callback;
    PSC fail_callback;
    void *callback_data;
    peer *best_parent;
    icp_ping_data icp;
} ps_state;


extern void peerSelect _PARAMS((request_t *, StoreEntry *, PSC, PSC, void *data));
extern int peerSelectDirect _PARAMS((request_t *));
extern peer *peerGetSomeParent _PARAMS((request_t *, hier_code *));
extern int matchInsideFirewall _PARAMS((const char *));
extern void peerSelectInit _PARAMS((void));

#endif /* PEER_SELECT_H */
