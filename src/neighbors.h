
/* 
 *  $Id$
 *
 *  File:         neighbors.h
 *  Description:  
 *  Author:       Peter Danzig, USC
 *  Created:      May 1994
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#ifndef NEIGHBORS_H
#define NEIGHBORS_H

#define isNeighbor( X ) (((X).type==is_a_neighbor))
#define isParent( X )   ((X).type==is_a_parent)

/* Labels for hierachical log file */
/* put them all here for easier reference when writing a logfile analyzer */

typedef enum {
    HIER_NONE,
    HIER_DIRECT,
    HIER_NEIGHBOR_HIT,
    HIER_PARENT_HIT,
    HIER_SINGLE_PARENT,
    HIER_NO_PARENT_DIRECT,
    HIER_FIRST_PARENT_MISS,
    HIER_LOCAL_IP_DIRECT,
    HIER_DEAD_PARENT,
    HIER_DEAD_NEIGHBOR,
    HIER_REVIVE_PARENT,
    HIER_REVIVE_NEIGHBOR,
    HIER_NO_DIRECT_FAIL,
    HIER_SOURCE_FASTEST,
    HIER_MAX
} hier_code;


/* Mark a neighbor cache as dead if it doesn't answer this many pings */
#define HIER_MAX_DEFICIT  20

typedef struct _dom_list {
    char *domain;
    int do_ping;		/* boolean */
    struct _dom_list *next;
} dom_list;

#define EDGE_MAX_ADDRESSES 10
typedef struct _edge {
    char *host;
    struct sockaddr_in in_addr;
    int rtt;
    int ack_deficit;
    enum {
	is_a_neighbor = 0, is_a_parent = 1
    } type;			/* 0 if neighbor, 1 if parent */

    int num_pings;
    int pings_sent;
    int pings_acked;
    int neighbor_up;		/* 0 if no, 1 if yes */
    int hits;
    int misses;

    int udp_port;
    int ascii_port;
    icp_common_t header;
    dom_list *domains;
    int proxy_only;
    time_t last_fail_time;	/* detect down dumb caches */
    struct in_addr addresses[10];
    int n_addresses;
    struct _edge *next;
} edge;

typedef struct {
    int n;
    int n_parent;
    int n_neighbor;
    edge *edges_head;
    edge *edges_tail;
    edge *first_ping;
    int fd;
} neighbors;

struct neighbor_cf {
    char *host;
    char *type;
    int ascii_port;
    int udp_port;
    int proxy_only;
    dom_list *domains;
    struct neighbor_cf *next;
};

extern edge *getSingleParent _PARAMS((char *host, int *n));
extern edge *getFirstParent _PARAMS((char *host));
extern void hierarchy_log_append _PARAMS((char *, hier_code, int, char *));
extern edge *getFirstEdge _PARAMS((void));
extern edge *getNextEdge _PARAMS((edge *));
extern int neighborsUdpPing _PARAMS((protodispatch_data *));
extern neighbors *neighbors_create _PARAMS(());
extern void neighbors_init _PARAMS((void));
extern void neighbors_open _PARAMS((int));

#endif
