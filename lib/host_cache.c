/*
 * $Id$
 *
 * DEBUG: 
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *   Squid is the result of efforts by numerous individuals from the
 *   Internet community.  Development is led by Duane Wessels of the
 *   National Laboratory for Applied Network Research and funded by
 *   the National Science Foundation.
 * 
 */
 
/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "config.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect NEXTSTEP */
#define _SQUID_NETDB_H_
#include <netdb.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "util.h"

#define HASHTABLE_N		511
#define HASHTABLE_M		  9

static Host HostTable[HASHTABLE_N];
static int hash_index _PARAMS((char *buf));

static int hash_index(buf)
     char *buf;
{
    static int n = HASHTABLE_N;
    static int m = HASHTABLE_M;
    int val = 0;
    char *s = NULL;

    for (s = buf; *s; s++)
	val += (int) (*s * m);
    val %= n;
    return val;
}

Host *get_host _PARAMS((char *hostname));
static void host_cache_init _PARAMS((void));
static Host *new_host _PARAMS((char *hostname));
static void Tolower _PARAMS((char *));
void dump_host_cache _PARAMS((int, int));
static int cache_inited = 0;

/* ========== PUBLIC FUNCTIONS ============================================= */

static void host_cache_init()
{
    memset(HostTable, '\0', HASHTABLE_N * sizeof(Host));
    cache_inited = 1;

    if (!get_host(getfullhostname())) {
	Log("Can't get my own host info!?\n");
	exit(1);
    }
    Debug(86, 1, ("host_cache: initialized\n"));
}

Host *get_host(hostname)
     char *hostname;
{
    static char hn[SQUIDHOSTNAMELEN];
    Host *h = 0;
    int idx;
    time_t now = time(0);

    if (hostname == (char *) 0)
	return NULL;

    Debug(86, 1, ("host_cache: get_host (%s)\n", hostname));

    if (!cache_inited)
	host_cache_init();

    strncpy(hn, hostname, SQUIDHOSTNAMELEN - 1);
    hn[SQUIDHOSTNAMELEN - 1] = 0;
    Tolower(hn);

    idx = hash_index(hn);
    Debug(86, 1, ("host_cache: hash index = %d\n", idx));
    if (!strcmp(HostTable[idx].key, hn))
	h = &HostTable[idx];

    if (!h)
	h = new_host(hostname);
    if (!h)
	return NULL;

    h->n++;
    h->last_t = now;

    return h;
}

static Host *new_host(hostname)
     char *hostname;
{
    Host *h = NULL;
    char *hn = NULL;
    static struct hostent *H = NULL;
    static struct in_addr ina;
    unsigned long ip;
    int idx;
    char x[64];

    Debug(86, 1, ("new_host: Adding %s\n", hostname));
    hn = xstrdup(hostname);
    if ((int) strlen(hn) > (SQUIDHOSTNAMELEN - 1))
	*(hn + SQUIDHOSTNAMELEN - 1) = 0;
    Tolower(hn);

    idx = hash_index(hn);
    h = &HostTable[idx];

    if (sscanf(hn, "%[0-9].%[0-9].%[0-9].%[0-9]%s", x, x, x, x, x) == 4) {
	ip = inet_addr(hn);
	Debug(86, 1, ("new_host: numeric address %s, trying gethostbyaddr()\n", hn));
	H = gethostbyaddr((char *) &ip, 4, AF_INET);
	if (!H) {		/* special hack for DNS's which don't work */
	    /* unknown if this works                   */
	    Debug(86, 1, ("new_host: gethostbyaddr() failed.  Trying hack.\n"));
	    memset(h, '\0', sizeof(Host));
	    strncpy(h->key, hn, SQUIDHOSTNAMELEN - 1);
	    strncpy(h->fqdn, hn, SQUIDHOSTNAMELEN - 1);
	    memcpy(h->ipaddr, &ip, h->addrlen = 4);
	    strcpy(h->dotaddr, hn);
	    xfree(hn);
	    return h;
	}
    } else {
	H = gethostbyname(hn);
	if (H == NULL)
	    Debug(86, 1, ("new_host: gethostbyname(%s) failed.\n", hn));
    }

    if (H == NULL) {
	Debug(86, 1, ("new_host: %s: unknown host\n", hn));
	xfree(hn);
	return 0;
    }
    memset(h, '\0', sizeof(Host));
    strncpy(h->key, hn, SQUIDHOSTNAMELEN - 1);
    strncpy(h->fqdn, H->h_name, SQUIDHOSTNAMELEN - 1);
    Tolower(h->fqdn);
    memcpy(h->ipaddr, *H->h_addr_list, h->addrlen = 4);
    memcpy(&ina.s_addr, *H->h_addr_list, 4);
    strcpy(h->dotaddr, inet_ntoa(ina));

    Debug(86, 1, ("new_host: successfully added host %s\n", h->key));
    Debug(86, 1, ("new_host:   FQDN=%s\n", h->fqdn));
    Debug(86, 1, ("new_host:     IP=%s\n", h->dotaddr));

    xfree(hn);
    return h;
}

#ifdef UNUSED_CODE
void dump_host_cache(d_sec, d_lvl)
     int d_sec;
     int d_lvl;
{
    int i;
    Host *h = NULL;

    Debug(d_sec, d_lvl, ("HostTable:\n"));
    for (i = 0; i < HASHTABLE_N; i++) {
	h = &HostTable[i];
	if (*h->fqdn) {
	    Debug(d_sec, d_lvl, ("key: %-30s = [%s] %s\n",
		    h->key, h->dotaddr, h->fqdn));
	}
    }
}
#endif /* UNUSED_CODE */


/* ========== MISC UTIL FUNCS ============================================== */

static void Tolower(q)
     char *q;
{
    char *s = q;
    while (*s) {
	*s = tolower((unsigned char) *s);
	s++;
    }
}
