static char rcsid[] = "$Id$";
/*
 *  host_cache.c - An IP/DNS cache to avoid frequent gethostbyname() calls
 * 
 *  DEBUG: section  86, level 1         Common utilities DNS host cache
 *
 *  Duane Wessels, wessels@cs.colorado.edu,  March 1995
 *
 *  ----------------------------------------------------------------------
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
 */

#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#include "util.h"

#define HASHTABLE_N		511
#define HASHTABLE_M		  9

static Host HostTable[HASHTABLE_N];

static int hash_index(buf)
     char *buf;
{
    static int n = HASHTABLE_N;
    static int m = HASHTABLE_M;
    register int val = 0;
    register char *s;

    for (s = buf; *s; s++)
	val += (int) (*s * m);
    val %= n;
    return val;
}

Host *get_host _PARAMS((char *hostname));
void host_cache_init _PARAMS((void));
static Host *new_host _PARAMS((char *hostname));
static void Tolower _PARAMS((char *));
void dump_host_cache _PARAMS((int, int));
static int cache_inited = 0;

/* ========== PUBLIC FUNCTIONS ============================================= */

void host_cache_init()
{
    char *getfullhostname();

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
    static char hn[HARVESTHOSTNAMELEN];
    Host *h = 0;
    int idx;
    time_t now = time(0);

    if (hostname == (char *) 0)
	return 0;

    Debug(86, 1, ("host_cache: get_host (%s)\n", hostname));

    if (!cache_inited)
	host_cache_init();

    strncpy(hn, hostname, HARVESTHOSTNAMELEN - 1);
    hn[HARVESTHOSTNAMELEN - 1] = 0;
    Tolower(hn);

    idx = hash_index(hn);
    Debug(86, 1, ("host_cache: hash index = %d\n", idx));
    if (!strcmp(HostTable[idx].key, hn))
	h = &HostTable[idx];

    if (!h)
	h = new_host(hostname);
    if (!h)
	return 0;

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
    if ((int) strlen(hn) > (HARVESTHOSTNAMELEN - 1))
	*(hn + HARVESTHOSTNAMELEN - 1) = 0;
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
	    strncpy(h->key, hn, HARVESTHOSTNAMELEN - 1);
	    strncpy(h->fqdn, hn, HARVESTHOSTNAMELEN - 1);
	    memcpy(h->ipaddr, &ip, h->addrlen = 4);
	    strcpy(h->dotaddr, hn);
	    xfree(hn);
	    return h;
	}
    } else {
	H = gethostbyname(hn);
	if (H == (struct hostent *) NULL)
	    Debug(86, 1, ("new_host: gethostbyname(%s) failed.\n", hn));
    }

    if (H == (struct hostent *) NULL) {
	Debug(86, 1, ("new_host: %s: unknown host\n", hn));
	xfree(hn);
	return 0;
    }
    memset(h, '\0', sizeof(Host));
    strncpy(h->key, hn, HARVESTHOSTNAMELEN - 1);
    strncpy(h->fqdn, H->h_name, HARVESTHOSTNAMELEN - 1);
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

void dump_host_cache(d_sec, d_lvl)
{
    int i;
    Host *h;

    Debug(d_sec, d_lvl, ("HostTable:\n"));
    for (i = 0; i < HASHTABLE_N; i++) {
	h = &HostTable[i];
	if (*h->fqdn) {
	    Debug(d_sec, d_lvl, ("key: %-30s = [%s] %s\n",
		    h->key, h->dotaddr, h->fqdn));
	}
    }
}


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
