static char rcsid[] = "$Id$";
/*
 *  File:         ttl.c
 *  Description:  TTL calculations for cached objects
 *  Author:       Duane Wessels, CU Boulder
 *  Created:      Mon Jul 31 1995
 *  Language:     C
 *
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

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <memory.h>

#include "autoconf.h"
#include "GNUregex.h"
#include "debug.h"
#include "cache_cf.h"
#include "comm.h"
#include "store.h"
#include "util.h"

typedef struct _ttl_t {
    char *pattern;
    regex_t compiled_pattern;
    time_t abs_ttl;
    int pct_age;
    time_t age_max;
    time_t pct_max;
    struct _ttl_t *next;
} ttl_t;

extern time_t cached_curtime;
extern time_t parse_rfc850 _PARAMS((char *str));
extern char *mkrfc850 _PARAMS((time_t * t));

static ttl_t *TTL_tbl = NULL;
static ttl_t *TTL_tail = NULL;

#define TTL_EXPIRES	0x01
#define TTL_SERVERDATE	0x02
#define TTL_LASTMOD	0x04
#define TTL_MATCHED	0x08
#define TTL_PCTAGE	0x10
#define TTL_ABSOLUTE	0x20
#define TTL_DEFAULT	0x40

void ttlAddToList(pattern, abs_ttl, pct_age, age_max)
     char *pattern;
     time_t abs_ttl;
     int pct_age;
     time_t age_max;
{
    ttl_t *t;
    regex_t comp;

    if (regcomp(&comp, pattern, REG_EXTENDED) != REG_NOERROR) {
	debug(0, "ttlAddToList: Invalid regular expression: %s\n",
	    pattern);
	return;
    }
    pct_age = pct_age < 0 ? 0 : pct_age > 100 ? 100 : pct_age;
    age_max = age_max < 0 ? 0 : age_max;

    t = (ttl_t *) xmalloc(sizeof(ttl_t));
    memset((char *) t, '\0', sizeof(ttl_t));

    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->abs_ttl = abs_ttl;
    t->pct_age = pct_age;
    t->age_max = age_max;
    t->next = (ttl_t *) NULL;

    if (!TTL_tbl)
	TTL_tbl = t;
    if (TTL_tail)
	TTL_tail->next = t;
    TTL_tail = t;
}



time_t ttlSet(entry)
     StoreEntry *entry;
{
    char buf[301];
    time_t last_modified = -1;
    time_t expire = -1;
    time_t their_date = -1;
    time_t x = 0;
    time_t now = 0;
    time_t ttl = 0;
    time_t default_ttl = 0;
    ttl_t *t;
    ttl_t *match;
    double d;
    int flags = 0;

    debug(5, "ttlSet: Choosing TTL for %s\n", entry->url);

    /*
     * Check for Unauthorized HTTP requests.
     * This needs to be improved.  I don't think we can/should rely on
     * a server sending the string 'Unauthorized'.  Would be nice if
     * we could write 'if (http_code == 401)' in http.c.       -DW
     */
    if (storeGrep(entry, "401", 15))	/* Unauthorized */
	return 0;
    if (storeGrep(entry, "407", 15))	/* NS: Proxy Authentication Required */
	return 0;

    /* these are case-insensitive compares */
    buf[0] = '\0';
    if (storeMatchMime(entry, "last-modified: ", buf, 300)) {
	if ((x = parse_rfc850(buf)) > 0) {
	    last_modified = x;
	    flags |= TTL_LASTMOD;
	}
    }
    buf[0] = '\0';
    if (storeMatchMime(entry, "date: ", buf, 300)) {
	if ((x = parse_rfc850(buf)) > 0) {
	    their_date = x;
	    flags |= TTL_SERVERDATE;
	}
    }
    buf[0] = '\0';
    if (storeMatchMime(entry, "expires: ", buf, 300)) {
	if ((x = parse_rfc850(buf)) > 0) {
	    expire = x;
	    flags |= TTL_EXPIRES;
	}
    }
    if (last_modified > 0)
	debug(5, "ttlSet: Last-Modified: %s\n", mkrfc850(&last_modified));
    if (expire > 0)
	debug(5, "ttlSet:       Expires: %s\n", mkrfc850(&expire));
    if (their_date > 0)
	debug(5, "ttlSet:   Server-Date: %s\n", mkrfc850(&their_date));

    now = their_date > 0 ? their_date : cached_curtime;

    if (expire > 0) {
	ttl = (expire - now);
	if (ttl < 0)
	    ttl = 0;
	debug(4, "ttlSet: [%c%c%c%c%c%c%c] %6.2lf days %s\n",
	    flags & TTL_EXPIRES ? 'E' : '.',
	    flags & TTL_SERVERDATE ? 'S' : '.',
	    flags & TTL_LASTMOD ? 'L' : '.',
	    flags & TTL_MATCHED ? 'M' : '.',
	    flags & TTL_PCTAGE ? 'P' : '.',
	    flags & TTL_ABSOLUTE ? 'A' : '.',
	    flags & TTL_DEFAULT ? 'D' : '.',
	    (double) ttl / 86400, entry->url);
	return ttl;
    }
    /*
     * ** Calculate default TTL for later use
     */
    if (!strncmp(entry->url, "http:", 5))
	default_ttl = getHttpTTL();
    else if (!strncmp(entry->url, "ftp:", 4))
	default_ttl = getFtpTTL();
    else if (!strncmp(entry->url, "gopher:", 7))
	default_ttl = getGopherTTL();

    match = (ttl_t *) NULL;
    for (t = TTL_tbl; t; t = t->next) {
	if (regexec(&(t->compiled_pattern), entry->url, 0, 0, 0) == 0) {
	    match = t;
	    debug(5, "ttlSet: Matched '%s %d %d%%'\n",
		match->pattern, match->abs_ttl, match->pct_age);
	    flags |= TTL_MATCHED;
	}
    }

    /*       Return a TTL that is a percent of the object's age     */
    /*       if a last-mod was given for the object.                */

    if (match && match->pct_age && last_modified > 0) {
	d = (double) (now - last_modified) * match->pct_age / 100;
	ttl = (time_t) d;
	if (ttl > match->age_max)	/* place upper limit on           */
	    ttl = match->age_max;	/* ttls set from %-of-age       */
	flags |= TTL_PCTAGE;
    } else
	/*      Return an absolute TTL value from a match (unless       */
	/*      'abs_ttl' is negative).                                 */
    if (match && match->abs_ttl >= 0) {
	ttl = match->abs_ttl;
	flags |= TTL_ABSOLUTE;
    } else
	/*      No match, use 50% of age if we have last-modified.      */
	/*      But limit this to the default TTL.                      */
    if (last_modified > 0) {
	ttl = ((now - last_modified) / 2);
	flags |= TTL_PCTAGE;
	if (ttl > default_ttl)
	    ttl = default_ttl;
    } else
	/*      No last-modified, use the defaults                      */
    {
	ttl = default_ttl;
	flags |= TTL_DEFAULT;
    }

    debug(4, "ttlSet: [%c%c%c%c%c%c%c] %6.2lf days %s\n",
	flags & TTL_EXPIRES ? 'E' : '.',
	flags & TTL_SERVERDATE ? 'S' : '.',
	flags & TTL_LASTMOD ? 'L' : '.',
	flags & TTL_MATCHED ? 'M' : '.',
	flags & TTL_PCTAGE ? 'P' : '.',
	flags & TTL_ABSOLUTE ? 'A' : '.',
	flags & TTL_DEFAULT ? 'D' : '.',
	(double) ttl / 86400, entry->url);

    return ttl;
}
