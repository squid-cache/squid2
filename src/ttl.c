/*
 * $Id$
 *
 * DEBUG: section 22	TTL Calculation
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
 
#ifdef HARVEST_COPYRIGHT
Copyright (c) 1994, 1995.  All rights reserved.
 
  The Harvest software was developed by the Internet Research Task
  Force Research Group on Resource Discovery (IRTF-RD):
 
        Mic Bowman of Transarc Corporation.
        Peter Danzig of the University of Southern California.
        Darren R. Hardy of the University of Colorado at Boulder.
        Udi Manber of the University of Arizona.
        Michael F. Schwartz of the University of Colorado at Boulder.
        Duane Wessels of the University of Colorado at Boulder.
 
  This copyright notice applies to software in the Harvest
  ``src/'' directory only.  Users should consult the individual
  copyright notices in the ``components/'' subdirectories for
  copyright information about other software bundled with the
  Harvest source code distribution.
 
TERMS OF USE
  
  The Harvest software may be used and re-distributed without
  charge, provided that the software origin and research team are
  cited in any use of the system.  Most commonly this is
  accomplished by including a link to the Harvest Home Page
  (http://harvest.cs.colorado.edu/) from the query page of any
  Broker you deploy, as well as in the query result pages.  These
  links are generated automatically by the standard Broker
  software distribution.
  
  The Harvest software is provided ``as is'', without express or
  implied warranty, and with no support nor obligation to assist
  in its use, correction, modification or enhancement.  We assume
  no liability with respect to the infringement of copyrights,
  trade secrets, or any patents, and are not responsible for
  consequential damages.  Proper use of the Harvest software is
  entirely the responsibility of the user.
 
DERIVATIVE WORKS
 
  Users may make derivative works from the Harvest software, subject 
  to the following constraints:
 
    - You must include the above copyright notice and these 
      accompanying paragraphs in all forms of derivative works, 
      and any documentation and other materials related to such 
      distribution and use acknowledge that the software was 
      developed at the above institutions.
 
    - You must notify IRTF-RD regarding your distribution of 
      the derivative work.
 
    - You must clearly notify users that your are distributing 
      a modified version and not the original Harvest software.
 
    - Any derivative product is also subject to these copyright 
      and use restrictions.
 
  Note that the Harvest software is NOT in the public domain.  We
  retain copyright, as specified above.
 
HISTORY OF FREE SOFTWARE STATUS
 
  Originally we required sites to license the software in cases
  where they were going to build commercial products/services
  around Harvest.  In June 1995 we changed this policy.  We now
  allow people to use the core Harvest software (the code found in
  the Harvest ``src/'' directory) for free.  We made this change
  in the interest of encouraging the widest possible deployment of
  the technology.  The Harvest software is really a reference
  implementation of a set of protocols and formats, some of which
  we intend to standardize.  We encourage commercial
  re-implementations of code complying to this set of standards.  
#endif


#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"

#define DEFAULT_AGE_PERCENT 0.20

typedef struct _ttl_t {
    char *pattern;
    regex_t compiled_pattern;
    time_t abs_ttl;
    int pct_age;
    time_t age_max;
    time_t pct_max;
    struct _ttl_t *next;
} ttl_t;

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
	debug(22, 0, "ttlAddToList: Invalid regular expression: %s\n",
	    pattern);
	return;
    }
    pct_age = pct_age < 0 ? 0 : pct_age > 100 ? 100 : pct_age;
    age_max = age_max < 0 ? 0 : age_max;

    t = xcalloc(1, sizeof(ttl_t));
    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->abs_ttl = abs_ttl;
    t->pct_age = pct_age;
    t->age_max = age_max;
    t->next = NULL;

    if (!TTL_tbl)
	TTL_tbl = t;
    if (TTL_tail)
	TTL_tail->next = t;
    TTL_tail = t;
}



time_t ttlSet(entry)
     StoreEntry *entry;
{
    time_t last_modified = -1;
    time_t expire = -1;
    time_t their_date = -1;
    time_t x = 0;
    time_t now = 0;
    time_t ttl = 0;
    time_t default_ttl = 0;
    ttl_t *t = NULL;
    ttl_t *match = NULL;
    double d;
    int flags = 0;
    struct _http_reply *reply = NULL;
    request_t *request = NULL;

    debug(22, 5, "ttlSet: Choosing TTL for %s\n", entry->url);

    reply = entry->mem_obj->reply;
    request = entry->mem_obj->request;

    /* these are case-insensitive compares */
    if (reply->last_modified[0]) {
	if ((x = parse_rfc850(reply->last_modified)) > 0) {
	    last_modified = x;
	    flags |= TTL_LASTMOD;
	}
    }
    if (reply->date[0]) {
	if ((x = parse_rfc850(reply->date)) > 0) {
	    their_date = x;
	    flags |= TTL_SERVERDATE;
	}
    }
    now = their_date > 0 ? their_date : squid_curtime;

    if (reply->expires[0]) {
	/*
	 * The HTTP/1.0 specs says that robust implementations should
	 * consider bad or malformed Expires header as equivalent to
	 * "expires immediately."
	 */
	flags |= TTL_EXPIRES;
	expire = ((x = parse_rfc850(reply->expires)) > 0) ? x : now;
    }
    if (last_modified > 0)
	debug(22, 5, "ttlSet: Last-Modified: %s\n", mkrfc850(&last_modified));
    if (expire > 0)
	debug(22, 5, "ttlSet:       Expires: %s\n", mkrfc850(&expire));
    if (their_date > 0)
	debug(22, 5, "ttlSet:   Server-Date: %s\n", mkrfc850(&their_date));

    if (expire > 0) {
	ttl = (expire - now);
	if (ttl < 0)
	    ttl = 0;
	debug(22, 4, "ttlSet: [%c%c%c%c%c%c%c] %6.2lf days %s\n",
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
    if (request->protocol == PROTO_HTTP)
	default_ttl = getHttpTTL();
    else if (request->protocol == PROTO_FTP)
	default_ttl = getFtpTTL();
    else if (request->protocol == PROTO_GOPHER)
	default_ttl = getGopherTTL();

    match = NULL;
    for (t = TTL_tbl; t; t = t->next) {
	if (regexec(&(t->compiled_pattern), entry->url, 0, 0, 0) == 0) {
	    match = t;
	    debug(22, 5, "ttlSet: Matched '%s %d %d%%'\n",
		match->pattern, match->abs_ttl > 0 ? match->abs_ttl : default_ttl,
		match->pct_age);
	    flags |= TTL_MATCHED;
	}
    }

    /* Return a TTL that is a percent of the object's age if a last-mod
     * was given for the object. */

    if (match && match->pct_age && last_modified > 0) {
	d = (double) (now - last_modified) * match->pct_age / 100;
	ttl = (time_t) d;
	if (ttl > match->age_max)	/* place upper limit on */
	    ttl = match->age_max;	/* ttls set from %-of-age */
	flags |= TTL_PCTAGE;
    } else if (match && match->abs_ttl >= 0) {
	/* Return an absolute TTL value from a match (unless 
	 * 'abs_ttl' is negative). */
	ttl = match->abs_ttl;
	flags |= TTL_ABSOLUTE;
    } else if (!match && last_modified > 0) {
	/* No match, use 20% of age if we have last-modified.
	 * But limit this to the default TTL. */
	ttl = ((now - last_modified) * DEFAULT_AGE_PERCENT);
	flags |= TTL_PCTAGE;
	if (ttl > default_ttl)
	    ttl = default_ttl;
    } else {
	/* No last-modified, use the defaults */
	ttl = default_ttl;
	flags |= TTL_DEFAULT;
    }

    debug(22, 4, "ttlSet: [%c%c%c%c%c%c%c] %6.2lf days %s\n",
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
