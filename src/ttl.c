
/* $Id$ */

/*
 * DEBUG: Section 22          ttl
 */

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"


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

    debug(22, 5, "ttlSet: Choosing TTL for %s\n", entry->url);

    reply = entry->mem_obj->reply;

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
    now = their_date > 0 ? their_date : cached_curtime;

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
	    debug(22, 5, "ttlSet: Matched '%s %d %d%%'\n",
		match->pattern, match->abs_ttl > 0 ? match->abs_ttl : default_ttl,
		match->pct_age);
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
