/*
 * $Id$
 *
 *  File:         block.c
 *  Description:  Blacklisting specific URLs
 *  Author:       Duane Wessels, CU Boulder & Daniel O'Callaghan, U of Melbourne
 *  Created:      Fri Dec 15 1995
 *  Language:     C
 *
 * DEBUG: Section 2             blocklist
 */

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"

typedef struct _blocklist {
    char *pattern;
    regex_t compiled_pattern;
    struct _blocklist *next;
} blocklist;

static blocklist *BLOCK_tbl = NULL;
static blocklist *BLOCK_tail = NULL;

#define BLOCK_MATCHED 1

void blockAddToList(pattern)
     char *pattern;
{
    blocklist *t;
    regex_t comp;

    if (regcomp(&comp, pattern, REG_EXTENDED) != REG_NOERROR) {
	debug(2, 0, "blockAddToList: Invalid regular expression: %s\n",
	    pattern);
	return;
    }
    t = (blocklist *) xmalloc(sizeof(blocklist));
    memset((char *) t, '\0', sizeof(blocklist));

    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->next = (blocklist *) NULL;

    if (!BLOCK_tbl)
	BLOCK_tbl = t;
    if (BLOCK_tail)
	BLOCK_tail->next = t;
    BLOCK_tail = t;
}


int blockCheck(url)
     char *url;
{
    blocklist *t = NULL;
    blocklist *match = NULL;
    int flags = 0;

    debug(2, 5, "blockCheck: Checking blocklist for %s\n", url);

    for (t = BLOCK_tbl; t; t = t->next) {
	if (regexec(&(t->compiled_pattern), url, 0, 0, 0) == 0) {
	    match = t;
	    debug(2, 5, "blockCheck: Matched '%s'\n",
		match->pattern);
	    flags |= BLOCK_MATCHED;
	}
    }

    return flags;
}
