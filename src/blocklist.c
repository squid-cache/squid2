/*
 * $Id$
 *
 *  File:         block.c
 *  Description:  Blacklisting specific URLs
 *  Author:       Duane Wessels, CU Boulder & Daniel O'Callaghan, U of Melbourne
 *  Created:      Fri Dec 15 1995
 *  Language:     C
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
#include "store.h"
#include "cache_cf.h"
#include "util.h"

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
	debug(0, "blockAddToList: Invalid regular expression: %s\n",
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
    char buf[301];
    blocklist *t;
    blocklist *match;
    double d;
    int flags = 0;

    debug(5, "blockCheck: Checking blocklist for %s\n", url);

    match = (blocklist *) NULL;
    for (t = BLOCK_tbl; t; t = t->next) {
	if (regexec(&(t->compiled_pattern), url, 0, 0, 0) == 0) {
	    match = t;
	    debug(5, "blockCheck: Matched '%s'\n",
		match->pattern);
	    flags |= BLOCK_MATCHED;
	}
    }

    return flags;
}
