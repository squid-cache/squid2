/* $Id$ */

#include <stdlib.h>
#include <string.h>
#define MAIN
#include "util.h"

int Harvest_debug_levels[MAX_DEBUG_LEVELS];
int Harvest_do_debug = 0;

/*
 *  debug_reset() - Reset debugging routines.
 */
void debug_reset()
{
    int i;

    for (i = 0; i < MAX_DEBUG_LEVELS; i++)
	Harvest_debug_levels[i] = -1;
    Harvest_do_debug = 0;
}

/*
 *  debug_enable() - Enables debugging output for section s, level l.
 */
void debug_enable(s, l)
     int s, l;
{
#ifdef USE_NO_DEBUGGING
    return;
#else
    if (s > MAX_DEBUG_LEVELS || s < 0)
	return;
    Harvest_debug_levels[s] = l;
    Harvest_do_debug = 1;
    Log("Enabling debugging for Section %d, level %d.\n", s, l == -2 ? 99 : l);
#endif
}
/*
 *  debug_disable() - Disables debugging output for section s, level l.
 */
void debug_disable(s)
     int s;
{
    if (s > MAX_DEBUG_LEVELS || s < 0)
	return;
    Log("Disabling debugging for Section %d.\n", s);
    Harvest_debug_levels[s] = -1;
}

/*
 *  debug_ok() - Returns non-zero if the caller is debugging the
 *  given section and level.  If level is -2, then all debugging is used.
 *  In general, level 1 should be minimal and level 9 the max.
 */
int debug_ok(s, lev)
     int s, lev;
{
#ifdef USE_NO_DEBUGGING
    return 0;
#else
    /* totally disabled */
    if (Harvest_do_debug == 0)
	return 0;
    /* section out of range */
    if (s < 0 || s > MAX_DEBUG_LEVELS)
	return 0;
    /* -1 means disabled for that section */
    if (Harvest_debug_levels[s] == -1)
	return 0;
    /* -2 means fully enabled for that section */
    if (Harvest_debug_levels[s] == -2)
	return 1;
    /* enabled if lev is less than or equal to section level */
    if (lev <= Harvest_debug_levels[s])
	return 1;
    return 0;
#endif
}

/*
 *  debug_flag() - Processes a -D flag and runs debug_enable()
 *  Flags are of the form:
 *      -Ds     Enable debugging for section s
 *      -D-s    Disable debugging for section s
 *      -Ds,l   Enable debugging for section s, level l
 *      -DALL   Everything enabled
 */
void debug_flag(flag)
     char *flag;
{
    int s = -1, l = -2, i;
    char *p;

    if (flag == NULL || strncmp(flag, "-D", 2) != 0)
	return;

    if (!strcmp(flag, "-DALL")) {
	for (i = 0; i < MAX_DEBUG_LEVELS; i++) {
	    debug_enable(i, -2);
	}
	return;
    }
    p = flag;
    p += 2;			/* skip -D */

    s = atoi(p);
    while (*p && *p != ',')
	p++;
    if (*p)
	l = atoi(++p);
    if (s < 0)
	debug_disable(-s);
    else
	debug_enable(s, l);
}

/*
 *  debug_init() - Initializes debugging from $SQUID_DEBUG variable
 *
 */
void debug_init()
{
    char *s, *t, *u;

    s = getenv("SQUID_DEBUG");
    if (s == (char *) 0)
	return;

    t = xstrdup(s);

    u = strtok(t, " \t\n");
    do {
	debug_flag(u);
    } while ((u = strtok((char *) 0, " \t\n")) != (char *) NULL);
    xfree(t);
}
