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

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#define MAIN
#include "util.h"

static void debug_enable _PARAMS((int, int));
static void debug_disable _PARAMS((int));

int Harvest_debug_levels[MAX_DEBUG_LEVELS];
int Harvest_do_debug = 0;

#ifdef UNUSED_CODE
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
#endif /* UNUSED_CODE */

/*
 *  debug_enable() - Enables debugging output for section s, level l.
 */
static void debug_enable(s, l)
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

#ifdef UNUSED_CODE
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
#endif /* UNUSED_CODE */

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
    } while ((u = strtok((char *) 0, " \t\n")) != NULL);
    xfree(t);
}
