/*
 * $Id$
 *
 * DEBUG: section 49     SNMP Interface
 * AUTHOR: Kostas Anagnostakis
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/***********************************************************
        Copyright 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/



#include "squid.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <ctype.h>
#ifdef linux
#include <string.h>
#include <stdlib.h>
#endif

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"

#define USEC_QOS_AUTH 4
#define USEC_QOS_PRIV 5
int maintenanceView = 0;

static int linenumber = 0;

/* fwd: */
/* from usec.c: */

char *
gettoken(tokenptr)
     char **tokenptr;
{
    char *p = *tokenptr;
    char *tp;
    char ch;

    while ((ch = *p) != '\0' && isspace(ch))
	p++;
    tp = p;
    while ((ch = *p) != '\0' && !isspace(ch))
	p++;
    if (*p)
	*p++ = '\0';
    *tokenptr = p;
    return tp;
}


void
snmpTokenize(char *line, char **tokens, int max_tokens)
{
    int i;
    char *tokenptr;

    tokenptr = line;
    for (i = 0; i < max_tokens; i++) {
	tokens[i] = gettoken(&tokenptr);
	if (tokens[i][0] == '\0')
	    break;
    }
    for (; i < max_tokens; i++)
	tokens[i] = "";
}

int
snmpCreateView(tokens)
     char *tokens[];
{
    static int nextview = 1;
    viewEntry *vp;
    viewEntry *new, *prev = 0;

    if (tokens[3][0] == 0 || tokens[4][0] != 0) {
	debug(49, 0) ("snmpCreateView: bad view line, line %d\n", linenumber);
	return -1;
    }
    if (strlen(tokens[1]) > (sizeof(vp->viewName) - 1)) {
	debug(49, 0) ("snmpCreateView:view name too long, line %d\n", linenumber);
	return -1;
    }
    for (vp = Config.Snmp.views; vp; prev = vp, vp = vp->next) {
	if (strcmp(tokens[1], vp->viewName) == 0)
	    break;
    }

    new = (viewEntry *) xcalloc(1, sizeof(viewEntry));
    memset(new, '\0', sizeof(viewEntry));

    xstrncpy(new->viewName, tokens[1], 32);
    new->viewIndex = vp ? vp->viewIndex : nextview++;
    new->viewType = strcmp(tokens[3], "included") ? VIEWEXCLUDED : VIEWINCLUDED;

    new->viewSubtreeLen = sizeof(vp->viewSubtree) / sizeof(oid);
    read_objid(tokens[2], new->viewSubtree, &new->viewSubtreeLen);
    if (Config.Snmp.views) {
	for (; vp; prev = vp, vp = vp->next);
	prev->next = new;
    } else {
	Config.Snmp.views = new;
    }

    return new->viewIndex;
}

static int
find_view(name)
     char *name;
{
    viewEntry *vp;
    viewEntry *views = Config.Snmp.views;

    if (strcmp(name, "-") == 0)
	return 0;

    for (vp = views; vp; vp = vp->next) {
	if (strcmp(vp->viewName, name) == 0)
	    return vp->viewIndex;
    }
    return -1;
}

int
snmpCreateUser(tokens)
     char *tokens[];
{
    usecEntry *up;
    usecEntry *new, *prev = 0;
    char *start, *cp;
    int ch;
    int i;

    if (tokens[5][0] == 0 || tokens[6][0] != 0) {
	debug(49, 0) ("snmpCreateUser: bad user line, line %d\n", linenumber);
	return -1;
    }
    if (strlen(tokens[1]) > (sizeof(up->userName) - 1)) {
	debug(49, 0) ("snmpCreateUser: user name too long, line %d\n", linenumber);
	return -1;
    }
    for (up = Config.Snmp.users; up; prev = up, up = up->next) {
	if (strcmp(tokens[1], (char *) up->userName) == 0)
	    break;
    }

    if (up) {
	debug(49, 0) ("snmpCreateUser: user '%s' already defined\n", tokens[1]);
	return -1;
    }
    new = (usecEntry *) xcalloc(1, sizeof(usecEntry));
    if (Config.Snmp.users) {
	prev->next = new;
    } else {
	Config.Snmp.users = new;
    }

    memset(new, 0, sizeof(usecEntry));
    new->noauthReadView = find_view(tokens[1]);
    new->noauthWriteView = find_view(tokens[2]);
    new->authReadView = find_view(tokens[3]);
    new->authWriteView = find_view(tokens[4]);
    if (new->noauthReadView < 0 || new->noauthWriteView < 0
	|| new->authReadView < 0 || new->authWriteView < 0) {
	debug(49, 0) ("snmpCreateUser: unknown view name referenced, line %d\n", linenumber);
	return -1;
    }
    start = cp = tokens[5];
    while (*cp && *cp != '/')
	cp++;
    new->userLen = cp - start;
    strncpy((char *) new->userName, start, cp - start);

    if (new->userLen == 0) {
	debug(49, 0) ("snmpCreateUser: user name invalid, line %d\n", linenumber);
	return -1;
    }
    /* look for authKey */
    if (*cp != '/')
	return 0;
    cp++;

    start = cp;
    while (*cp && *cp != '/')
	cp++;
    if ((cp - start > 2) && (strncmp(start, "0x", 2) == 0)) {
	if (cp - start != 34) {
	    debug(49, 0) ("snmpCreateUser: auth key not 16 octets\n");
	    return -1;
	}
	start += 2;
	for (i = 0; i < 16; i++) {
	    if (sscanf(start, "%2x", &ch) != 1) {
		debug(49, 0) ("snmpCreateUser: auth key contains non hex digits\n");
		return -1;
	    }
	    start += 2;
	    new->authKey[i] = ch;
	}
	new->qoS |= USEC_QOS_AUTH;
    } else if (cp - start > 0) {
	new->qoS |= USEC_QOS_AUTH;
    }
    /* look for privKey */
    if (*cp != '/')
	return 0;
    cp++;

    start = cp;
    while (*cp && *cp != '/')
	cp++;
    if ((cp - start > 2) && (strncmp(start, "0x", 2) == 0)) {
	if (cp - start != 34) {
	    debug(49, 0) ("snmpCreateUser: priv key not 16 octets\n");
	    return -1;
	}
	start += 2;
	for (i = 0; i < 16; i++) {
	    if (sscanf(start, "%2x", &ch) != 1) {
		debug(49, 0) ("snmpCreateUser: priv key contains non hex digits\n");
		return -1;
	    }
	    new->privKey[i] = ch;
	    start += 2;
	}
	new->qoS |= USEC_QOS_PRIV;
    } else if (cp - start > 0) {
	new->qoS |= USEC_QOS_PRIV;
    }
    return 0;
}

int
snmpCreateCommunity(char **tokens)
{
    communityEntry *cp;
    communityEntry *new, *prev = 0;
    if (tokens[3][0] == 0 || tokens[4][0] != 0) {
	debug(49, 5) ("snmpCreateCommunity: bad community line, line %d\n", linenumber);
	return -1;
    }
    if (strlen(tokens[1]) > (sizeof(cp->name) - 1)) {
	debug(49, 5) ("snmpCreateCommunity: community name too long, line %d\n",
	    linenumber);
	return -1;
    }
    for (cp = Config.Snmp.communities; cp; prev = cp, cp = cp->next) {
	if (strcmp(tokens[1], cp->name) == 0)
	    break;
    }

    if (cp) {
	debug(49, 0) ("snmpCreateCommunity: community '%s' already defined\n",
	    tokens[1]);
	return -1;
    }
    debug(49, 5) ("snmpCreateCommunity: Adding %s\n", tokens[1]);
    new = (communityEntry *) xcalloc(1, sizeof(communityEntry));
    memset(new, 0, sizeof(communityEntry));
    xstrncpy(new->name, tokens[1], 32);
    new->readView = find_view(tokens[2]);
    new->writeView = find_view(tokens[3]);
    if (new->readView < 0 || new->writeView < 0) {
	debug(49, 0) ("snmpCreateCommunity: unknown view name referenced, line %d\n",
	    linenumber);
	return -1;
    }
    if (Config.Snmp.communities) {
	prev->next = new;
    } else {
	Config.Snmp.communities = new;
    }
    return 0;
}

int
snmpDefaultAuth()
{
    char *tokens[10];
    char *t;
    t = xstrdup("view $$INTERNAL$$ .1.3.6.1.6.3.6.1 included");
    snmpTokenize(t, tokens, 10);
    maintenanceView = snmpCreateView(tokens);
    xfree(t);
    t = xstrdup("view $$INTERNAL$$ .1.3.6.1.6.3.1.1.1 included");
    snmpTokenize(t, tokens, 10);
    snmpCreateView(tokens);
    xfree(t);
    return 0;
}
