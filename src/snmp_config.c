#include "squid.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <ctype.h>
#ifdef linux
#include <string.h>
#include <stdlib.h>
#endif

#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define USEC_QOS_AUTH 4
#define USEC_QOS_PRIV 5
int maintenanceView = 0;

static int linenumber = 0;

/* fwd: */
/* from usec.c: */
#if 0
extern void v2md5auth_password_to_key();
#endif

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
tokenize(char *line, char **tokens, int max_tokens)
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
create_view(tokens)
     char *tokens[];
{
    static int nextview = 1;
    viewEntry *vp;
    viewEntry *new, *prev = 0;

    if (tokens[3][0] == 0 || tokens[4][0] != 0) {
	debug(49, 0) ("create_view: bad view line, line %d\n", linenumber);
	return -1;
    }
    if (strlen(tokens[1]) > (sizeof(vp->viewName) - 1)) {
	debug(49, 0) ("create_view:view name too long, line %d\n", linenumber);
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
create_user(tokens)
     char *tokens[];
{
    usecEntry *up;
    usecEntry *new, *prev = 0;
    char *start, *cp;
    int ch;
    int i;

    if (tokens[5][0] == 0 || tokens[6][0] != 0) {
	debug(49, 0) ("create_user: bad user line, line %d\n", linenumber);
	return -1;
    }
    if (strlen(tokens[1]) > (sizeof(up->userName) - 1)) {
	debug(49, 0) ("create_user: user name too long, line %d\n", linenumber);
	return -1;
    }
    for (up = Config.Snmp.users; up; prev = up, up = up->next) {
	if (strcmp(tokens[1], (char *) up->userName) == 0)
	    break;
    }

    if (up) {
	debug(49, 0) ("create_user: user '%s' already defined\n", tokens[1]);
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
	debug(49, 0) ("create_user: unknown view name referenced, line %d\n", linenumber);
	return -1;
    }
    start = cp = tokens[5];
    while (*cp && *cp != '/')
	cp++;
    new->userLen = cp - start;
    strncpy((char *) new->userName, start, cp - start);

    if (new->userLen == 0) {
	debug(49, 0) ("create_user: user name invalid, line %d\n", linenumber);
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
	    debug(49, 0) ("create_user: auth key not 16 octets\n");
	    return -1;
	}
	start += 2;
	for (i = 0; i < 16; i++) {
	    if (sscanf(start, "%2x", &ch) != 1) {
		debug(49, 0) ("create_user: auth key contains non hex digits\n");
		return -1;
	    }
	    start += 2;
	    new->authKey[i] = ch;
	}
	new->qoS |= USEC_QOS_AUTH;
    } else if (cp - start > 0) {
#if 0
	v2md5auth_password_to_key(start, cp - start, new->authKey);
#endif
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
	    debug(49, 0) ("create_user: priv key not 16 octets\n");
	    return -1;
	}
	start += 2;
	for (i = 0; i < 16; i++) {
	    if (sscanf(start, "%2x", &ch) != 1) {
		debug(49, 0) ("create_user: priv key contains non hex digits\n");
		return -1;
	    }
	    new->privKey[i] = ch;
	    start += 2;
	}
	new->qoS |= USEC_QOS_PRIV;
    } else if (cp - start > 0) {
#if 0
	v2md5auth_password_to_key(start, cp - start, new->privKey);
#endif
	new->qoS |= USEC_QOS_PRIV;
    }
    return 0;
}

int
create_community(char **tokens)
{
    communityEntry *cp;
    communityEntry *new, *prev = 0;
    debug(49, 3) ("Called create_community (HEY code)\n");
    if (tokens[3][0] == 0 || tokens[4][0] != 0) {
	debug(49, 5) ("create_community: bad community line, line %d\n", linenumber);
	return -1;
    }
    if (strlen(tokens[1]) > (sizeof(cp->name) - 1)) {
	debug(49, 5) ("create_community: community name too long, line %d\n",
	    linenumber);
	return -1;
    }
    for (cp = Config.Snmp.communities; cp; prev = cp, cp = cp->next) {
	if (strcmp(tokens[1], cp->name) == 0)
	    break;
    }

    if (cp) {
	debug(49, 0) ("create_community: community '%s' already defined\n",
	    tokens[1]);
	return -1;
    }
    debug(49, 5) ("Adding %s\n", tokens[1]);
    new = (communityEntry *) xcalloc(1, sizeof(communityEntry));
    memset(new, 0, sizeof(communityEntry));
    xstrncpy(new->name, tokens[1], 32);
    new->readView = find_view(tokens[2]);
    new->writeView = find_view(tokens[3]);
    if (new->readView < 0 || new->writeView < 0) {
	debug(49, 0) ("create_community: unknown view name referenced, line %d\n",
	    linenumber);
	return -1;
    }
    if (Config.Snmp.communities) {
	prev->next = new;
    } else {
	Config.Snmp.communities = new;
    }
    debug(49, 5) ("create_community: Everything ok!\n");
    return 0;
}

int
default_auth()
{
    char *tokens[10];
    char *t;
    t = xstrdup("view $$INTERNAL$$ .1.3.6.1.6.3.6.1 included");
    tokenize(t, tokens, 10);
    maintenanceView = create_view(tokens);
    xfree(t);
    t = xstrdup("view $$INTERNAL$$ .1.3.6.1.6.3.1.1.1 included");
    tokenize(t, tokens, 10);
    create_view(tokens);
    xfree(t);
    return 0;
}
