
/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager Objects
 * AUTHOR: Harvest Derived
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

#include "squid.h"
#include "objcache_opcodes.h"

#define STAT_TTL 2
#define OBJCACHE_MAX_REQUEST_SZ 128
#define OBJCACHE_MAX_PASSWD_SZ 128

cacheinfo *HTTPCacheInfo = NULL;
cacheinfo *ICPCacheInfo = NULL;

typedef struct objcache_ds {
    StoreEntry *entry;
    char passwd[OBJCACHE_MAX_PASSWD_SZ + 1];
    int reply_fd;
    objcache_op op;
} ObjectCacheData;

struct _cachemgr_passwd {
    char *passwd;
    long actions;
    struct _cachemgr_passwd *next;
};

static ObjectCacheData *objcache_url_parser _PARAMS((const char *url));
static int objcache_CheckPassword _PARAMS((ObjectCacheData *));
static char *objcachePasswdGet _PARAMS((cachemgr_passwd ** a, objcache_op op));

/* These operations will not be preformed without a valid password */
static long PASSWD_REQUIRED =
(1 << MGR_LOG_CLEAR) |
(1 << MGR_LOG_DISABLE) |
(1 << MGR_LOG_ENABLE) |
(1 << MGR_LOG_STATUS) |
(1 << MGR_LOG_VIEW) |
(1 << MGR_SHUTDOWN) |
(1 << MGR_CONFIG_FILE);

static objcache_op
objcacheParseRequest(const char *buf)
{
    objcache_op op = MGR_NONE;
    if (!strcmp(buf, "shutdown"))
	op = MGR_SHUTDOWN;
    else if (!strcmp(buf, "info"))
	op = MGR_INFO;
    else if (!strcmp(buf, "stats/objects"))
	op = MGR_OBJECTS;
    else if (!strcmp(buf, "stats/vm_objects"))
	op = MGR_VM_OBJECTS;
    else if (!strcmp(buf, "stats/utilization"))
	op = MGR_UTILIZATION;
    else if (!strcmp(buf, "stats/ipcache"))
	op = MGR_IPCACHE;
    else if (!strcmp(buf, "stats/fqdncache"))
	op = MGR_FQDNCACHE;
    else if (!strcmp(buf, "stats/dns"))
	op = MGR_DNSSERVERS;
    else if (!strcmp(buf, "stats/redirector"))
	op = MGR_REDIRECTORS;
    else if (!strcmp(buf, "stats/io"))
	op = MGR_IO;
    else if (!strcmp(buf, "stats/reply_headers"))
	op = MGR_REPLY_HDRS;
    else if (!strcmp(buf, "stats/filedescriptors"))
	op = MGR_FILEDESCRIPTORS;
    else if (!strcmp(buf, "stats/netdb"))
	op = MGR_NETDB;
    else if (!strcmp(buf, "log/status"))
	op = MGR_LOG_STATUS;
    else if (!strcmp(buf, "log/enable"))
	op = MGR_LOG_ENABLE;
    else if (!strcmp(buf, "log/disable"))
	op = MGR_LOG_DISABLE;
    else if (!strcmp(buf, "log/clear"))
	op = MGR_LOG_CLEAR;
    else if (!strcmp(buf, "log"))
	op = MGR_LOG_VIEW;
    else if (!strcmp(buf, "parameter"))
	op = MGR_CONFIG;
    else if (!strcmp(buf, "server_list"))
	op = MGR_SERVER_LIST;
    else if (!strcmp(buf, "client_list"))
	op = MGR_CLIENT_LIST;
    else if (!strcmp(buf, "squid.conf"))
	op = MGR_CONFIG_FILE;
    return op;
}


static ObjectCacheData *
objcache_url_parser(const char *url)
{
    int t;
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, request, MAX_URL);
    LOCAL_ARRAY(char, password, MAX_URL);
    ObjectCacheData *obj = NULL;
    t = sscanf(url, "cache_object://%[^/]/%[^@]@%s", host, request, password);
    if (t < 2) {
	debug(16, 0, "Invalid Syntax: '%s', sscanf returns %d\n", url, t);
	return NULL;
    }
    obj = xcalloc(1, sizeof(ObjectCacheData));
    strcpy(obj->passwd, t == 3 ? password : "nopassword");
    obj->op = objcacheParseRequest(request);
    return obj;
}

/* return 0 if obj->password is good */
static int
objcache_CheckPassword(ObjectCacheData * obj)
{
    char *pwd = objcachePasswdGet(&Config.passwd_list, obj->op);
    if (pwd == NULL)
	return ((1 << obj->op) & PASSWD_REQUIRED);
    if (strcmp(pwd, "disable") == 0)
	return 1;
    if (strcmp(pwd, "none") == 0)
	return 0;
    return strcmp(pwd, obj->passwd);
}

int
objcacheStart(int fd, const char *url, StoreEntry * entry)
{
    static const char *const BADCacheURL = "Bad Object Cache URL %s ... negative cached.\n";
    static const char *const BADPassword = "Incorrect password, sorry.\n";
    ObjectCacheData *data = NULL;
    int complete_flag = 1;

    debug(16, 3, "objectcacheStart: '%s'\n", url);
    if ((data = objcache_url_parser(url)) == NULL) {
	storeAbort(entry, "Invalid objcache syntax.\n");
	entry->expires = squid_curtime + STAT_TTL;
	safe_free(data);
	InvokeHandlers(entry);
	return COMM_ERROR;
    }
    data->reply_fd = fd;
    data->entry = entry;
    entry->expires = squid_curtime + STAT_TTL;
    debug(16, 1, "CACHEMGR: %s requesting '%s'\n",
	fd_table[fd].ipaddr,
	objcacheOpcodeStr[data->op]);
    /* Check password */
    if (objcache_CheckPassword(data) != 0) {
	debug(16, 1, "WARNING: Incorrect Cachemgr Password!\n");
	storeAbort(entry, BADPassword);
	entry->expires = squid_curtime + STAT_TTL;
	InvokeHandlers(entry);
	return COMM_ERROR;
    }
    /* retrieve object requested */
    BIT_SET(entry->flag, DELAY_SENDING);
    switch (data->op) {
    case MGR_SHUTDOWN:
	debug(16, 0, "Shutdown by command.\n");
	/* free up state datastructure */
	safe_free(data);
	shut_down(0);
	break;
    case MGR_INFO:
	HTTPCacheInfo->info_get(HTTPCacheInfo, entry);
	break;
    case MGR_OBJECTS:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "objects", entry);
	break;
    case MGR_VM_OBJECTS:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "vm_objects", entry);
	break;
    case MGR_UTILIZATION:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "utilization", entry);
	break;
    case MGR_IPCACHE:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "ipcache", entry);
	break;
    case MGR_FQDNCACHE:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "fqdncache", entry);
	break;
    case MGR_DNSSERVERS:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "dns", entry);
	break;
    case MGR_REDIRECTORS:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "redirector", entry);
	break;
    case MGR_IO:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "io", entry);
	break;
    case MGR_REPLY_HDRS:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "reply_headers", entry);
	break;
    case MGR_FILEDESCRIPTORS:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "filedescriptors", entry);
	break;
    case MGR_NETDB:
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "netdb", entry);
	break;
    case MGR_LOG_STATUS:
	HTTPCacheInfo->log_status_get(HTTPCacheInfo, entry);
	break;
    case MGR_LOG_ENABLE:
	HTTPCacheInfo->log_enable(HTTPCacheInfo, entry);
	break;
    case MGR_LOG_DISABLE:
	HTTPCacheInfo->log_disable(HTTPCacheInfo, entry);
	break;
    case MGR_LOG_CLEAR:
	HTTPCacheInfo->log_clear(HTTPCacheInfo, entry);
	break;
    case MGR_LOG_VIEW:
	HTTPCacheInfo->log_get_start(HTTPCacheInfo, entry);
	complete_flag = 0;
	break;
    case MGR_CONFIG:
	HTTPCacheInfo->parameter_get(HTTPCacheInfo, entry);
	break;
    case MGR_SERVER_LIST:
	HTTPCacheInfo->server_list(HTTPCacheInfo, entry);
	break;
    case MGR_CLIENT_LIST:
	clientdbDump(entry);
	break;
    case MGR_CONFIG_FILE:
	HTTPCacheInfo->squid_get_start(HTTPCacheInfo, entry);
	complete_flag = 0;
	break;
    default:
	debug(16, 5, "Bad Object Cache URL %s ... negative cached.\n", url);
	storeAppendPrintf(entry, BADCacheURL, url);
	break;
    }
    BIT_RESET(entry->flag, DELAY_SENDING);
    if (complete_flag)
	storeComplete(entry);
    safe_free(data);
    return COMM_OK;
}

void
objcachePasswdAdd(cachemgr_passwd ** list, char *passwd, wordlist * actions)
{
    cachemgr_passwd *p, *q;
    wordlist *w;
    objcache_op op;
    if (!(*list)) {
	/* empty list */
	*list = xcalloc(1, sizeof(cachemgr_passwd));
	(*list)->next = NULL;
	q = *list;
    } else {
	/* find end of list */
	p = *list;
	while (p->next)
	    p = p->next;
	q = xcalloc(1, sizeof(cachemgr_passwd));
	q->next = NULL;
	p->next = q;
    }
    q->passwd = passwd;
    q->actions = 0;
    for (w = actions; w; w = w->next) {
	op = objcacheParseRequest(w->key);
	if (op <= MGR_NONE || op >= MGR_MAX) {
	    debug(16, 0, "objcachePasswdAdd: Invalid operation: '%s'\n", w->key);
	    continue;
	}
	q->actions |= (1 << op);
    }
}

void
objcachePasswdDestroy(cachemgr_passwd ** a)
{
    cachemgr_passwd *b;
    cachemgr_passwd *n;
    for (b = *a; b; b = n) {
	n = b->next;
	safe_free(b->passwd);
	safe_free(b);
    }
    *a = NULL;
}

static char *
objcachePasswdGet(cachemgr_passwd ** a, objcache_op op)
{
    cachemgr_passwd *b;
    for (b = *a; b; b = b->next) {
	if (b->actions & (1 << op))
	    return b->passwd;
    }
    return NULL;
}
