
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

#define OBJCACHE_MAX_PASSWD_SZ 128

typedef struct objcache_ds {
    StoreEntry *entry;
    char passwd[OBJCACHE_MAX_PASSWD_SZ + 1];
    int reply_fd;
    objcache_op op;
} ObjectCacheData;

struct op_table {
    objcache_op op;
    OBJH *handler;
};

static ObjectCacheData *objcache_url_parser(const char *url);
static int objcache_CheckPassword(ObjectCacheData *);
static char *objcachePasswdGet(cachemgr_passwd ** a, objcache_op op);
static OBJH objcacheUnimplemented;
static OBJH cachemgrShutdown;

static struct op_table OpTable[] =
{
    {MGR_CLIENT_LIST, clientdbDump},
    {MGR_CONFIGURATION, dump_config},
    {MGR_DNSSERVERS, dnsStats},
    {MGR_FILEDESCRIPTORS, statFiledescriptors},
    {MGR_FQDNCACHE, fqdnStats},
    {MGR_INFO, info_get},
    {MGR_IO, stat_io_get},
    {MGR_IPCACHE, stat_ipcache_get},
    {MGR_LOG_CLEAR, objcacheUnimplemented},
    {MGR_LOG_DISABLE, objcacheUnimplemented},
    {MGR_LOG_ENABLE, objcacheUnimplemented},
    {MGR_LOG_STATUS, objcacheUnimplemented},
    {MGR_LOG_VIEW, objcacheUnimplemented},
    {MGR_NETDB, netdbDump},
    {MGR_OBJECTS, stat_objects_get},
    {MGR_REDIRECTORS, redirectStats},
    {MGR_REFRESH, objcacheUnimplemented},
    {MGR_REMOVE, objcacheUnimplemented},
    {MGR_REPLY_HDRS, httpReplyHeaderStats},
    {MGR_SERVER_LIST, server_list},
    {MGR_NON_PEERS, neighborDumpNonPeers},
    {MGR_SHUTDOWN, cachemgrShutdown},
    {MGR_UTILIZATION, stat_utilization_get},
    {MGR_VM_OBJECTS, stat_vmobjects_get},
    {MGR_STOREDIR, storeDirStats},
    {MGR_CBDATA, cbdataDump},
    {MGR_PCONN, pconnHistDump},
    {MGR_5MIN, statAvgDump},
    {MGR_MAX, NULL}		/* terminate list with NULL */
};

/* These operations will not be preformed without a valid password */
static long PASSWD_REQUIRED =
(1 << MGR_LOG_CLEAR) |
(1 << MGR_LOG_DISABLE) |
(1 << MGR_LOG_ENABLE) |
(1 << MGR_LOG_STATUS) |
(1 << MGR_LOG_VIEW) |
(1 << MGR_SHUTDOWN);

static objcache_op
objcacheParseRequest(const char *buf)
{
    objcache_op op = MGR_NONE;
    if (!strcmp(buf, "shutdown"))
	op = MGR_SHUTDOWN;
    else if (!strcmp(buf, "info"))
	op = MGR_INFO;
    else if (!strcmp(buf, "objects"))
	op = MGR_OBJECTS;
    else if (!strcmp(buf, "vm_objects"))
	op = MGR_VM_OBJECTS;
    else if (!strcmp(buf, "utilization"))
	op = MGR_UTILIZATION;
    else if (!strcmp(buf, "ipcache"))
	op = MGR_IPCACHE;
    else if (!strcmp(buf, "fqdncache"))
	op = MGR_FQDNCACHE;
    else if (!strcmp(buf, "dns"))
	op = MGR_DNSSERVERS;
    else if (!strcmp(buf, "redirector"))
	op = MGR_REDIRECTORS;
    else if (!strcmp(buf, "io"))
	op = MGR_IO;
    else if (!strcmp(buf, "reply_headers"))
	op = MGR_REPLY_HDRS;
    else if (!strcmp(buf, "filedescriptors"))
	op = MGR_FILEDESCRIPTORS;
    else if (!strcmp(buf, "netdb"))
	op = MGR_NETDB;
    else if (!strcmp(buf, "storedir"))
	op = MGR_STOREDIR;
    else if (!strcmp(buf, "cbdata"))
	op = MGR_CBDATA;
    else if (!strcmp(buf, "log_status"))
	op = MGR_LOG_STATUS;
    else if (!strcmp(buf, "log_enable"))
	op = MGR_LOG_ENABLE;
    else if (!strcmp(buf, "log_disable"))
	op = MGR_LOG_DISABLE;
    else if (!strcmp(buf, "log_clear"))
	op = MGR_LOG_CLEAR;
    else if (!strcmp(buf, "log"))
	op = MGR_LOG_VIEW;
    else if (!strcmp(buf, "server_list"))
	op = MGR_SERVER_LIST;
    else if (!strcmp(buf, "non_peers"))
	op = MGR_NON_PEERS;
    else if (!strcmp(buf, "client_list"))
	op = MGR_CLIENT_LIST;
    else if (!strcmp(buf, "config"))
	op = MGR_CONFIGURATION;
    else if (!strcmp(buf, "pconn"))
	op = MGR_PCONN;
    else if (!strcmp(buf, "5min"))
	op = MGR_5MIN;
    return op;
}

static ObjectCacheData *
objcache_url_parser(const char *url)
{
    int t;
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, request, MAX_URL);
    LOCAL_ARRAY(char, password, MAX_URL);
    objcache_op op = MGR_NONE;
    ObjectCacheData *obj = NULL;
    t = sscanf(url, "cache_object://%[^/]/%[^@]@%s", host, request, password);
    if (t < 2) {
	debug(16, 0) ("Invalid Syntax: '%s', sscanf returns %d\n", url, t);
	return NULL;
    }
    if ((op = objcacheParseRequest(request)) == MGR_NONE)
	return NULL;
    obj = xcalloc(1, sizeof(ObjectCacheData));
    strcpy(obj->passwd, t == 3 ? password : "nopassword");
    obj->op = op;
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

void
objcacheStart(int fd, StoreEntry * entry)
{
    ObjectCacheData *data = NULL;
    int i;
    OBJH *handler = NULL;
    ErrorState *err = NULL;
    char *hdr;
    debug(16, 3) ("objectcacheStart: '%s'\n", storeUrl(entry));
    if ((data = objcache_url_parser(storeUrl(entry))) == NULL) {
	err = errorCon(ERR_INVALID_REQ, HTTP_NOT_FOUND);
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	entry->expires = squid_curtime;
	return;
    }
    data->reply_fd = fd;
    data->entry = entry;
    entry->expires = squid_curtime;
    debug(16, 1) ("CACHEMGR: %s requesting '%s'\n",
	fd_table[fd].ipaddr,
	objcacheOpcodeStr[data->op]);
    /* Check password */
    if (objcache_CheckPassword(data) != 0) {
	safe_free(data);
	debug(16, 1) ("WARNING: Incorrect Cachemgr Password!\n");
	err = errorCon(ERR_INVALID_REQ, HTTP_NOT_FOUND);
	errorAppendEntry(entry, err);
	entry->expires = squid_curtime;
	storeComplete(entry);
	return;
    }
    /* retrieve object requested */
    for (i = 0; OpTable[i].handler; i++) {
	if (OpTable[i].op == data->op) {
	    handler = OpTable[i].handler;
	    break;
	}
    }
    assert(handler != NULL);
    storeBuffer(entry);
    hdr = httpReplyHeader((double) 1.0,
        HTTP_OK,
        "text/plain",
        -1,			/* Content-Length */
        squid_curtime,		/* LMT */
        squid_curtime);
    storeAppend(entry, hdr, strlen(hdr));
    storeAppend(entry, "\r\n", 2);
    handler(entry);
    storeBufferFlush(entry);
    storeComplete(entry);
    safe_free(data);
}

static void
cachemgrShutdown(StoreEntry * entryunused)
{
    debug(16, 0) ("Shutdown by command.\n");
    shut_down(0);
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
	if (!strcmp(w->key, "all")) {
	    q->actions = ~0;
	    continue;
	}
	op = objcacheParseRequest(w->key);
	if (op <= MGR_NONE || op >= MGR_MAX) {
	    debug(16, 0) ("objcachePasswdAdd: Invalid operation: '%s'\n", w->key);
	    continue;
	}
	q->actions |= (1 << op);
    }
}

void
objcachePasswdDestroy(cachemgr_passwd ** a)
{
    cachemgr_passwd *b;
    cachemgr_passwd *n = NULL;
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

static void
objcacheUnimplemented(StoreEntry * entry)
{
    storeAppendPrintf(entry, "Unimplemented operation\n");
}

void
objcacheInit(void)
{
    assert(sizeof(objcacheOpcodeStr) == (MGR_MAX + 1) * sizeof(char *));
}
