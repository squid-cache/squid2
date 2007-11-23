
/*
 * $Id$
 *
 * DEBUG: section 82    External ACL
 * AUTHOR: Henrik Nordstrom
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  The contents of this file is Copyright (C) 2002 by MARA Systems AB,
 *  Sweden, unless otherwise is indicated in the specific function. The
 *  author gives his full permission to include this file into the Squid
 *  software product under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

#ifndef DEFAULT_REFRESH_CHECK_CHILDREN
#define DEFAULT_REFRESH_CHECK_CHILDREN 5
#endif

/******************************************************************
 * external_refresh_check parser
 */
typedef struct _refresh_check_format refresh_check_format;

struct _refresh_check_helper {
    refresh_check_format *format;
    wordlist *cmdline;
    int children;
    int concurrency;
    helper *helper;
    dlink_list queue;
};

struct _refresh_check_format {
    enum {
	REFRESH_CHECK_UNKNOWN,
	REFRESH_CHECK_URI,
	REFRESH_CHECK_RESP_HEADER,
	REFRESH_CHECK_RESP_HEADER_MEMBER,
	REFRESH_CHECK_RESP_HEADER_ID,
	REFRESH_CHECK_RESP_HEADER_ID_MEMBER,
	REFRESH_CHECK_AGE,
	REFRESH_CHECK_END
    } type;
    refresh_check_format *next;
    char *header;
    char *member;
    char separator;
    http_hdr_type header_id;
};

/* FIXME: These are not really cbdata, but it is an easy way
 * to get them pooled, refcounted, accounted and freed properly...
 */
CBDATA_TYPE(refresh_check_helper);
CBDATA_TYPE(refresh_check_format);

static void
free_refresh_check_format(void *data)
{
    refresh_check_format *p = data;
    safe_free(p->header);
}

static void
free_refresh_check_helper(void *data)
{
    refresh_check_helper *p = data;
    while (p->format) {
	refresh_check_format *f = p->format;
	p->format = f->next;
	cbdataFree(f);
    }
    wordlistDestroy(&p->cmdline);
    if (p->helper) {
	helperShutdown(p->helper);
	helperFree(p->helper);
	p->helper = NULL;
    }
}

void
parse_refreshCheckHelper(refresh_check_helper ** ptr)
{
    refresh_check_helper *a;
    char *token;
    refresh_check_format **p;

    if (*ptr)
	self_destruct();

    CBDATA_INIT_TYPE_FREECB(refresh_check_helper, free_refresh_check_helper);
    CBDATA_INIT_TYPE_FREECB(refresh_check_format, free_refresh_check_format);

    a = cbdataAlloc(refresh_check_helper);

    a->children = DEFAULT_REFRESH_CHECK_CHILDREN;

    /* Parse options */
    while ((token = strtok(NULL, w_space)) != NULL) {
	if (strncmp(token, "children=", 9) == 0) {
	    a->children = atoi(token + 9);
	} else if (strncmp(token, "concurrency=", 12) == 0) {
	    a->concurrency = atoi(token + 12);
	} else {
	    break;
	}
    }

    /* Parse format */
    p = &a->format;
    while (token) {
	refresh_check_format *format;

	/* stop on first non-format token found */
	if (*token != '%')
	    break;

	format = cbdataAlloc(refresh_check_format);

	if (strncmp(token, "%RES{", 5) == 0) {
	    /* header format */
	    char *header, *member, *end;
	    header = token + 5;
	    end = strchr(header, '}');
	    /* cut away the terminating } */
	    if (end && strlen(end) == 1)
		*end = '\0';
	    else
		self_destruct();

	    member = strchr(header, ':');
	    if (member) {
		/* Split in header and member */
		*member++ = '\0';
		if (!xisalnum(*member))
		    format->separator = *member++;
		else
		    format->separator = ',';
		format->member = xstrdup(member);
		format->type = REFRESH_CHECK_RESP_HEADER_MEMBER;
	    } else {
		format->type = REFRESH_CHECK_RESP_HEADER;
	    }
	    format->header = xstrdup(header);
	    format->header_id = httpHeaderIdByNameDef(header, strlen(header));
	    if (format->header_id != -1) {
		if (member)
		    format->type = REFRESH_CHECK_RESP_HEADER_ID_MEMBER;
		else
		    format->type = REFRESH_CHECK_RESP_HEADER_ID;
	    }
	} else if (strcmp(token, "%URI") == 0)
	    format->type = REFRESH_CHECK_URI;
	else if (strcmp(token, "%URL") == 0)
	    format->type = REFRESH_CHECK_URI;
	else if (strcmp(token, "%CACHE_URI") == 0)
	    format->type = REFRESH_CHECK_URI;
	else if (strcmp(token, "%AGE") == 0)
	    format->type = REFRESH_CHECK_AGE;
	else {
	    self_destruct();
	}
	*p = format;
	p = &format->next;
	token = strtok(NULL, w_space);
    }
    /* There must be at least one format token */
    if (!a->format)
	self_destruct();

    /* helper */
    if (!token)
	self_destruct();
    wordlistAdd(&a->cmdline, token);

    /* arguments */
    parse_wordlist(&a->cmdline);

    *ptr = a;
}

void
dump_refreshCheckHelper(StoreEntry * sentry, const char *name, const refresh_check_helper * list)
{
    const refresh_check_helper *node = list;
    const refresh_check_format *format;
    const wordlist *word;
    if (node) {
	storeAppendPrintf(sentry, "%s", name);
	if (node->children != DEFAULT_REFRESH_CHECK_CHILDREN)
	    storeAppendPrintf(sentry, " children=%d", node->children);
	if (node->concurrency)
	    storeAppendPrintf(sentry, " concurrency=%d", node->concurrency);
	for (format = node->format; format; format = format->next) {
	    switch (format->type) {
	    case REFRESH_CHECK_RESP_HEADER:
	    case REFRESH_CHECK_RESP_HEADER_ID:
		storeAppendPrintf(sentry, " %%{%s}", format->header);
		break;
	    case REFRESH_CHECK_RESP_HEADER_MEMBER:
	    case REFRESH_CHECK_RESP_HEADER_ID_MEMBER:
		storeAppendPrintf(sentry, " %%{%s:%s}", format->header, format->member);
		break;
#define DUMP_REFRESH_CHECK_TYPE(a) \
	    case REFRESH_CHECK_##a: \
		storeAppendPrintf(sentry, " %%%s", #a); \
		break
		DUMP_REFRESH_CHECK_TYPE(URI);
		DUMP_REFRESH_CHECK_TYPE(AGE);
	    case REFRESH_CHECK_UNKNOWN:
	    case REFRESH_CHECK_END:
		fatal("unknown refresh_check format error");
		break;
	    }
	}
	for (word = node->cmdline; word; word = word->next)
	    storeAppendPrintf(sentry, " %s", word->key);
	storeAppendPrintf(sentry, "\n");
    }
}

void
free_refreshCheckHelper(refresh_check_helper ** list)
{
    while (*list) {
	refresh_check_helper *node = *list;
	*list = NULL;
	cbdataFree(node);
    }
}

/******************************************************************
 * refresh_check runtime
 */

static inline int
refreshCheckOverload(refresh_check_helper * def)
{
    return def->helper->stats.queue_size > def->helper->n_running;
}

static char *
makeRefreshCheckRequest(StoreEntry * entry, refresh_check_format * format)
{
    static MemBuf mb = MemBufNULL;
    int first = 1;
    HttpReply *reply;
    String sb = StringNull;

    if (!entry->mem_obj)
	return NULL;

    reply = entry->mem_obj->reply;
    memBufReset(&mb);
    for (; format; format = format->next) {
	char buf[256];
	const char *str = NULL;
	const char *quoted;
	switch (format->type) {
	case REFRESH_CHECK_URI:
	    str = entry->mem_obj->url;
	    break;
	case REFRESH_CHECK_AGE:
	    snprintf(buf, sizeof(buf), "%ld", (long int) (squid_curtime - entry->timestamp));
	    str = buf;
	    break;
	case REFRESH_CHECK_RESP_HEADER:
	    sb = httpHeaderGetByName(&reply->header, format->header);
	    str = strBuf(sb);
	    break;
	case REFRESH_CHECK_RESP_HEADER_ID:
	    sb = httpHeaderGetStrOrList(&reply->header, format->header_id);
	    str = strBuf(sb);
	    break;
	case REFRESH_CHECK_RESP_HEADER_MEMBER:
	    sb = httpHeaderGetByNameListMember(&reply->header, format->header, format->member, format->separator);
	    str = strBuf(sb);
	    break;
	case REFRESH_CHECK_RESP_HEADER_ID_MEMBER:
	    sb = httpHeaderGetListMember(&reply->header, format->header_id, format->member, format->separator);
	    str = strBuf(sb);
	    break;

	case REFRESH_CHECK_UNKNOWN:
	case REFRESH_CHECK_END:
	    fatal("unknown refresh_check_program format error");
	    break;
	}
	if (!str || !*str)
	    str = "-";
	if (!first)
	    memBufAppend(&mb, " ", 1);
	quoted = rfc1738_escape(str);
	memBufAppend(&mb, quoted, strlen(quoted));
	stringClean(&sb);
	first = 0;
    }
    return mb.buf;
}

/******************************************************************
 * refresh_check requests
 */

typedef struct _refreshCheckState refreshCheckState;
struct _refreshCheckState {
    REFRESHCHECK *callback;
    void *callback_data;
    StoreEntry *entry;
    refresh_check_helper *def;
    dlink_node list;
    refreshCheckState *queue;
};

CBDATA_TYPE(refreshCheckState);
static void
free_refreshCheckState(void *data)
{
    refreshCheckState *state = data;
    storeUnlockObject(state->entry);
    cbdataUnlock(state->callback_data);
    cbdataUnlock(state->def);
}

/*
 * The helper program receives queries on stdin, one
 * per line, and must return the result on on stdout
 */
static void
refreshCheckHandleReply(void *data, char *reply)
{
    refreshCheckState *state = data;
    refreshCheckState *next;
    int freshness = -1;
    char *log = NULL;
    MemBuf hdrs = MemBufNULL;


    debug(82, 2) ("refreshCheckHandleReply: reply=\"%s\"\n", reply);

    if (reply) {
	char *t = NULL;
	char *token = strwordtok(reply, &t);
	if (token && strcmp(token, "FRESH") == 0)
	    freshness = 0;
	else if (token && strcmp(token, "OK") == 0)
	    freshness = 0;

	while ((token = strwordtok(NULL, &t))) {
	    char *value = strchr(token, '=');
	    if (value) {
		*value++ = '\0';	/* terminate the token, and move up to the value */
		rfc1738_unescape(value);
		if (strcmp(token, "freshness") == 0)
		    freshness = atoi(value);
		else if (strcmp(token, "log") == 0)
		    log = value;
		else if (strncmp(token, "res{", 4) == 0) {
		    char *header, *t;
		    header = token + 4;
		    t = strrchr(header, '}');
		    if (!t)
			continue;
		    *t = '\0';
		    if (!hdrs.buf)
			memBufDefInit(&hdrs);
		    memBufPrintf(&hdrs, "%s: %s\r\n", header, value);
		}
	    }
	}
    }
    if (freshness >= 0) {
	if (hdrs.size) {
	    HttpReply *rep = httpReplyCreate();
	    httpHeaderParse(&rep->header, hdrs.buf, hdrs.buf + hdrs.size);
	    httpReplyUpdateOnNotModified(state->entry->mem_obj->reply, rep);
	    storeTimestampsSet(state->entry);
	    if (!httpHeaderHas(&rep->header, HDR_DATE)) {
		state->entry->timestamp = squid_curtime;
		state->entry->expires = squid_curtime + freshness;
	    } else if (freshness) {
		state->entry->expires = squid_curtime + freshness;
	    }
	    httpReplyDestroy(rep);
	    storeUpdate(state->entry, NULL);
	} else {
	    state->entry->timestamp = squid_curtime;
	    state->entry->expires = squid_curtime + freshness;
	}
    }
    if (hdrs.buf)
	memBufClean(&hdrs);
    dlinkDelete(&state->list, &state->def->queue);
    do {
	cbdataUnlock(state->def);
	state->def = NULL;

	if (state->callback && cbdataValid(state->callback_data))
	    state->callback(state->callback_data, freshness >= 0, log);
	cbdataUnlock(state->callback_data);
	state->callback_data = NULL;

	next = state->queue;
	cbdataFree(state);
	state = next;
    } while (state);
}

void
refreshCheckSubmit(StoreEntry * entry, REFRESHCHECK * callback, void *callback_data)
{
    MemBuf buf;
    const char *key;
    refresh_check_helper *def = Config.Program.refresh_check;
    refreshCheckState *state;
    dlink_node *node;
    refreshCheckState *oldstate = NULL;

    if (!def) {
	callback(callback_data, 0, NULL);
	return;
    }
    key = makeRefreshCheckRequest(entry, def->format);
    if (!key) {
	callback(callback_data, 0, NULL);
	return;
    }
    debug(82, 2) ("refreshCheckLookup: for '%s'\n", key);

    /* Check for a pending lookup to hook into */
    for (node = def->queue.head; node; node = node->next) {
	refreshCheckState *oldstatetmp = node->data;
	if (entry == oldstatetmp->entry) {
	    oldstate = oldstatetmp;
	    break;
	}
    }

    state = cbdataAlloc(refreshCheckState);
    state->def = def;
    cbdataLock(state->def);
    state->entry = entry;
    storeLockObject(entry);
    state->callback = callback;
    state->callback_data = callback_data;
    cbdataLock(state->callback_data);
    if (oldstate) {
	/* Hook into pending lookup */
	state->queue = oldstate->queue;
	oldstate->queue = state;
    } else {
	/* No pending lookup found. Sumbit to helper */
	/* Check for queue overload */
	if (refreshCheckOverload(def)) {
	    debug(82, 1) ("refreshCheckLookup: queue overload\n");
	    cbdataFree(state);
	    callback(callback_data, 0, "Overload");
	    return;
	}
	/* Send it off to the helper */
	memBufDefInit(&buf);
	memBufPrintf(&buf, "%s\n", key);
	helperSubmit(def->helper, buf.buf, refreshCheckHandleReply, state);
	dlinkAdd(state, &state->list, &def->queue);
	memBufClean(&buf);
    }
}

static void
refreshCheckStats(StoreEntry * sentry)
{
    refresh_check_helper *p = Config.Program.refresh_check;

    if (p) {
	storeAppendPrintf(sentry, "Refresh Check helper statistics:\n");
	helperStats(sentry, p->helper);
	storeAppendPrintf(sentry, "\n");
    }
}
void
refreshCheckConfigure(void)
{
    refresh_check_helper *p = Config.Program.refresh_check;
    if (p) {
	requirePathnameExists("external_refresh_check", p->cmdline->key);
    }
}
void
refreshCheckInit(void)
{
    static int firstTimeInit = 1;
    refresh_check_helper *p = Config.Program.refresh_check;

    if (p) {
	if (!p->helper)
	    p->helper = helperCreate("external_refresh_check");
	p->helper->cmdline = p->cmdline;
	p->helper->n_to_start = p->children;
	p->helper->concurrency = p->concurrency;
	p->helper->ipc_type = IPC_STREAM;
	helperOpenServers(p->helper);
	if (firstTimeInit) {
	    firstTimeInit = 0;
	    cachemgrRegister("refresh_check",
		"External ACL stats",
		refreshCheckStats, 0, 1);
	}
	CBDATA_INIT_TYPE_FREECB(refreshCheckState, free_refreshCheckState);
    }
}

void
refreshCheckShutdown(void)
{
    refresh_check_helper *p = Config.Program.refresh_check;
    if (p) {
	helperShutdown(p->helper);
    }
}
