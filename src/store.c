
/*
 * $Id$
 *
 * DEBUG: section 20    Storeage Manager
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

#include "squid.h"		/* goes first */

#define REBUILD_TIMESTAMP_DELTA_MAX 2
#define MAX_SWAP_FILE		(1<<21)
#define SWAP_BUF		DISK_PAGE_SIZE

#define WITH_MEMOBJ	1
#define WITHOUT_MEMOBJ	0

#define STORE_IN_MEM_BUCKETS		(229)

#define STORE_LOG_CREATE	0
#define STORE_LOG_SWAPIN	1
#define STORE_LOG_SWAPOUT	2
#define STORE_LOG_RELEASE	3

static char *storeLogTags[] =
{
    "CREATE",
    "SWAPIN",
    "SWAPOUT",
    "RELEASE"
};

const char *pingStatusStr[] =
{
    "PING_WAITING",
    "PING_TIMEOUT",
    "PING_DONE",
    "PING_NONE"
};

const char *swapStatusStr[] =
{
    "NO_SWAP",
    "SWAPPING_OUT",
    "SWAP_OK"
};

const char *storeStatusStr[] =
{
    "STORE_OK",
    "STORE_PENDING",
    "STORE_ABORTED"
};

struct storeRebuild_data {
    FILE *log;
    int objcount;		/* # objects successfully reloaded */
    int expcount;		/* # objects expired */
    int linecount;		/* # lines parsed from cache logfile */
    int clashcount;		/* # swapfile clashes avoided */
    int dupcount;		/* # duplicates purged */
    time_t start, stop;
    int speed;			/* # Objects per run */
    char line_in[4096];
};

struct _bucketOrder {
    unsigned int bucket;
    int index;
};

/* initializtion flag */
int store_rebuilding = STORE_REBUILDING_SLOW;

/* Static Functions */
static char *storeSwapFullPath _PARAMS((int, char *));
static HashID storeCreateHashTable _PARAMS((int (*)_PARAMS((const char *, const char *))));
static int compareLastRef _PARAMS((StoreEntry **, StoreEntry **));
static int compareBucketOrder _PARAMS((struct _bucketOrder *, struct _bucketOrder *));
static int storeAddSwapDisk _PARAMS((const char *));
static int storeCheckExpired _PARAMS((const StoreEntry *, int flag));
static int storeClientListSearch _PARAMS((const MemObject *, int));
static int storeEntryLocked _PARAMS((const StoreEntry *));
static int storeEntryValidLength _PARAMS((const StoreEntry *));
static int storeHashDelete _PARAMS((StoreEntry *));
static MemObject *new_MemObject _PARAMS((void));
static StoreEntry *new_StoreEntry _PARAMS((int));
static StoreEntry *storeAddDiskRestore _PARAMS((const char *, int, int, time_t, time_t, time_t));
static unsigned int storeGetBucketNum _PARAMS((void));
static void destroy_MemObject _PARAMS((MemObject *));
static void destroy_StoreEntry _PARAMS((StoreEntry *));
static void storePurgeMem _PARAMS((StoreEntry *));
static void storeSanityCheck _PARAMS((void));
static void storeStartRebuildFromDisk _PARAMS((void));
static void storeSwapLog _PARAMS((const StoreEntry *));
static void storeSetPrivateKey _PARAMS((StoreEntry *));
static void storeDoRebuildFromDisk _PARAMS((void *data));
static void storeRebuiltFromDisk _PARAMS((struct storeRebuild_data * data));
static unsigned int getKeyCounter _PARAMS((void));
static int storeOpenSwapFileWrite _PARAMS((StoreEntry *));
static void storePutUnusedFileno _PARAMS((int fileno));
static int storeGetUnusedFileno _PARAMS((void));
static void storeGetSwapSpace _PARAMS((void));

/* Now, this table is inaccessible to outsider. They have to use a method
 * to access a value in internal storage data structure. */
static HashID store_table = 0;

static int store_pages_max = 0;
static int store_pages_high = 0;
static int store_pages_low = 0;

/* current file name, swap file, use number as a filename */
static int swapfileno = 0;
static int store_swapok_size = 0;	/* kilobytes !! */
static int store_swappingout_size = 0;	/* bytes */
#define store_swap_size (store_swapok_size + (store_swappingout_size>>10))
static int store_swap_high = 0;
static int store_swap_low = 0;
static int swaplog_fd = -1;
static int storelog_fd = -1;

/* key temp buffer */
static char key_temp_buffer[MAX_URL + 100];
static char swaplog_file[SQUID_MAXPATHLEN];
static char tmp_filename[SQUID_MAXPATHLEN];

/* patch cache_dir to accomodate multiple disk storage */
static char **CacheDirs = NULL;
static int CacheDirsAllocated = 0;
int ncache_dirs = 0;

/* expiration parameters and stats */
static int store_buckets;
static int store_maintain_rate;
static int store_maintain_buckets;
static int scan_revolutions;
static struct _bucketOrder *MaintBucketsOrder = NULL;

/* unused fileno stack */
#define FILENO_STACK_SIZE 128
static int fileno_stack[FILENO_STACK_SIZE];
int fileno_stack_count = 0;

static MemObject *
new_MemObject(void)
{
    MemObject *mem = get_free_mem_obj();
    mem->swapout_fd = -1;
    mem->reply = xcalloc(1, sizeof(struct _http_reply));
    mem->reply->date = -2;
    mem->reply->expires = -2;
    mem->reply->last_modified = -2;
    meta_data.mem_obj_count++;
    meta_data.misc += sizeof(struct _http_reply);
    debug(20, 3, "new_MemObject: returning %p\n", mem);
    return mem;
}

static StoreEntry *
new_StoreEntry(int mem_obj_flag)
{
    StoreEntry *e = NULL;

    e = xcalloc(1, sizeof(StoreEntry));
    meta_data.store_entries++;
    if (mem_obj_flag)
	e->mem_obj = new_MemObject();
    debug(20, 3, "new_StoreEntry: returning %p\n", e);
    return e;
}

static void
destroy_MemObject(MemObject * mem)
{
    debug(20, 3, "destroy_MemObject: destroying %p\n", mem);
    safe_free(mem->clients);
    safe_free(mem->mime_hdr);
    safe_free(mem->reply);
    safe_free(mem->e_abort_msg);
    requestUnlink(mem->request);
    mem->request = NULL;
    put_free_mem_obj(mem);
    meta_data.mem_obj_count--;
    meta_data.misc -= sizeof(struct _http_reply);
}

static void
destroy_StoreEntry(StoreEntry * e)
{
    debug(20, 3, "destroy_StoreEntry: destroying %p\n", e);
    if (!e) {
	debug_trap("destroy_StoreEntry: NULL Entry");
	return;
    }
    if (e->mem_obj)
	destroy_MemObject(e->mem_obj);
    if (e->url) {
	meta_data.url_strings -= strlen(e->url);
	safe_free(e->url);
    } else {
	debug(20, 3, "destroy_StoreEntry: WARNING: Entry without URL string!\n");
    }
    if (BIT_TEST(e->flag, KEY_URL))
	e->key = NULL;
    else
	safe_free(e->key);
    xfree(e);
    meta_data.store_entries--;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

/*
 * Create 1 hash tables, "table" has all objects.
 */

static HashID
storeCreateHashTable(int (*cmp_func) (const char *, const char *))
{
    store_table = hash_create(cmp_func, store_buckets, hash4);
    return store_table;
}

static int
storeHashInsert(StoreEntry * e)
{
    debug(20, 3, "storeHashInsert: Inserting Entry %p key '%s'\n",
	e, e->key);
    return hash_join(store_table, (hash_link *) e);
}

static int
storeHashDelete(StoreEntry * e)
{
    return hash_remove_link(store_table, (hash_link *) e);
}

/* -------------------------------------------------------------------------- */

static void
storeLog(int tag, const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    MemObject *mem = e->mem_obj;
    struct _http_reply *reply;
    if (storelog_fd < 0)
	return;
    if (mem == NULL)
	return;
    reply = mem->reply;
    sprintf(logmsg, "%9d.%03d %-7s %4d %9d %9d %9d %s %d/%d %s %s\n",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec / 1000,
	storeLogTags[tag],
	reply->code,
	(int) reply->date,
	(int) reply->last_modified,
	(int) reply->expires,
	reply->content_type[0] ? reply->content_type : "unknown",
	reply->content_length,
	e->object_len - mem->reply->hdr_sz,
	RequestMethodStr[e->method],
	e->key);
    file_write(storelog_fd,
	xstrdup(logmsg),
	strlen(logmsg),
	NULL,
	NULL,
	xfree);
}


/* get rid of memory copy of the object */
/* Only call this if storeCheckPurgeMem(e) returns 1 */
static void
storePurgeMem(StoreEntry * e)
{
    debug(20, 3, "storePurgeMem: Freeing memory-copy of %s\n", e->key);
    if (e->mem_obj == NULL)
	return;
    destroy_MemObject(e->mem_obj);
    e->mem_obj = NULL;
}

void
storeLockObject(StoreEntry * e)
{
    e->lock_count++;
    debug(20, 3, "storeLockObject: key '%s' count=%d\n",
	e->key, (int) e->lock_count);
    e->lastref = squid_curtime;
}

void
storeReleaseRequest(StoreEntry * e)
{
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	return;
    if (!storeEntryLocked(e)) {
	debug_trap("Someone called storeReleaseRequest on an unlocked entry");
	debug(20, 0, "  --> '%s'\n", e->url ? e->url : "NULL URL");
	return;
    }
    debug(20, 3, "storeReleaseRequest: FOR '%s'\n", e->key ? e->key : e->url);
    e->flag |= RELEASE_REQUEST;
    storeSetPrivateKey(e);
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */
int
storeUnlockObject(StoreEntry * e)
{
    e->lock_count--;
    debug(20, 3, "storeUnlockObject: key '%s' count=%d\n",
	e->key, e->lock_count);
    if (e->lock_count)
	return (int) e->lock_count;
    if (e->store_status == STORE_PENDING) {
#ifdef COMPLAIN
	debug_trap("storeUnlockObject: Someone unlocked STORE_PENDING object");
	debug(20, 1, "   --> Key '%s'\n", e->key);
#endif
	e->store_status = STORE_ABORTED;
    }
    if (storePendingNClients(e) > 0)
	fatal_dump("storeUnlockObject: unlocked with pending clients\n");
    if (e->swap_status != SWAP_OK)
	fatal_dump("storeUnlockObject: bad swap_status");
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	storeRelease(e);
    else if (!storeEntryValidLength(e))
	storeRelease(e);
    else if (e->object_len > Config.Store.maxObjectSize)
	storeRelease(e);
    else {
	storeSwapLog(e);
	storeLog(STORE_LOG_SWAPOUT, e);
	storePurgeMem(e);
    }
    return 0;
}

/* Lookup an object in the cache. 
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *
storeGet(const char *url)
{
    debug(20, 3, "storeGet: looking up %s\n", url);
    return (StoreEntry *) hash_lookup(store_table, url);
}

unsigned int
getKeyCounter(void)
{
    static unsigned int key_counter = 0;
    if (++key_counter == (1 << 24))
	key_counter = 1;
    return key_counter;
}

unsigned int
storeReqnum(StoreEntry * e, method_t method)
{
    unsigned int k;
    if (BIT_TEST(e->flag, KEY_PRIVATE))
	k = atoi(e->key);
    else
	k = getKeyCounter();
    if (method == METHOD_GET)
	return k;
    return (method << 24) | k;
}

const char *
storeGeneratePrivateKey(const char *url, method_t method, int num)
{
    if (num == 0)
	num = getKeyCounter();
    else if (num & 0xFF000000) {
	method = (method_t) (num >> 24);
	num &= 0x00FFFFFF;
    }
    debug(20, 3, "storeGeneratePrivateKey: '%s'\n", url);
    key_temp_buffer[0] = '\0';
    sprintf(key_temp_buffer, "%d/%s/%s",
	num,
	RequestMethodStr[method],
	url);
    return key_temp_buffer;
}

const char *
storeGeneratePublicKey(const char *url, method_t method)
{
    debug(20, 3, "storeGeneratePublicKey: type=%d %s\n", method, url);
    switch (method) {
    case METHOD_GET:
	return url;
	/* NOTREACHED */
	break;
    case METHOD_POST:
    case METHOD_PUT:
    case METHOD_HEAD:
    case METHOD_CONNECT:
    case METHOD_TRACE:
	sprintf(key_temp_buffer, "/%s/%s", RequestMethodStr[method], url);
	return key_temp_buffer;
	/* NOTREACHED */
	break;
    default:
	debug_trap("storeGeneratePublicKey: Unsupported request method");
	break;
    }
    return NULL;
}

static void
storeSetPrivateKey(StoreEntry * e)
{
    StoreEntry *e2 = NULL;
    hash_link *table_entry = NULL;
    const char *newkey = NULL;

    if (e->key && BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already private */

    newkey = storeGeneratePrivateKey(e->url, e->method, 0);
    if ((table_entry = hash_lookup(store_table, newkey))) {
	e2 = (StoreEntry *) table_entry;
	debug(20, 0, "storeSetPrivateKey: Entry already exists with key '%s'\n",
	    newkey);
	debug(20, 0, "storeSetPrivateKey: Entry Dump:\n%s\n", storeToString(e2));
	debug_trap("Private key already exists.");
	return;
    }
    if (e->key)
	storeHashDelete(e);
    if (e->key && !BIT_TEST(e->flag, KEY_URL))
	safe_free(e->key);
    e->key = xstrdup(newkey);
    storeHashInsert(e);
    BIT_RESET(e->flag, KEY_URL);
    BIT_SET(e->flag, KEY_CHANGE);
    BIT_SET(e->flag, KEY_PRIVATE);
}

void
storeSetPublicKey(StoreEntry * e)
{
    StoreEntry *e2 = NULL;
    hash_link *table_entry = NULL;
    const char *newkey = NULL;
    int loop_detect = 0;

    if (e->key && !BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already public */

    newkey = storeGeneratePublicKey(e->url, e->method);
    while ((table_entry = hash_lookup(store_table, newkey))) {
	debug(20, 3, "storeSetPublicKey: Making old '%s' private.\n", newkey);
	e2 = (StoreEntry *) table_entry;
	storeSetPrivateKey(e2);
	storeRelease(e2);
	if (loop_detect++ == 10)
	    fatal_dump("storeSetPublicKey() is looping!!");
	newkey = storeGeneratePublicKey(e->url, e->method);
    }
    if (e->key)
	storeHashDelete(e);
    if (e->key && !BIT_TEST(e->flag, KEY_URL))
	safe_free(e->key);
    if (e->method == METHOD_GET) {
	e->key = e->url;
	BIT_SET(e->flag, KEY_URL);
	BIT_RESET(e->flag, KEY_CHANGE);
    } else {
	e->key = xstrdup(newkey);
	BIT_RESET(e->flag, KEY_URL);
	BIT_SET(e->flag, KEY_CHANGE);
    }
    BIT_RESET(e->flag, KEY_PRIVATE);
    storeHashInsert(e);
}

StoreEntry *
storeCreateEntry(const char *url,
    const char *req_hdr,
    int req_hdr_sz,
    int flags,
    method_t method)
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    int i;
    debug(20, 3, "storeCreateEntry: '%s' icp flags=%x\n", url, flags);

    e = new_StoreEntry(WITH_MEMOBJ);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    e->url = xstrdup(url);
    meta_data.url_strings += strlen(url);
    e->method = method;
    if (req_hdr) {
	mem->mime_hdr_sz = req_hdr_sz;
	mem->mime_hdr = xmalloc(req_hdr_sz + 1);
	xmemcpy(mem->mime_hdr, req_hdr, req_hdr_sz);
	*(mem->mime_hdr + req_hdr_sz) = '\0';
    }
    if (BIT_TEST(flags, REQ_CACHABLE)) {
	BIT_SET(e->flag, ENTRY_CACHABLE);
	BIT_RESET(e->flag, RELEASE_REQUEST);
    } else {
	BIT_RESET(e->flag, ENTRY_CACHABLE);
	storeReleaseRequest(e);
    }
    if (BIT_TEST(flags, REQ_HIERARCHICAL))
	BIT_SET(e->flag, HIERARCHICAL);
    else
	BIT_RESET(e->flag, HIERARCHICAL);
    if (neighbors_do_private_keys || !BIT_TEST(flags, REQ_HIERARCHICAL))
	storeSetPrivateKey(e);
    else
	storeSetPublicKey(e);
    BIT_SET(e->flag, ENTRY_HTML);

    e->store_status = STORE_PENDING;
    e->swap_file_number = -1;
    e->swap_status = NO_SWAP;
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = 0;		/* set in storeTimestampsSet() */
    e->ping_status = PING_NONE;
    storeOpenSwapFileWrite(e);

    /* allocate client list */
    mem->nclients = MIN_CLIENT;
    mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
    for (i = 0; i < mem->nclients; i++)
	mem->clients[i].fd = -1;
    /* storeLog(STORE_LOG_CREATE, e); */
    return e;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
static StoreEntry *
storeAddDiskRestore(const char *url, int file_number, int size, time_t expires, time_t timestamp, time_t lastmod)
{
    StoreEntry *e = NULL;

    debug(20, 5, "StoreAddDiskRestore: '%s': size %d: expires %d: file_number %d\n",
	url, size, expires, file_number);

    /* if you call this you'd better be sure file_number is not 
     * already in use! */

    meta_data.url_strings += strlen(url);

    e = new_StoreEntry(WITHOUT_MEMOBJ);
    e->url = xstrdup(url);
    e->method = METHOD_GET;
    storeSetPublicKey(e);
    BIT_SET(e->flag, ENTRY_CACHABLE);
    BIT_RESET(e->flag, RELEASE_REQUEST);
    BIT_SET(e->flag, ENTRY_HTML);
    e->store_status = STORE_OK;
    e->swap_file_number = file_number;
    e->swap_status = SWAP_OK;
    file_map_bit_set(file_number);
    e->object_len = size;
    e->lock_count = 0;
    BIT_RESET(e->flag, CLIENT_ABORT_REQUEST);
    e->refcount = 0;
    e->lastref = timestamp;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->ping_status = PING_NONE;
    store_swapok_size += (size + 1023) >> 10;
    return e;
}

/* Register interest in an object currently being retrieved. */
void
storeRegister(StoreEntry * e, int fd, PIF handler, void *data, off_t offset)
{
    int i;
    MemObject *mem = e->mem_obj;
    debug(20, 3, "storeRegister: FD %d '%s'\n", fd, e->key);
    if ((i = storeClientListSearch(mem, fd)) < 0)
	i = storeClientListAdd(e, fd);
    if (mem->clients[i].callback)
	fatal_dump("storeRegister: handler already exists");
    mem->clients[i].offset = offset;
    mem->clients[i].callback = handler;
    mem->clients[i].callback_data = data;
    if (offset < e->object_len) {
	mem->clients[i].callback = NULL;
	mem->clients[i].callback_data = NULL;
	handler(fd, data);
    }
}

int
storeUnregister(StoreEntry * e, int fd)
{
    int i;
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
    debug(20, 3, "storeUnregister: called for FD %d '%s'\n", fd, e->key);
    if ((i = storeClientListSearch(mem, fd)) < 0)
	return 0;
    mem->clients[i].fd = -1;
    mem->clients[i].offset = 0;
    mem->clients[i].callback = NULL;
    mem->clients[i].callback_data = NULL;
    debug(20, 9, "storeUnregister: returning 1\n");
    return 1;
}

off_t
storeGetLowestReaderOffset(const StoreEntry * e)
{
    const MemObject *mem = e->mem_obj;
    int lowest = e->object_len;
    int i;
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].fd == -1)
	    continue;
	if (mem->clients[i].offset < lowest)
	    lowest = mem->clients[i].offset;
    }
    return lowest;
}

/* Call handlers waiting for  data to be appended to E. */
void
InvokeHandlers(StoreEntry * e)
{
    int i;
    MemObject *mem = e->mem_obj;
    PIF handler = NULL;
    void *data = NULL;
    struct _store_client *sc;
    if (mem->clients == NULL && mem->nclients) {
	debug_trap("InvokeHandlers: NULL mem->clients");
	return;
    }
    /* walk the entire list looking for valid handlers */
    for (i = 0; i < mem->nclients; i++) {
	sc = &mem->clients[i];
	if (sc->fd == -1)
	    continue;
	if ((handler = sc->callback) == NULL)
	    continue;
	data = sc->callback_data;
	sc->callback = NULL;
	sc->callback_data = NULL;
	handler(sc->fd, data);
    }
}

/* Mark object as expired */
void
storeExpireNow(StoreEntry * e)
{
    debug(20, 3, "storeExpireNow: '%s'\n", e->key);
    e->expires = squid_curtime;
}

void
storeCheckDoneWriting(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    protocol_t proto = mem->request ? mem->request->protocol : PROTO_NONE;
    if (e->store_status == STORE_PENDING)
	return;
    if (e->object_len < mem->swap_length)
	return;
    e->swap_status = SWAP_OK;
    store_swappingout_size -= (int) e->object_len;
    store_swapok_size += (int) ((e->object_len + 1023) >> 10);
    if (mem->swapout_fd > -1) {
	file_close(mem->swapout_fd);
	mem->swapout_fd = -1;
    }
    HTTPCacheInfo->proto_newobject(HTTPCacheInfo,
            proto,
            e->object_len,
            FALSE);
    storeUnlockObject(e);
}

void
storeLowerSwapSize(void)
{
    int newsize;
    newsize = store_swap_size * 90 / 100;
    if (newsize < Config.Swap.maxSize) {
	/* reduce the swap_size limit to 90% of current size. */
	Config.Swap.maxSize = store_swap_size * 90 / 100;
	debug(20, 0, "WARNING: Setting Maximum Swap Size to %d KB\n",
	    Config.Swap.maxSize);
	storeConfigure();
    }
    storeGetSwapSpace();
}

static void
storeAppendDone(int fd, int err, int len, StoreEntry * e)
{
    debug(20, 3, "storeAppendDone: FD %d, err=%d, len=%d, '%s'\n",
	fd, err, len, e->key);
    if (err) {
	debug(20, 0, "storeAppendDone: ERROR %d for '%s'\n", err, e->key);
	if (err == DISK_NO_SPACE_LEFT)
	    storeLowerSwapSize();
    }
    e->object_len += len;
    store_swappingout_size += len;
    if (e->store_status != STORE_ABORTED && !BIT_TEST(e->flag, DELAY_SENDING))
	InvokeHandlers(e);
    storeCheckDoneWriting(e);
}

/* Append incoming data from a primary server to an entry. */
void
storeAppend(StoreEntry * e, const char *data, int len)
{
    MemObject *mem;
    int xlen;
    int l;
    char *buf;
    /* sanity check */
    if (e == NULL) {
	debug_trap("storeAppend: NULL entry.");
	return;
    } else if ((mem = e->mem_obj) == NULL) {
	debug_trap("storeAppend: NULL e->mem_obj");
	return;
    }
    if (len < 0)
	fatal_dump("storeAppend: len < 0");
    if (len == 0) {
	storeAppendDone(mem->swapout_fd, 0, len, e);
	return;
    }
    debug(20, 3, "storeAppend: FD %d appending %d bytes for '%s'\n",
	mem->swapout_fd, len, e->key);
    xlen = len;
    while (xlen > 0) {
	buf = get_free_8k_page();
	l = xlen > 8192 ? 8192 : xlen;
	memcpy(buf, data, l);
	file_write(mem->swapout_fd,
	    buf,
	    l,
	    storeAppendDone,
	    e,
	    put_free_8k_page);
	xlen -= l;
	data += l;
	mem->swap_length += l;
	e->swap_status = SWAPPING_OUT;
    }
}

#ifdef __STDC__
void
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
{
    va_list args;
    LOCAL_ARRAY(char, buf, 4096);
    va_start(args, fmt);
#else
void
storeAppendPrintf(va_alist)
     va_dcl
{
    va_list args;
    StoreEntry *e = NULL;
    const char *fmt = NULL;
    LOCAL_ARRAY(char, buf, 4096);
    va_start(args);
    e = va_arg(args, StoreEntry *);
    fmt = va_arg(args, char *);
#endif
    buf[0] = '\0';
    vsprintf(buf, fmt, args);
    storeAppend(e, buf, strlen(buf));
    va_end(args);
}

/* add directory to swap disk */
static int
storeAddSwapDisk(const char *path)
{
    char **tmp = NULL;
    int i;
    if (strlen(path) > (SQUID_MAXPATHLEN - 32))
	fatal_dump("cache_dir pathname is too long");
    if (CacheDirs == NULL) {
	CacheDirsAllocated = 4;
	CacheDirs = xcalloc(CacheDirsAllocated, sizeof(char *));
    }
    if (CacheDirsAllocated == ncache_dirs) {
	CacheDirsAllocated <<= 1;
	tmp = xcalloc(CacheDirsAllocated, sizeof(char *));
	for (i = 0; i < ncache_dirs; i++)
	    *(tmp + i) = *(CacheDirs + i);
	xfree(CacheDirs);
	CacheDirs = tmp;
    }
    *(CacheDirs + ncache_dirs) = xstrdup(path);
    return ++ncache_dirs;
}

/* return the nth swap directory */
const char *
swappath(int n)
{
    return *(CacheDirs + (n % ncache_dirs));
}


/* return full name to swapfile */
static char *
storeSwapFullPath(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    sprintf(fullpath, "%s/%02X/%02X/%08X",
	swappath(fn),
	(fn / ncache_dirs) % Config.levelOneDirs,
	(fn / ncache_dirs) / Config.levelOneDirs % Config.levelTwoDirs,
	fn);
    return fullpath;
}

static void
storeSwapLog(const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    /* Note this printf format appears in storeWriteCleanLog() too */
    sprintf(logmsg, "%08x %08x %08x %08x %9d %s\n",
	(int) e->swap_file_number,
	(int) e->timestamp,
	(int) e->expires,
	(int) e->lastmod,
	e->object_len,
	e->url);
    file_write(swaplog_fd,
	xstrdup(logmsg),
	strlen(logmsg),
	NULL,
	NULL,
	xfree);
}


static int
storeOpenSwapFileWrite(StoreEntry * e)
{
    int fd;
    int x;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN);
    MemObject *mem = e->mem_obj;
    /* Suggest a new swap file number */
    if ((x = storeGetUnusedFileno()) >= 0)
	swapfileno = x;
    else
	swapfileno = (swapfileno + 1) % (MAX_SWAP_FILE);
    /* Record the number returned */
    swapfileno = file_map_allocate(swapfileno);
    storeSwapFullPath(swapfileno, swapfilename);
    fd = file_open(swapfilename, NULL, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
	debug(20, 0, "storeOpenSwapFileWrite: Unable to open swapfile: %s\n",
	    swapfilename);
	file_map_bit_reset(swapfileno);
	e->swap_file_number = -1;
	e->swap_status = NO_SWAP;
	return -1;
    }
    mem->swapout_fd = (short) fd;
    debug(20, 3, "storeOpenSwapFileWrite: FD %d, saving '%s' to %s.\n",
	fd, e->url, swapfilename);
    e->swap_file_number = swapfileno;
    mem->swap_length = 0;
    storeLockObject(e);
    return fd;
}

int
storeOpenSwapFileRead(StoreEntry * e)
{
    int fd;
    char *path = NULL;
    /* sanity check! */
    if (e->swap_file_number < 0) {
	debug_trap("storeSwapInStart: bad swap_file_number");
	return -1;
    }
    path = storeSwapFullPath(e->swap_file_number, NULL);
    if ((fd = file_open(path, NULL, O_RDONLY)) < 0) {
	debug(20, 0, "storeSwapInStart: Failed for '%s'\n", e->url);
	return -1;
    }
    debug(20, 3, "storeOpenSwapFileRead: opened on FD %d\n", fd);
    if (e->mem_obj == NULL)
	e->mem_obj = new_MemObject();
    return fd;
}


/* recreate meta data from disk image in swap directory */

/* Add one swap file at a time from disk storage */
static void
storeDoRebuildFromDisk(void *data)
{
    struct storeRebuild_data *rebuildData = data;
    LOCAL_ARRAY(char, swapfile, MAXPATHLEN);
    LOCAL_ARRAY(char, url, MAX_URL);
    StoreEntry *e = NULL;
    time_t expires;
    time_t timestamp;
    time_t lastmod;
    int scan1;
    int scan2;
    int scan3;
    int scan4;
    struct stat sb;
    off_t size;
    int sfileno = 0;
    int count;
    int x;
    int used;			/* is swapfile already in use? */
    int newer;			/* is the log entry newer than current entry? */

    /* load a number of objects per invocation */
    for (count = 0; count < rebuildData->speed; count++) {
	if (fgets(rebuildData->line_in, 4095, rebuildData->log) == NULL) {
	    /* We are done */
	    diskWriteIsComplete(swaplog_fd);
	    storeRebuiltFromDisk(rebuildData);
	    return;
	}
	if ((++rebuildData->linecount & 0xFFF) == 0)
	    debug(20, 1, "  %7d Lines read so far.\n", rebuildData->linecount);

	debug(20, 9, "line_in: %s", rebuildData->line_in);
	if ((rebuildData->line_in[0] == '\0') || (rebuildData->line_in[0] == '\n') ||
	    (rebuildData->line_in[0] == '#'))
	    continue;		/* skip bad lines */

	url[0] = '\0';
	swapfile[0] = '\0';
	sfileno = 0;
	scan1 = 0;
	scan2 = 0;
	scan3 = 0;
	scan4 = 0;
	x = sscanf(rebuildData->line_in, "%x %x %x %x %d %s",
	    &sfileno,		/* swap_file_number */
	    &scan1,		/* timestamp */
	    &scan2,		/* expires */
	    &scan3,		/* last modified */
	    &scan4,		/* size */
	    url);		/* url */
	if (x > 0)
	    storeSwapFullPath(sfileno, swapfile);
	if (x != 6) {
	    if (opt_unlink_on_reload && swapfile[0])
		storePutUnusedFileno(sfileno);
	    continue;
	}
	if (sfileno < 0 || sfileno >= MAX_SWAP_FILE)
	    continue;
	timestamp = (time_t) scan1;
	expires = (time_t) scan2;
	lastmod = (time_t) scan3;
	size = (off_t) scan4;

	if (store_rebuilding != STORE_REBUILDING_FAST) {
	    if (stat(swapfile, &sb) < 0) {
		debug(50, 3, "storeRebuildFromDisk: Swap file missing: '%s': %s: %s.\n", url, swapfile, xstrerror());
		if (opt_unlink_on_reload)
		    safeunlink(swapfile, 1);
		/* XXX probably a bad idea to unlink during reload for NOVM */
		continue;
	    }
	    /* Empty swap file? */
	    if (sb.st_size == 0) {
		if (opt_unlink_on_reload)
		    safeunlink(swapfile, 1);
		/* XXX probably a bad idea to unlink during reload for NOVM */
		continue;
	    }
	    /* Wrong size? */
	    if (sb.st_size != size) {
		/* this log entry doesn't correspond to this file */
		rebuildData->clashcount++;
		continue;
	    }
	    debug(20, 9, "storeRebuildFromDisk: swap file exists: '%s': %s\n",
		url, swapfile);
	}
	e = storeGet(url);
	used = file_map_bit_test(sfileno);
	/* If this URL already exists in the cache, does the swap log
	 * appear to have a newer entry?  Compare 'timestamp' from the
	 * swap log to e->lastref.  Note, we can't compare e->timestamp
	 * because it is the Date: header from the HTTP reply and
	 * doesn't really tell us when the object was added to the
	 * cache. */
	newer = e ? (timestamp > e->lastref ? 1 : 0) : 0;
	if (used && !newer) {
	    /* log entry is old, ignore it */
	    rebuildData->clashcount++;
	    continue;
	} else if (used && e && e->swap_file_number == sfileno) {
	    /* swapfile taken, same URL, newer, update meta */
	    e->lastref = timestamp;
	    e->timestamp = timestamp;
	    e->expires = expires;
	    e->lastmod = lastmod;
	    continue;
	} else if (used) {
	    /* swapfile in use, not by this URL, log entry is newer */
	    /* This is sorta bad: the log entry should NOT be newer at this
	     * point.  If the log is dirty, the filesize check should have
	     * caught this.  If the log is clean, there should never be a
	     * newer entry. */
	    debug(20, 1, "WARNING: newer swaplog entry for fileno %08X\n",
		sfileno);
	    /* I'm tempted to remove the swapfile here just to be safe,
	     * but there is a bad race condition in the NOVM version if
	     * the swapfile has recently been opened for writing, but
	     * not yet opened for reading.  Because we can't map
	     * swapfiles back to StoreEntrys, we don't know the state
	     * of the entry using that file.  */
	    rebuildData->clashcount++;
	    continue;
	} else if (e) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    rebuildData->dupcount++;
	} else {
	    /* URL doesnt exist, swapfile not in use */
	    /* load new */
	    (void) 0;
	}
	rebuildData->objcount++;
	e = storeAddDiskRestore(url,
	    sfileno,
	    (int) size,
	    expires,
	    timestamp,
	    lastmod);
	storeSwapLog(e);
	HTTPCacheInfo->proto_newobject(HTTPCacheInfo,
	    urlParseProtocol(url),
	    (int) size,
	    TRUE);
    }
    eventAdd("storeRebuild", storeDoRebuildFromDisk, rebuildData, 0);
}

/* meta data recreated from disk image in swap directory */
static void
storeRebuiltFromDisk(struct storeRebuild_data *data)
{
    time_t r;
    time_t stop;

    stop = getCurrentTime();
    r = stop - data->start;
    debug(20, 1, "Finished rebuilding storage from disk image.\n");
    debug(20, 1, "  %7d Lines read from previous logfile.\n", data->linecount);
    debug(20, 1, "  %7d Objects loaded.\n", data->objcount);
    debug(20, 1, "  %7d Objects expired.\n", data->expcount);
    debug(20, 1, "  %7d Duplicate URLs purged.\n", data->dupcount);
    debug(20, 1, "  %7d Swapfile clashes avoided.\n", data->clashcount);
    debug(20, 1, "  Took %d seconds (%6.1lf objects/sec).\n",
	r > 0 ? r : 0, (double) data->objcount / (r > 0 ? r : 1));
    debug(20, 1, "  store_swap_size = %dk\n", store_swap_size);

    store_rebuilding = STORE_NOT_REBUILDING;

    fclose(data->log);
    safe_free(data);
    sprintf(tmp_filename, "%s.new", swaplog_file);
    if (rename(tmp_filename, swaplog_file) < 0) {
	debug(50, 0, "storeRebuiltFromDisk: %s,%s: %s\n",
	    tmp_filename, swaplog_file, xstrerror());
	fatal_dump("storeRebuiltFromDisk: rename failed");
    }
    file_close(swaplog_fd);
    if ((swaplog_fd = file_open(swaplog_file, NULL, O_WRONLY | O_CREAT)) < 0)
	fatal_dump("storeRebuiltFromDisk: file_open(swaplog_file) failed");
}

static void
storeStartRebuildFromDisk(void)
{
    struct stat sb;
    int i;
    struct storeRebuild_data *data;
    time_t last_clean;

    if (stat(swaplog_file, &sb) < 0) {
	debug(20, 1, "storeRebuildFromDisk: No log file\n");
	store_rebuilding = STORE_NOT_REBUILDING;
	return;
    }
    data = xcalloc(1, sizeof(*data));

    for (i = 0; i < ncache_dirs; i++)
	debug(20, 1, "Rebuilding storage from disk image in %s\n", swappath(i));
    data->start = getCurrentTime();

    /* Check if log is clean */
    sprintf(tmp_filename, "%s-last-clean", swaplog_file);
    if (stat(tmp_filename, &sb) >= 0) {
	last_clean = sb.st_mtime;
	if (stat(swaplog_file, &sb) >= 0)
	    store_rebuilding = (sb.st_mtime <= last_clean) ?
		STORE_REBUILDING_FAST : STORE_REBUILDING_SLOW;
    }
    /* Remove timestamp in case we crash during rebuild */
    safeunlink(tmp_filename, 1);
    /* close the existing write-only swaplog, and open a temporary
     * write-only swaplog  */
    if (swaplog_fd > -1)
	file_close(swaplog_fd);
    sprintf(tmp_filename, "%s.new", swaplog_file);
    swaplog_fd = file_open(tmp_filename, NULL, O_WRONLY | O_CREAT | O_TRUNC);
    debug(20, 3, "swaplog_fd %d is now '%s'\n", swaplog_fd, tmp_filename);
    if (swaplog_fd < 0) {
	debug(50, 0, "storeStartRebuildFromDisk: %s: %s\n",
	    tmp_filename, xstrerror());
	fatal("storeStartRebuildFromDisk: Can't open tmp swaplog");
    }
    /* Open the existing swap log for reading */
    if ((data->log = fopen(swaplog_file, "r")) == (FILE *) NULL) {
	sprintf(tmp_error_buf, "storeRebuildFromDisk: %s: %s",
	    swaplog_file, xstrerror());
	fatal(tmp_error_buf);
    }
    debug(20, 3, "data->log %d is now '%s'\n", fileno(data->log), swaplog_file);
    if (store_rebuilding == STORE_REBUILDING_FAST)
	debug(20, 1, "Rebuilding in FAST MODE.\n");

    memset(data->line_in, '\0', 4096);
    data->speed = store_rebuilding == STORE_REBUILDING_FAST ? 50 : 5;

    /* Start reading the log file */
    if (opt_foreground_rebuild) {
	data->speed = 1 << 30;
	storeDoRebuildFromDisk(data);
    } else {
	eventAdd("storeRebuild", storeDoRebuildFromDisk, data, 0);
    }
}

/* return current swap size in kilo-bytes */
int
storeGetSwapSize(void)
{
    return store_swap_size;
}

void
storeAbort(StoreEntry * e, const char *msg)
{
    MemObject *mem = e->mem_obj;
    if (e->store_status != STORE_PENDING) {
	debug_trap("storeAbort: bad store_status");
	return;
    } else if (mem == NULL) {
	debug_trap("storeAbort: null mem");
	return;
    }
    e->store_status = STORE_ABORTED;
    mem->e_abort_msg = msg ? xstrdup(msg) : NULL;
    storeReleaseRequest(e);
    InvokeHandlers(e);
    storeCheckDoneWriting(e);
}

/* Complete transfer into the local cache.  */
void
storeComplete(StoreEntry * e)
{
    debug(20, 3, "storeComplete: '%s'\n", e->key);
    e->lastref = squid_curtime;
    e->store_status = STORE_OK;
    safe_free(e->mem_obj->mime_hdr);
    e->mem_obj->mime_hdr = NULL;
    InvokeHandlers(e);
    storeCheckDoneWriting(e);
}

/* get the first entry in the storage */
StoreEntry *
storeGetFirst(void)
{
    return ((StoreEntry *) hash_first(store_table));
}


/* get the next entry in the storage for a given search pointer */
StoreEntry *
storeGetNext(void)
{
    return ((StoreEntry *) hash_next(store_table));
}

/* free up all ttl-expired objects */
void
storePurgeOld(void *unused)
{
    StoreEntry *e = NULL;
    int n = 0;
    int count = 0;
    /* reschedule */
    eventAdd("storePurgeOld", storePurgeOld, NULL, Config.cleanRate);
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if ((++n & 0xFF) == 0) {
	    getCurrentTime();
	    if (shutdown_pending || reread_pending)
		break;
	}
	if ((n & 0xFFF) == 0)
	    debug(20, 2, "storeWalkThrough: %7d objects so far.\n", n);
	if (storeCheckExpired(e, 1))
	    count += storeRelease(e);
    }
    debug(20, 0, "storePurgeOld: Removed %d objects\n", count);
}

static int
compareLastRef(StoreEntry ** e1, StoreEntry ** e2)
{
    if (!e1 || !e2)
	fatal_dump(NULL);
    if ((*e1)->lastref > (*e2)->lastref)
	return (1);
    if ((*e1)->lastref < (*e2)->lastref)
	return (-1);
    return (0);
}

static int
compareBucketOrder(struct _bucketOrder *a, struct _bucketOrder *b)
{
    return a->index - b->index;
}

/* returns the bucket number to work on,
 * pointer to next bucket after each calling
 */
static unsigned int
storeGetBucketNum(void)
{
    static unsigned int bucket = 0;
    if (bucket >= store_buckets)
	bucket = 0;
    return (bucket++);
}

#define SWAP_MAX_HELP (store_buckets/2)

/* The maximum objects to scan for maintain storage space */
#define SWAP_LRUSCAN_COUNT	256
#define SWAP_LRU_REMOVE_COUNT	8

/* Clear Swap storage to accommodate the given object len */
static void
storeGetSwapSpace()
{
    static int swap_help = 0;
    StoreEntry *e = NULL;
    int scanned = 0;
    int removed = 0;
    int locked = 0;
    int locked_size = 0;
    int list_count = 0;
    int scan_count = 0;
    int max_list_count = SWAP_LRUSCAN_COUNT << 1;
    int i;
    StoreEntry **LRU_list;
    hash_link *link_ptr = NULL, *next = NULL;
    static time_t last_warning = 0;
    debug(20, 2, "storeGetSwapSpace: Starting\n");
    if ((i = storeGetUnusedFileno()) >= 0) {
	safeunlink(storeSwapFullPath(i, NULL), 0);
	if (++removed == SWAP_LRU_REMOVE_COUNT)
	    return;
    }
    LRU_list = xcalloc(max_list_count, sizeof(StoreEntry *));
    /* remove expired objects until recover enough or no expired objects */
    for (i = 0; i < store_buckets; i++) {
	link_ptr = hash_get_bucket(store_table, storeGetBucketNum());
	if (link_ptr == NULL)
	    continue;
	/* this for loop handles one bucket of hash table */
	for (; link_ptr; link_ptr = next) {
	    if (list_count == max_list_count)
		break;
	    scanned++;
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;
	    if (!storeEntryLocked(e)) {
		*(LRU_list + list_count) = e;
		list_count++;
		scan_count++;
	    } else {
		locked++;
		locked_size += e->object_len;
	    }
	}			/* for, end of one bucket of hash table */
	qsort((char *) LRU_list,
	    list_count,
	    sizeof(StoreEntry *),
	    (QS) compareLastRef);
	if (list_count > (SWAP_LRU_REMOVE_COUNT - removed))
	    list_count = (SWAP_LRU_REMOVE_COUNT - removed);	/* chop list */
	if (scan_count > SWAP_LRUSCAN_COUNT)
	    break;
    }
    for (i = 0; i < list_count; i++)
	removed += storeRelease(*(LRU_list + i));
    debug(20, 2, "storeGetSwapSpace: After Freeing Size:   %7d kbytes\n",
	store_swap_size);
    /* free the list */
    safe_free(LRU_list);
    if (store_swap_size > store_swap_high) {
	if (++swap_help > SWAP_MAX_HELP)
	    fatal_dump("Repeated failures to free up disk space");
	if (squid_curtime - last_warning > 600) {
	    debug(20, 0, "WARNING: Exceeded 'cache_swap' high water mark (%dK > %dK)\n",
		store_swap_size, store_swap_high);
	    last_warning = squid_curtime;
	}
    } else {
	swap_help = 0;
    }
    getCurrentTime();		/* we may have taken more than one second */
    debug(20, 2, "Removed %d objects\n", removed);
}


/* release an object from a cache */
/* return number of objects released. */
int
storeRelease(StoreEntry * e)
{
    StoreEntry *result = NULL;
    StoreEntry *hentry = NULL;
    hash_link *hptr = NULL;
    const char *hkey;

    debug(20, 3, "storeRelease: Releasing: '%s'\n", e->key);

    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */
    if (storeEntryLocked(e)) {
	storeExpireNow(e);
	debug(20, 3, "storeRelease: Only setting RELEASE_REQUEST bit\n");
	storeReleaseRequest(e);
	return 0;
    }
    if (e->key != NULL) {
	if ((hptr = hash_lookup(store_table, e->key)) == NULL) {
	    debug(20, 0, "storeRelease: Not Found: '%s'\n", e->key);
	    debug(20, 0, "Dump of Entry 'e':\n %s\n", storeToString(e));
	    debug_trap("storeRelease: Invalid Entry");
	    return 0;
	}
	result = (StoreEntry *) hptr;
	if (result != e) {
	    debug(20, 0, "storeRelease: Duplicated entry? '%s'\n",
		result->url ? result->url : "NULL");
	    debug(20, 0, "Dump of Entry 'e':\n%s", storeToString(e));
	    debug(20, 0, "Dump of Entry 'result':\n%s", storeToString(result));
	    debug_trap("storeRelease: Duplicate Entry");
	    return 0;
	}
    }
    /* check if coresponding HEAD object exists. */
    if (e->method == METHOD_GET) {
	hkey = storeGeneratePublicKey(e->url, METHOD_HEAD);
	if ((hentry = (StoreEntry *) hash_lookup(store_table, hkey)))
	    storeExpireNow(hentry);
    }
    if (e->key)
	debug(20, 5, "storeRelease: Release object key: %s\n", e->key);
    else
	debug(20, 5, "storeRelease: Release anonymous object\n");

    if (e->swap_status == SWAP_OK)
	store_swapok_size -= (e->object_len + 1023) >> 10;
    else if (e->swap_status == SWAPPING_OUT)
	store_swappingout_size -= e->object_len;
    if (e->swap_file_number > -1) {
	if (store_swap_size > store_swap_high)
	    safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
	else
	    storePutUnusedFileno(e->swap_file_number);
	file_map_bit_reset(e->swap_file_number);
	e->swap_file_number = -1;
	e->swap_status = NO_SWAP;
	HTTPCacheInfo->proto_purgeobject(HTTPCacheInfo,
	    urlParseProtocol(e->url),
	    e->object_len);
    }
    storeHashDelete(e);
    storeLog(STORE_LOG_RELEASE, e);
    destroy_StoreEntry(e);
    return 1;
}


/* return 1 if a store entry is locked */
static int
storeEntryLocked(const StoreEntry * e)
{
    if (e->lock_count)
	return 1;
    return 0;
}

/* check if there is any client waiting for this object at all */
/* return 1 if there is at least one client */
int
storeClientWaiting(const StoreEntry * e)
{
    int i;
    MemObject *mem = e->mem_obj;
    if (mem->clients) {
	for (i = 0; i < mem->nclients; i++) {
	    if (mem->clients[i].fd != -1)
		return 1;
	}
    }
    return 0;
}

static int
storeClientListSearch(const MemObject * mem, int fd)
{
    int i;
    if (mem->clients) {
	for (i = 0; i < mem->nclients; i++) {
	    if (mem->clients[i].fd == -1)
		continue;
	    if (mem->clients[i].fd != fd)
		continue;
	    return i;
	}
    }
    return -1;
}

/* add client with fd to client list */
int
storeClientListAdd(StoreEntry * e, int fd)
{
    int i;
    MemObject *mem = e->mem_obj;
    struct _store_client *oldlist = NULL;
    int oldsize;
    /* look for empty slot */
    if (mem->clients == NULL) {
	mem->nclients = MIN_CLIENT;
	mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
	for (i = 0; i < mem->nclients; i++)
	    mem->clients[i].fd = -1;
    }
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].fd == fd)
	    return i;		/* its already here */
	if (mem->clients[i].fd == -1)
	    break;
    }
    if (i == mem->nclients) {
	debug(20, 3, "storeClientListAdd: FD %d Growing clients for '%s'\n",
	    fd, e->url);
	oldlist = mem->clients;
	oldsize = mem->nclients;
	mem->nclients <<= 1;
	mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
	for (i = 0; i < oldsize; i++)
	    mem->clients[i] = oldlist[i];
	for (; i < mem->nclients; i++)
	    mem->clients[i].fd = -1;
	safe_free(oldlist);
	i = oldsize;
    }
    mem->clients[i].fd = fd;
    mem->clients[i].offset = 0;
    return i;
}

static int
storeEntryValidLength(const StoreEntry * e)
{
    int diff;
    int hdr_sz;
    int content_length;

    if (e->mem_obj == NULL)
	fatal_dump("storeEntryValidLength: NULL mem_obj");

    hdr_sz = e->mem_obj->reply->hdr_sz;
    content_length = e->mem_obj->reply->content_length;

    debug(20, 3, "storeEntryValidLength: Checking '%s'\n", e->key);
    debug(20, 5, "storeEntryValidLength:     object_len = %d\n", e->object_len);
    debug(20, 5, "storeEntryValidLength:         hdr_sz = %d\n", hdr_sz);
    debug(20, 5, "storeEntryValidLength: content_length = %d\n", content_length);

    if (content_length == 0) {
	debug(20, 5, "storeEntryValidLength: Zero content length; assume valid; '%s'\n",
	    e->key);
	return 1;
    }
    if (hdr_sz == 0) {
	debug(20, 5, "storeEntryValidLength: Zero header size; assume valid; '%s'\n",
	    e->key);
	return 1;
    }
    diff = hdr_sz + content_length - e->object_len;
    if (diff != 0) {
	debug(20, 3, "storeEntryValidLength: %d bytes too %s; '%s'\n",
	    diff < 0 ? -diff : diff,
	    diff < 0 ? "small" : "big",
	    e->key);
	return 0;
    }
    return 1;
}

static int
storeVerifySwapDirs(int clean)
{
    int inx;
    const char *path = NULL;
    struct stat sb;
    int directory_created = 0;
    char *cmdbuf = NULL;

    for (inx = 0; inx < ncache_dirs; inx++) {
	path = swappath(inx);
	debug(20, 9, "storeVerifySwapDirs: Creating swap space in %s\n", path);
	if (stat(path, &sb) < 0) {
	    /* we need to create a directory for swap file here. */
	    if (mkdir(path, 0777) < 0) {
		if (errno != EEXIST) {
		    sprintf(tmp_error_buf, "Failed to create swap directory %s: %s",
			path,
			xstrerror());
		    fatal(tmp_error_buf);
		}
	    }
	    if (stat(path, &sb) < 0) {
		sprintf(tmp_error_buf,
		    "Failed to verify swap directory %s: %s",
		    path, xstrerror());
		fatal(tmp_error_buf);
	    }
	    debug(20, 1, "storeVerifySwapDirs: Created swap directory %s\n", path);
	    directory_created = 1;
	}
	if (clean && opt_unlink_on_reload) {
	    debug(20, 1, "storeVerifySwapDirs: Zapping all objects on disk storage.\n");
	    cmdbuf = xcalloc(1, BUFSIZ);
	    sprintf(cmdbuf, "cd %s; /bin/rm -rf %s [0-9A-F][0-9A-F]",
		path, swaplog_file);
	    debug(20, 1, "storeVerifySwapDirs: Running '%s'\n", cmdbuf);
	    system(cmdbuf);	/* XXX should avoid system(3) */
	    xfree(cmdbuf);
	}
    }
    return directory_created;
}

static void
storeCreateSwapSubDirs(void)
{
    int i, j, k;
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (j = 0; j < ncache_dirs; j++) {
	for (i = 0; i < Config.levelOneDirs; i++) {
	    sprintf(name, "%s/%02X", swappath(j), i);
	    debug(20, 1, "Making directories in %s\n", name);
	    if (mkdir(name, 0755) < 0) {
		if (errno != EEXIST) {
		    sprintf(tmp_error_buf,
			"Failed to make swap directory %s: %s",
			name, xstrerror());
		    fatal(tmp_error_buf);
		}
	    }
	    for (k = 0; k < Config.levelTwoDirs; k++) {
		sprintf(name, "%s/%02X/%02X", swappath(j), i, k);
		if (mkdir(name, 0755) < 0) {
		    if (errno != EEXIST) {
			sprintf(tmp_error_buf,
			    "Failed to make swap directory %s: %s",
			    name, xstrerror());
			fatal(tmp_error_buf);
		    }
		}
	    }
	}
    }
}

#if HAVE_RANDOM
#define squid_random random
#elif HAVE_LRAND48
#define squid_random lrand48
#else
#define squid_random rand
#endif

static void
storeRandomizeBuckets(void)
{
    int i;
    struct _bucketOrder *b;
    if (MaintBucketsOrder == NULL)
	MaintBucketsOrder = xcalloc(store_buckets, sizeof(struct _bucketOrder));
    for (i = 0; i < store_buckets; i++) {
	b = MaintBucketsOrder + i;
	b->bucket = (unsigned int) i;
	b->index = (int) squid_random();
    }
    qsort((char *) MaintBucketsOrder,
	store_buckets,
	sizeof(struct _bucketOrder),
	             (QS) compareBucketOrder);
}

static void
storeInitHashValues(void)
{
    int i;
    /* Calculate size of hash table (maximum currently 64k buckets).  */
    i = Config.Swap.maxSize / Config.Store.avgObjectSize;
    debug(20, 1, "Swap maxSize %d, estimated %d objects\n",
	Config.Swap.maxSize, i);
    i /= Config.Store.objectsPerBucket;
    debug(20, 1, "Target number of buckets: %d\n", i);
    /* ideally the full scan period should be configurable, for the
     * moment it remains at approximately 24 hours.  */
    if (i < 8192)
	store_buckets = 7951, store_maintain_rate = 10;
    else if (i < 12288)
	store_buckets = 12149, store_maintain_rate = 7;
    else if (i < 16384)
	store_buckets = 16231, store_maintain_rate = 5;
    else if (i < 32768)
	store_buckets = 33493, store_maintain_rate = 2;
    else
	store_buckets = 65357, store_maintain_rate = 1;
    store_maintain_buckets = 1;
    storeRandomizeBuckets();
    debug(20, 1, "Using %d Store buckets, maintain %d bucket%s every %d second%s\n",
	store_buckets,
	store_maintain_buckets,
	store_maintain_buckets == 1 ? null_string : "s",
	store_maintain_rate,
	store_maintain_rate == 1 ? null_string : "s");
}

void
storeInit(void)
{
    int dir_created = 0;
    wordlist *w = NULL;
    char *fname = NULL;
    file_map_create(MAX_SWAP_FILE);
    storeInitHashValues();
    storeCreateHashTable(urlcmp);
    if (strcmp((fname = Config.Log.store), "none") == 0)
	storelog_fd = -1;
    else
	storelog_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (storelog_fd < 0)
	debug(20, 1, "Store logging disabled\n");
    for (w = Config.cache_dirs; w; w = w->next)
	storeAddSwapDisk(w->key);
    storeSanityCheck();
    dir_created = storeVerifySwapDirs(opt_zap_disk_store);
    if (Config.Log.swap)
	xstrncpy(swaplog_file, Config.Log.swap, SQUID_MAXPATHLEN);
    else
	sprintf(swaplog_file, "%s/log", swappath(0));
    swaplog_fd = file_open(swaplog_file, NULL, O_WRONLY | O_CREAT);
    debug(20, 3, "swaplog_fd %d is now '%s'\n", swaplog_fd, swaplog_file);
    if (swaplog_fd < 0) {
	sprintf(tmp_error_buf, "Cannot open swap logfile: %s", swaplog_file);
	fatal(tmp_error_buf);
    }
    if (!opt_zap_disk_store)
	storeStartRebuildFromDisk();
    else
	store_rebuilding = STORE_NOT_REBUILDING;
    if (dir_created || opt_zap_disk_store)
	storeCreateSwapSubDirs();
}

void
storeConfigure(void)
{
    int store_mem_high = 0;
    int store_mem_low = 0;
    store_mem_high = (long) (Config.Mem.maxSize / 100) *
	Config.Mem.highWaterMark;
    store_mem_low = (long) (Config.Mem.maxSize / 100) *
	Config.Mem.lowWaterMark;

    store_swap_high = (long) (((float) Config.Swap.maxSize *
	    (float) Config.Swap.highWaterMark) / (float) 100);
    store_swap_low = (long) (((float) Config.Swap.maxSize *
	    (float) Config.Swap.lowWaterMark) / (float) 100);

    store_pages_max = Config.Mem.maxSize / SM_PAGE_SIZE;
    store_pages_high = store_mem_high / SM_PAGE_SIZE;
    store_pages_low = store_mem_low / SM_PAGE_SIZE;
}

/* 
 *  storeSanityCheck - verify that all swap storage areas exist, and
 *  are writable; otherwise, force -z.
 */
static void
storeSanityCheck(void)
{
    LOCAL_ARRAY(char, name, 4096);
    int i;

    if (ncache_dirs < 1)
	storeAddSwapDisk(DefaultSwapDir);

    for (i = 0; i < Config.levelOneDirs; i++) {
	sprintf(name, "%s/%02X", swappath(i), i);
	errno = 0;
	if (access(name, W_OK)) {
	    /* A very annoying problem occurs when access() fails because
	     * the system file table is full.  To prevent squid from
	     * deleting your entire disk cache on a whim, insist that the
	     * errno indicates that the directory doesn't exist */
	    if (errno != ENOENT)
		continue;
	    debug(20, 0, "WARNING: Cannot write to swap directory '%s'\n",
		name);
	    debug(20, 0, "Forcing a *full restart* (e.g., %s -z)...\n",
		appname);
	    opt_zap_disk_store = 1;
	    return;
	}
    }
}

int
urlcmp(const char *url1, const char *url2)
{
    if (!url1 || !url2)
	fatal_dump("urlcmp: Got a NULL url pointer.");
    return (strcmp(url1, url2));
}

/* 
 * This routine is to be called by main loop in main.c.
 * It removes expired objects on only one bucket for each time called.
 * returns the number of objects removed
 *
 * This should get called 1/s from main().
 */
void
storeMaintainSwapSpace(void *unused)
{
    static time_t last_time = 0;
    static int bucket_index = 0;
    hash_link *link_ptr = NULL, *next = NULL;
    StoreEntry *e = NULL;
    int rm_obj = 0;
    int scan_buckets = 0;
    int scan_obj = 0;
    static struct _bucketOrder *b;

    if (store_swap_size > store_swap_high) {
	eventAdd("storeMaintain", storeMaintainSwapSpace, NULL, 0);
	storeGetSwapSpace();
	return;
    }
    eventAdd("storeMaintain", storeMaintainSwapSpace, NULL, 1);
    /* We can't delete objects while rebuilding swap */
    if (store_rebuilding == STORE_REBUILDING_FAST)
	return;

    /* Purges expired objects, check one bucket on each calling */
    if (squid_curtime - last_time >= store_maintain_rate) {
	for (;;) {
	    if (scan_obj && scan_buckets >= store_maintain_buckets)
		break;
	    if (++scan_buckets > 100)
		break;
	    last_time = squid_curtime;
	    if (bucket_index >= store_buckets) {
		bucket_index = 0;
		scan_revolutions++;
		debug(51, 1, "Completed %d full expiration scans of store table\n",
		    scan_revolutions);
		storeRandomizeBuckets();
	    }
	    b = MaintBucketsOrder + bucket_index++;
	    next = hash_get_bucket(store_table, b->bucket);
	    while ((link_ptr = next)) {
		scan_obj++;
		next = link_ptr->next;
		e = (StoreEntry *) link_ptr;
		if (!storeCheckExpired(e, 1))
		    continue;
		rm_obj += storeRelease(e);
	    }
	}
    }
    debug(51, rm_obj ? 2 : 9, "Removed %d of %d objects from bucket %d\n",
	rm_obj, scan_obj, (int) b->bucket);
}


/*
 *  storeWriteCleanLog
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
int
storeWriteCleanLog(void)
{
    StoreEntry *e = NULL;
    FILE *fp = NULL;
    int n = 0;
    int x = 0;
    time_t start, stop, r;
    struct stat sb;

    if (store_rebuilding) {
	debug(20, 1, "storeWriteCleanLog: Not currently OK to rewrite swap log.\n");
	debug(20, 1, "storeWriteCleanLog: Operation aborted.\n");
	return 0;
    }
    debug(20, 1, "storeWriteCleanLog: Starting...\n");
    start = getCurrentTime();
    sprintf(tmp_filename, "%s_clean", swaplog_file);
    if ((fp = fopen(tmp_filename, "a+")) == NULL) {
	debug(50, 0, "storeWriteCleanLog: %s: %s\n", tmp_filename, xstrerror());
	return 0;
    }
#if HAVE_FCHMOD
    if (stat(swaplog_file, &sb) == 0)
	fchmod(fileno(fp), sb.st_mode);
#endif
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAP_OK)
	    continue;
	if (e->object_len <= 0)
	    continue;
	if (BIT_TEST(e->flag, RELEASE_REQUEST))
	    continue;
	if (BIT_TEST(e->flag, KEY_PRIVATE))
	    continue;
	x = fprintf(fp, "%08x %08x %08x %08x %9d %s\n",
	    (int) e->swap_file_number,
	    (int) e->timestamp,
	    (int) e->expires,
	    (int) e->lastmod,
	    e->object_len,
	    e->url);
	if (x < 0) {
	    debug(50, 0, "storeWriteCleanLog: %s: %s\n", tmp_filename, xstrerror());
	    debug(20, 0, "storeWriteCleanLog: Current swap logfile not replaced.\n");
	    fclose(fp);
	    safeunlink(tmp_filename, 0);
	    return 0;
	}
	if ((++n & 0xFFF) == 0) {
	    getCurrentTime();
	    debug(20, 1, "  %7d lines written so far.\n", n);
	}
    }
    if (fclose(fp) < 0) {
	debug(50, 0, "storeWriteCleanLog: %s: %s\n", tmp_filename, xstrerror());
	debug(20, 0, "storeWriteCleanLog: Current swap logfile not replaced.\n");
	safeunlink(tmp_filename, 0);
	return 0;
    }
    if (rename(tmp_filename, swaplog_file) < 0) {
	debug(50, 0, "storeWriteCleanLog: rename failed: %s\n",
	    xstrerror());
	return 0;
    }
    file_close(swaplog_fd);
    swaplog_fd = file_open(swaplog_file, NULL, O_WRONLY | O_CREAT);
    if (swaplog_fd < 0) {
	sprintf(tmp_error_buf, "Cannot open swap logfile: %s", swaplog_file);
	fatal(tmp_error_buf);
    }
    stop = getCurrentTime();
    r = stop - start;
    debug(20, 1, "  Finished.  Wrote %d lines.\n", n);
    debug(20, 1, "  Took %d seconds (%6.1lf lines/sec).\n",
	r > 0 ? r : 0, (double) n / (r > 0 ? r : 1));

    /* touch a timestamp file */
    sprintf(tmp_filename, "%s-last-clean", swaplog_file);
    file_close(file_open(tmp_filename, NULL, O_WRONLY | O_CREAT | O_TRUNC));
    return n;
}

int
storePendingNClients(const StoreEntry * e)
{
    int npend = 0;
    MemObject *mem = e->mem_obj;
    int i;
    if (mem == NULL)
	return 0;
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].fd == -1)
	    continue;
	npend++;
    }
    return npend;
}

void
storeRotateLog(void)
{
    char *fname = NULL;
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
    struct stat sb;

    if (storelog_fd > -1) {
	file_close(storelog_fd);
	storelog_fd = -1;
    }
    if ((fname = Config.Log.store) == NULL)
	return;
    if (strcmp(fname, "none") == 0)
	return;
#ifdef S_ISREG
    if (stat(fname, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif

    debug(20, 1, "storeRotateLog: Rotating.\n");

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	sprintf(from, "%s.%d", fname, i - 1);
	sprintf(to, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	sprintf(to, "%s.%d", fname, 0);
	rename(fname, to);
    }
    storelog_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (storelog_fd < 0) {
	debug(50, 0, "storeRotateLog: %s: %s\n", fname, xstrerror());
	debug(20, 1, "Store logging disabled\n");
    }
}

static int
storeCheckExpired(const StoreEntry * e, int check_lru_age)
{
    time_t max_age;
    if (storeEntryLocked(e))
	return 0;
    if (BIT_TEST(e->flag, ENTRY_NEGCACHED) && squid_curtime >= e->expires)
	return 1;
    if (!check_lru_age)
	return 0;
    if ((max_age = storeExpiredReferenceAge()) <= 0)
	return 0;
    if (squid_curtime - e->lastref > max_age)
	return 1;
    return 0;
}

/* 
 * storeExpiredReferenceAge
 *
 * The LRU age is scaled exponentially between 1 minute and
 * Config.referenceAge , when store_swap_low < store_swap_size <
 * store_swap_high.  This keeps store_swap_size within the low and high
 * water marks.  If the cache is very busy then store_swap_size stays
 * closer to the low water mark, if it is not busy, then it will stay
 * near the high water mark.  The LRU age value can be examined on the
 * cachemgr 'info' page.
 */
time_t
storeExpiredReferenceAge(void)
{
    double x;
    double z;
    time_t age;
    if (Config.referenceAge == 0)
	return 0;
    x = (double) (store_swap_high - store_swap_size) / (store_swap_high - store_swap_low);
    x = x < 0.0 ? 0.0 : x > 1.0 ? 1.0 : x;
    z = pow((double) Config.referenceAge, x);
    age = (time_t) (z * 60.0);
    if (age < 60)
	age = 60;
    else if (age > 31536000)
	age = 31536000;
    return age;
}

void
storeCloseLog(void)
{
    if (swaplog_fd >= 0)
	file_close(swaplog_fd);
    if (storelog_fd >= 0)
	file_close(storelog_fd);
}

void
storeNegativeCache(StoreEntry * e)
{
    e->expires = squid_curtime + Config.negativeTtl;
    BIT_SET(e->flag, ENTRY_NEGCACHED);
}

void
storeFreeMemory(void)
{
    StoreEntry *e;
    StoreEntry **list;
    int i = 0;
    int j;
    list = xcalloc(meta_data.store_entries, sizeof(StoreEntry *));
    e = (StoreEntry *) hash_first(store_table);
    while (e && i < meta_data.store_entries) {
	*(list + i) = e;
	i++;
	e = (StoreEntry *) hash_next(store_table);
    }
    for (j = 0; j < i; j++)
	destroy_StoreEntry(*(list + j));
    xfree(list);
    hashFreeMemory(store_table);
    safe_free(MaintBucketsOrder);
}

int
expiresMoreThan(time_t expires, time_t when)
{
    if (expires < 0)		/* No Expires given */
	return 1;
    return (expires > (squid_curtime + when));
}

int
storeEntryValidToSend(StoreEntry * e)
{
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	return 0;
    if (BIT_TEST(e->flag, ENTRY_NEGCACHED))
	if (e->expires <= squid_curtime)
	    return 0;
    if (e->store_status == STORE_ABORTED)
	return 0;
    return 1;
}

int
storeFirstClientFD(MemObject * mem)
{
    int i;
    if (mem == NULL)
	return -1;
    if (mem->clients == NULL)
	return -1;
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].fd > -1)
	    return mem->clients[i].fd;
    }
    return -1;
}

void
storeTimestampsSet(StoreEntry * e)
{
    time_t served_date = -1;
    struct _http_reply *reply = e->mem_obj->reply;
    served_date = reply->date > -1 ? reply->date : squid_curtime;
    e->expires = reply->expires;
    if (reply->last_modified > -1)
	e->lastmod = reply->last_modified;
    else
	e->lastmod = served_date;
    e->timestamp = served_date;
}

static int
storeGetUnusedFileno(void)
{
    if (fileno_stack_count < 1)
	return -1;
    return fileno_stack[--fileno_stack_count];
}

static void
storePutUnusedFileno(int fileno)
{
    if (fileno_stack_count < FILENO_STACK_SIZE)
	fileno_stack[fileno_stack_count++] = fileno;
    else
	unlinkdUnlink(storeSwapFullPath(fileno, NULL));
}
