
/*
 * $Id$
 *
 * DEBUG: section 63    Low Level Memory Pool Management
 * AUTHOR: Alex Rousskov
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


#include "squid.h"
#include "Stack.h"

#if 0
    There are three levels of memory allocation.
    First two are implemented here. "User interface" is in mem.c

	- Level 0: Memoty chunks: big chunks of pre-allocated memory; source
	           of space for pools.
	- Level 1: Memory pools: common space for objects of the same size.

	- Level 2: User: arbitrary length/type objects; allocated using one of
		   the hard coded memory pools. (see mem.c)

    Note: we use term "pre-allocated" for memory that is allocated on-demand,
	  chunk by chunk until we reach the configurable limit. In other
	  words, we do not pre-allocate all specified memory at once, but do
	  it on demand. Chunks may be big in the begining. Chunk sizes get
	  smaller when we come close to the limit. Thus, one may specify
	  rather large limit and not worry about memory under utilization.
	  If no limit is specified we use minimal size chunks all the time.
#endif


/*
 * Configuration
 */

#define MB ((size_t)1024*1024)

/* maximum we are allowed to pre-allocate */
static size_t mem_max_size = 0; 

/* total of currently allocated mem; cannot lower maximum beyond this */
static size_t mem_size = 0;

/* huge constant to set mem_max_size to "unlimited" */
static const size_t mem_unlimited_size = 2*1024*MB;

/* _soft_ minimum for #entries to pre-allocate at a time (for a pool) */
static const int mem_pool_growth_count = 64;
/* growth_delta = current_size/factor; (other restrictions apply) */
static const int mem_pool_growth_factor = 10; /* 10 is 10%, 20 is 5% */

/* limitations on chunk sizes */
static const size_t chunk_min_size =  1*MB;
static const size_t chunk_max_size = 25*MB;

/* next_chunk_size = (mem_max_size - mem_size)/factor; (other restrictions apply) */
static const size_t mem_partition_factor = 3;

static double toMB(size_t size) { return ((double)size)/MB; }
static size_t toKB(size_t size) { return (size+1024-1)/1024; }

void
memConfigure()
{
    size_t new_mem_max_size = mem_max_size;
    /* set to configured value first */
    if (!Config.onoff.mem_pools)
	new_mem_max_size = 0;
    else
	new_mem_max_size = (Config.MemPools.limit > 0) ?
	    Config.MemPools.limit : mem_unlimited_size;
    /* currently, we cannot decrease current memory consumption */
    if (new_mem_max_size < mem_size) {
	debug(63, 0) ("Warning: configured mem pool limit is below current consumpion.\n");
	debug(63, 0) ("         seting limit[MB] to %.2 instead of %.2, was %.2.\n",
	    toMB(mem_size), toMB(new_mem_max_size), toMB(mem_max_size));
	new_mem_max_size = mem_size;
    }
    mem_max_size = new_mem_max_size;
    debug(63, 1) ("Memory pools are '%s'; limit: %.2f MB\n", 
	(Config.onoff.mem_pools ? "on" : "off"), toMB(mem_max_size));
}

/*
 * Implementation
 */


/* dynamic pool is not really a pool, just a placeholder for malloc stats */
struct _DynPool {
    size_t alive_size;  /* current memory allocated */
    size_t hwater_size; /* high water mark for alive_size */
};

/* a pool is a [growing] space for objects of the same size */
struct _MemPool {
    const char *label;
    size_t obj_size;
    size_t capacity;      /* total pre-allocated memory */
    size_t size;          /* used  pre-allocated memory */
    size_t hwater_size;   /* used  pre-allocated memory */
    int grow_count;       /* number of times this pool grew */
    Stack pstack;         /* stack for free pointers */
    DynPool dyn_pool;
};

/* pre-allocated memory is allocated by chunks */
typedef struct {
    char *buf;
    size_t capacity;   /* allocated amount */
    size_t used_size;  /* bytes already given away */
} MemChunk;

/* prototypes */
static void memPoolGrow(MemPool *pool);
static int memIsStatic(void *obj);
static char *memGetBlock(size_t min_size, size_t max_size, size_t *act_size);
static MemChunk *memGetChunk();
static MemChunk *memChunkCreate(size_t size);
static void memChunkDestroy(MemChunk *chunk);
static int memChunkContains(MemChunk *chunk, const char *ptr);
static char *memChunkGetBlock(MemChunk *chunk, size_t min_size, size_t max_size, size_t *act_size);

/* module globals */
static Stack Chunks;
static MemChunk *FreeChunk = 0;

/* global accounting */
/* memory lost due to fragmentation as seen from this module */
static size_t mem_lost_size = 0;
/* memory size to trigger next "current usage" message */
static size_t mem_next_report_level = 8*MB;
/* sizes and high water marks for static and dynamic memory */
static size_t mem_dyn_size = 0;
static size_t mem_dyn_size_hwater = 0;
static size_t mem_size_used = 0;
static size_t mem_size_used_hwater = 0;


static size_t mem_max(size_t a, size_t b) { return (a >= b) ? a : b; }
static size_t mem_min(size_t a, size_t b) { return (a <= b) ? a : b; }


#ifdef MEM_USER_LEVEL

/* module globals */

/* user defined pool attributes */  @?@ move to mem.c
typedef struct {
    mem_type id;
    const char *label;
    size_t obj_size;
} PoolAttr; @?@ move to mem.c

static const PoolAttr PoolAttrs[] = {
    { 
};


/* all memory pools are stored here */
Array Pools; @?@ move to mem.c

/* special pools for strings */ @?@ move to mem.c
MemPool *ShortStrPool = NULL;
MemPool *MediumStrPool = NULL;
MemPool *LongStrPool = NULL;
DynPool *HugeStrPool = NULL;
DynPool *DynStrPool = NULL;

MemPool *
memStringPoolCreate(const char *label)
{
    MemPool *pool = memPoolCreate(label, 1); /* @?@ */
    pool->obj_size = 0;
    stackPush(&pool->pstack, memPoolCreate("short string", 32));
    stackPush(&pool->pstack, memPoolCreate("medium string", 64));
    stackPush(&pool->pstack, memPoolCreate("url-size string", 128));
    stackPush(&pool->pstack, memPoolCreate("long string", 256));
    stackPush(&pool->pstack, memPoolCreate("huge string", 512));
    return pool;
}

static char *
tagStr(char *str, int tag)
{
    str[0] = (char)tag;
    return str+1;
}

char *
memStrAlloc(size_t size)
{
    if (!mem_pools_on)
	return memPoolMalloc(&DynStrPool, size);
    /* find closest pool, assume shorter strings are more popular */
    /* preserve one byte for a tag */
    if (size < ShortStrPool.obj_size)
	return tagStr(memAlloc(&ShortStrPool), 1);
    if (size < MediumStrPool.obj_size)
	return tagStr(memAlloc(&MediumStrPool), 2);
    if (size < LongStrPool.obj_size)
	return tagStr(memAlloc(&LongStrPool), 3);
    return tagStr(memPoolMalloc(&DynStrPool, size), 4);
}

void
memStrFree(char *str)
{
    int tag;
    if (!mem_pools_on)
	memPoolFree(&DynStrPool, str);
    assert(str);
    tag = *--str;
    if (tag == 1)
	memFree(&ShortStrPool, str);
    if (tag == 2)
	memFree(&MediumStrPool, str);
    if (tag == 3)
	memFree(&LongStrPool, str);
    assert(tag == 0);
    memPoolFree(&DynStrPool, str);
}

void
memReport(FILE *fp)
{
    int i;
    for (i = 0; i < Pools.count; i++) {
	fprintf(fp, "%3d : ", i);
	memPoolReport(Pools.buf[i], fp);
    }
    fprintf(fp, "mem_size: %.2f  mem_max_size: %.2f MB\n",
	mem_size/1024./1024., mem_max_size/1024/1024.);

}

#endif /* MEM_USER_LEVEL */

/* Initialization */

void
memInitModule()
{
    stackInit(&Chunks);
    FreeChunk = NULL;
}

void
memCleanModule()
{
    assert(mem_size_used == 0);
    while (Chunks.count)
	memChunkDestroy(stackPop(&Chunks));
    stackClean(&Chunks);
    FreeChunk = NULL;
}

/* DynPool */

DynPool *
dynPoolCreate()
{
    return xcalloc(1, sizeof(DynPool));
}

static void
dynPoolInit(DynPool *pool)
{
    pool->alive_size = 0;
    pool->hwater_size = 0;
}

static void
dynPoolClean(DynPool *pool)
{
}

void
dynPoolDestroy(DynPool *pool)
{
    xfree(pool);
}

void *
dynPoolAlloc(DynPool *pool, size_t size)
{
    assert(pool);
    pool->alive_size += size;
    if (pool->alive_size > pool->hwater_size)
	pool->hwater_size = pool->alive_size;
    mem_dyn_size += size;
    if (mem_dyn_size > mem_dyn_size_hwater)
	mem_dyn_size_hwater = mem_dyn_size;
    return xcalloc(1, size);
}

void
dynPoolFree(DynPool *pool, void *obj, size_t size)
{
    assert(pool);
    assert(pool->alive_size >= size);
    pool->alive_size -= size;
    mem_dyn_size -= size;
    xfree(obj);
}


/* MemPool */

MemPool *
memPoolCreate(const char *label, size_t obj_size)
{
    MemPool *pool = xcalloc(1, sizeof(MemPool));
    assert(label && obj_size);
    pool->label = label;
    pool->obj_size = obj_size;
    pool->capacity = 0;
    pool->size = 0;
    pool->hwater_size = 0;
    pool->grow_count = 0;
    dynPoolInit(&pool->dyn_pool);
    stackInit(&pool->pstack);
    return pool;
}

void
memPoolDestroy(MemPool *pool)
{
    assert(pool);
    stackClean(&pool->pstack);
    dynPoolClean(&pool->dyn_pool);
    xfree(pool);
}

void *
memPoolAlloc(MemPool *pool)
{
    assert(pool);
    if (!mem_max_size)
	return dynPoolAlloc(&pool->dyn_pool, pool->obj_size);
    if (!pool->pstack.count) {
	memPoolGrow(pool);
	if (!pool->pstack.count)
	    return dynPoolAlloc(&pool->dyn_pool, pool->obj_size);
    }
    pool->size += pool->obj_size;
    if (pool->size > pool->hwater_size)
	pool->hwater_size = pool->size;
    mem_size_used += pool->obj_size;
    if (mem_size_used > mem_size_used_hwater)
	mem_size_used_hwater = mem_size_used;
    return stackPop(&pool->pstack);
}

void
memPoolFree(MemPool *pool, void *obj)
{
    assert(pool && obj);
    if (mem_max_size && (!pool->dyn_pool.alive_size || memIsStatic(obj))) {
	pool->size -= pool->obj_size;
	mem_size_used -= pool->obj_size;
	memset(obj, 0, pool->obj_size);
	stackPush(&pool->pstack, obj);
    } else {
	dynPoolFree(&pool->dyn_pool, obj, pool->obj_size);
    }
}

/* try to grow by at least one element */
static void
memPoolGrow(MemPool *pool)
{
    const size_t obj_size = pool->obj_size;
    size_t delta = mem_max(
	obj_size*mem_pool_growth_count,
	obj_size*(pool->capacity/mem_pool_growth_factor/obj_size));
    char *block = memGetBlock(obj_size, delta, &delta);
    debug(63, 7) ("mem pool %-20s (%d) growing: %d += %d : %d/%d\n", 
	pool->label, pool->obj_size, pool->capacity, delta,
	pool->pstack.count, pool->pstack.capacity);
    if (block) {
	assert(delta >= obj_size);
	pool->capacity += delta;
	stackPrePush(&pool->pstack, delta/obj_size);
	while (delta >= obj_size) {
	    debug(63, 9) ("mem pool adds %p delta: %d\n", block, delta);
	    stackPush(&pool->pstack, block);
	    block += obj_size;
	    delta -= obj_size;
	}
	assert(delta == 0);
	pool->grow_count++;
    }
    debug(63, 7) ("mem pool %-20s grew: %d : %d/%d\n", 
	pool->label, pool->capacity,
	pool->pstack.count, pool->pstack.capacity);
}

int
memPoolWasNeverUsed(const MemPool *pool)
{
    assert(pool);
    return !pool->capacity && !pool->dyn_pool.hwater_size;
}

int
memPoolIsUsedNow(const MemPool *pool)
{
    assert(pool);
    return pool->size || pool->dyn_pool.alive_size;
}

int
memPoolUsedCount(const MemPool *pool)
{
    assert(pool && pool->obj_size);
    return (pool->size + pool->dyn_pool.alive_size)/pool->obj_size;
}

void
memPoolDescribe(const MemPool *pool)
{
    assert(pool);
    debug(63, 0) ("%-20s: obj size: %4d obj count: %4d used: %5d + %5d KB\n",
	pool->label, pool->obj_size,
	memPoolUsedCount(pool),
	toKB(pool->size), toKB(pool->dyn_pool.alive_size));
}

void
memPoolReport(const MemPool *pool, StoreEntry *e)
{
    assert(pool);
    storeAppendPrintf(e, "%-20s\t %4d\t %d\t %d\t %d\t %d\t %6.2f\t %d\t %d\t %d\t %d\n",
	pool->label, pool->obj_size,
	pool->capacity/pool->obj_size, toKB(pool->capacity), 
	toKB(pool->size), toKB(pool->hwater_size),
	xpercent(pool->size, pool->capacity), pool->grow_count,
	pool->dyn_pool.alive_size/pool->obj_size,
	toKB(pool->dyn_pool.alive_size), toKB(pool->dyn_pool.hwater_size));
}


/* Level 0: Chunks */

static int
memIsStatic(void *obj)
{
    int i = Chunks.count;
    while (i-- > 0)
	if (memChunkContains(Chunks.items[i], (const char *)obj))
	    return 1;
    debug(63,9) ("memIsStatic: searched %d chunks, negative\n",
	Chunks.count);
    return 0;
}

static char *
memGetBlock(size_t min_size, size_t max_size, size_t *act_size)
{
    if (!FreeChunk || FreeChunk->used_size + min_size > FreeChunk->capacity) {
	if (min_size > chunk_max_size) {
	    *act_size = 0;
	    return NULL;
	}
	if (FreeChunk)
	    mem_lost_size += FreeChunk->capacity - FreeChunk->used_size;
	FreeChunk = memGetChunk();
	if (FreeChunk)
	    stackPush(&Chunks, FreeChunk);
    }
    if (FreeChunk)
	return memChunkGetBlock(FreeChunk, min_size, max_size, act_size);
    *act_size = 0;
    return NULL;
}

static MemChunk *
memGetChunk()
{
    MemChunk *chunk;
    size_t chunk_size = mem_min(mem_max(
	(mem_max_size-mem_size)/mem_partition_factor, chunk_min_size),
	chunk_max_size);
    /* if no mem_max_size specified ("guess" mode) then use min chunk size */
    if (mem_max_size == mem_unlimited_size)
	chunk_size = chunk_min_size;
    /* check that we are not over the limit */
    if (mem_size + chunk_size > mem_max_size)
	chunk_size = mem_max_size - mem_size;
    if (chunk_size <= 0)
	return NULL;
    chunk = memChunkCreate(chunk_size);
    /* inform about pre-allocated memory getting larger */
    if (mem_size >= mem_next_report_level) {
	debug(63,1)("Mem: FYI: pre-allocated %.2f MB so far.\n",
	    toMB(mem_size));
	mem_next_report_level *= 2;
    }
    /* warn when pre-allocated memory is almost over */
    if (mem_size >= mem_max_size)
	debug(63,1)("Mem: pre-allocated last memory chunk (%d bytes); used %.2f MB total\n",
	    chunk_size, toMB(mem_size));
    return chunk;
}

static MemChunk *
memChunkCreate(size_t size)
{
    MemChunk *chunk = size ? xcalloc(1, sizeof(MemChunk)) : NULL;
    if (chunk) {
	mem_size += size;
        assert(mem_size <= mem_max_size);
	chunk->buf = xcalloc(1, size);
	chunk->capacity = size;
	chunk->used_size = 0;
    }
    return chunk;
}

static void
memChunkDestroy(MemChunk *chunk)
{
    assert(chunk);
    xfree(chunk->buf);
    xfree(chunk);
}

static int
memChunkContains(MemChunk *chunk, const char *ptr)
{
    assert(chunk);
    return chunk->buf <= ptr && ptr < chunk->buf + chunk->capacity;
}

/*
 * returns a portion of a chunk; 
 * returns NULL if not enough space is available
 * on success, block size will be:
 *      as close to max_size as possible;
 *	within [min_size, max_size];
 *	a multiple of min_size if min_size is non-zero
 */
static char *
memChunkGetBlock(MemChunk *chunk, size_t min_size, size_t max_size, size_t *act_size)
{
    const size_t free_size = chunk->capacity - chunk->used_size;
    if (min_size <= free_size) {
	char *block = chunk->buf + chunk->used_size;
	*act_size = (max_size <= free_size) ?
	    max_size :
	    ((min_size > 0) ? 
		min_size*(free_size/min_size) :
		free_size);
	chunk->used_size += *act_size;
	return block;
    }
    *act_size = 0;
    return NULL;
}

void
memReportTotals(StoreEntry *e)
{
    storeAppendPrintf(e, "Dynamic Malloc In Use   %7.2f MB           High Water %7.2f MB\n",
	toMB(mem_dyn_size), toMB(mem_dyn_size_hwater));
    storeAppendPrintf(e, "Pools In Use            %7.2f MB (%6.2f%%) High Water %7.2f MB\n",
	toMB(mem_size_used), xpercent(mem_size_used, mem_size), toMB(mem_size_used_hwater));
    storeAppendPrintf(e, "Fragmentation           %7.2f MB (%6.2f%%) #Chunks    %7d\n",
	toMB(mem_lost_size), xpercent(mem_lost_size, mem_size), Chunks.count);
    storeAppendPrintf(e, "Total Pools Allocated   %7.2f MB           Limit      %7.2f MB\n",
	toMB(mem_size), toMB(mem_max_size));
}
