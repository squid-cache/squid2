
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

#define MB ((size_t)1024*1024)


/* object to track per-action memory usage (e.g. #idle objects) */
typedef struct {
    size_t level;   /* current level */
    size_t hwater;  /* high water mark */
} MemMeter;

/* object to track per-pool memory usage (alloc = inuse+idle) */
typedef struct {
    MemMeter alloc;
    MemMeter inuse;
    MemMeter idle;
    MemMeter saved;
} MemPoolMeter;

/* a pool is a [growing] space for objects of the same size */
struct _MemPool {
    const char *label;
    size_t obj_size;
    Stack pstack;    /* stack for free pointers */
    MemPoolMeter meter;
};

/* prototypes */

/* module globals */

/* huge constant to set mem_idle_limit to "unlimited" */
static const size_t mem_unlimited_size = 2*1024*MB;

/* we cannot keep idle more than this limit */
static size_t mem_idle_limit = 0;

/* memory pool accounting */
static MemPoolMeter TheMeter;
static size_t mem_traffic_volume = 0;
static Stack Pools;

static double toMB(size_t size) { return ((double)size)/MB; }
static size_t toKB(size_t size) { return (size+1024-1)/1024; }


/* Initialization */

void
memConfigure()
{
    size_t new_pool_limit = mem_idle_limit;
    /* set to configured value first */
    if (!Config.onoff.mem_pools)
	new_pool_limit = 0;
    else
    if (Config.MemPools.limit > 0)
	new_pool_limit = Config.MemPools.limit;
    else
	new_pool_limit = mem_unlimited_size;
    /* currently, we cannot decrease current memory pool */
    if (new_pool_limit < TheMeter.idle.level) {
	debug(63, 0) ("Warning: configured mem pool limit is below current consumpion.\n");
	debug(63, 0) ("         seting limit[MB] to %.2 instead of %.2, was %.2.\n",
	    toMB(TheMeter.idle.level), toMB(new_pool_limit), toMB(mem_idle_limit));
	new_pool_limit = TheMeter.idle.level;
    }
    assert(TheMeter.idle.level <= new_pool_limit);
    mem_idle_limit = new_pool_limit;
}

void
memInitModule()
{
    memset(&TheMeter, 0, sizeof(TheMeter));
    stackInit(&Pools);
    debug(63, 1) ("Memory pools are '%s'; limit: %.2f MB\n",
	(Config.onoff.mem_pools ? "on" : "off"), toMB(mem_idle_limit));
}

void
memCleanModule()
{
    stackClean(&Pools);
}

/* MemMeter */

#define memMeterCheckHWater(m) if ((m).hwater < (m).level) (m).hwater = (m).level
#define memMeterInc(m) { (m).level++; memMeterCheckHWater(m); }
#define memMeterDec(m) { (m).level--; memMeterCheckHWater(m); }
#define memMeterAdd(m, sz) { (m).level += (sz); memMeterCheckHWater(m); }
#define memMeterDel(m, sz) { (m).level -= (sz); memMeterCheckHWater(m); }

/* MemPoolMeter */

static void
memPoolMeterReport(const MemPoolMeter *pm, size_t obj_size, 
    int alloc_count, int inuse_count, int idle_count, int saved_count, StoreEntry *e)
{
    assert(pm);
    storeAppendPrintf(e, "%d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\n",
	/* alloc */
	alloc_count,
	toKB(obj_size * pm->alloc.level),
	toKB(obj_size * pm->alloc.hwater),
	(int)rint(xpercent(obj_size * pm->alloc.level, TheMeter.alloc.level)),
	/* in use */
	inuse_count,
	toKB(obj_size * pm->inuse.level),
	toKB(obj_size * pm->inuse.hwater),
	(int)rint(xpercent(pm->inuse.level, pm->alloc.level)),
	/* idle */
	idle_count,
	toKB(obj_size * pm->idle.level),
	toKB(obj_size * pm->idle.hwater),
	/* (int)rint(xpercent(pm->idle.level, pm->alloc.level)), */
	/* saved */
	saved_count,
	(int)floor(toMB(obj_size * pm->saved.level)),
	/* (int)rint(xpercent(obj_size * pm->saved.level, TheMeter.saved.level))); */
	(int)rint(xpercent(obj_size * pm->saved.level, mem_traffic_volume)));
}


/* MemPool */

MemPool *
memPoolCreate(const char *label, size_t obj_size)
{
    MemPool *pool = xcalloc(1, sizeof(MemPool));
    assert(label && obj_size);
    pool->label = label;
    pool->obj_size = obj_size;
    stackInit(&pool->pstack);
    /* other members are set to 0 */
    stackPush(&Pools, pool);
    return pool;
}

/*
 * warning: we do not clean this entry from Pools stack assuming memPoolDestroy
 * is used at the end of the program only
 */
void
memPoolDestroy(MemPool *pool) {
    assert(pool);
    stackClean(&pool->pstack);
    xfree(pool);
}

void *
memPoolAlloc(MemPool *pool)
{
    assert(pool);
    memMeterInc(pool->meter.inuse);
    memMeterAdd(TheMeter.inuse, pool->obj_size);
    mem_traffic_volume += pool->obj_size;
    if (pool->pstack.count) {
	assert(pool->meter.idle.level);
	memMeterDec(pool->meter.idle);
	memMeterDel(TheMeter.idle, pool->obj_size);
	memMeterInc(pool->meter.saved);
	memMeterAdd(TheMeter.saved, pool->obj_size);
	return stackPop(&pool->pstack);
    } else {
	assert(!pool->meter.idle.level);
	memMeterInc(pool->meter.alloc);
	memMeterAdd(TheMeter.alloc, pool->obj_size);
	return xcalloc(1, pool->obj_size);
    }
}

void
memPoolFree(MemPool *pool, void *obj)
{
    assert(pool && obj);
    memMeterDec(pool->meter.inuse);
    memMeterDel(TheMeter.inuse, pool->obj_size);
    if (TheMeter.idle.level + pool->obj_size <= mem_idle_limit) {
	memMeterInc(pool->meter.idle);
	memMeterAdd(TheMeter.idle, pool->obj_size);
	memset(obj, 0, pool->obj_size);
	stackPush(&pool->pstack, obj);
    } else {
	memMeterDec(pool->meter.alloc);
	memMeterDel(TheMeter.alloc, pool->obj_size);
	xfree(obj);
    }
    assert(pool->meter.idle.level <= pool->meter.alloc.level);
}

int
memPoolWasUsed(const MemPool *pool)
{
    assert(pool);
    return pool->meter.alloc.hwater > 0;
}

int
memPoolInUseCount(const MemPool *pool)
{
    assert(pool);
    return pool->meter.inuse.level;
}

size_t
memPoolInUseSize(const MemPool *pool)
{
    assert(pool);
    return pool->obj_size * pool->meter.inuse.level;
}

void
memPoolDescribe(const MemPool *pool)
{
    assert(pool);
    debug(63, 0) ("%-20s: obj size: %4d used: count: %4d volume: %5d KB\n",
	pool->label, pool->obj_size,
	memPoolInUseCount(pool), memPoolInUseSize(pool));
}

void
memPoolReport(const MemPool *pool, StoreEntry *e)
{
    assert(pool);
    storeAppendPrintf(e, "%-20s\t %4d\t ",
	pool->label, pool->obj_size);
    memPoolMeterReport(&pool->meter, pool->obj_size, 
	pool->meter.alloc.level, pool->meter.inuse.level, pool->meter.idle.level, pool->meter.saved.level,
	e);
}

void
memReport(StoreEntry *e)
{
    size_t overhd_size = 0;
    int alloc_count = 0;
    int inuse_count = 0;
    int idle_count = 0;
    int saved_count = 0;
    int i;
    /* caption */
    storeAppendPrintf(e, "Current memory usage:\n");
    /* heading */
    storeAppendPrintf(e, "Pool\t Obj Size\t"
	"Alloc\t\t\t\t In Use\t\t\t\t Idle\t\t\t Alloc Saved\t\t\t\n"
	" \t (bytes)\t"
	"(#)\t (KB)\t high (KB)\t impact (%%total)\t"
	"(#)\t (KB)\t high (KB)\t portion (%%alloc)\t"
	"(#)\t (KB)\t high (KB)\t"
	"(#)\t (MB)\t impact (%%total)"
	"\n");
    /* main table */
    for (i = 0; i < Pools.count; i++) {
	const MemPool *pool = Pools.items[i];
	if (memPoolWasUsed(pool)) {
	    memPoolReport(pool, e);
	    alloc_count += pool->meter.alloc.level;
	    inuse_count += pool->meter.inuse.level;
	    idle_count += pool->meter.idle.level;
	    saved_count += pool->meter.saved.level;
	}
	overhd_size += sizeof(MemPool) + sizeof(MemPool*) +
	    strlen(pool->label)+1 +
	    pool->pstack.capacity*sizeof(void*);
    }
    overhd_size += sizeof(Pools) + Pools.capacity*sizeof(MemPool*);
    /* totals */
    storeAppendPrintf(e, "%-20s\t %-4s\t ", "Total", "-");
    memPoolMeterReport(&TheMeter, 1, alloc_count, inuse_count, idle_count, saved_count, e);
    storeAppendPrintf(e, "Cumulative traffic volume: %.2f MB\n", toMB(mem_traffic_volume));
    /* limits */
    storeAppendPrintf(e, "Configured pool limit: %.2f MB\n", toMB(mem_idle_limit));
    /* overhead */
    storeAppendPrintf(e, "Current overhead: %d bytes (%.3f%%)\n",
	overhd_size, xpercent(overhd_size, TheMeter.inuse.level));
}
