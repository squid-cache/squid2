
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


/* module globals */

/* huge constant to set mem_idle_limit to "unlimited" */
static const size_t mem_unlimited_size = 2 * 1024 * MB;

/* we cannot keep idle more than this limit */
static size_t mem_idle_limit = 0;

/* memory pool accounting */
static MemPoolMeter TheMeter;
static gb_t mem_traffic_volume = {0, 0};
static Stack Pools;

static double 
toMB(size_t size)
{
    return ((double) size) / MB;
}

static size_t 
toKB(size_t size)
{
    return (size + 1024 - 1) / 1024;
}


/* Initialization */

void
memConfigure()
{
    size_t new_pool_limit = mem_idle_limit;
    /* set to configured value first */
    if (!Config.onoff.mem_pools)
	new_pool_limit = 0;
    else if (Config.MemPools.limit > 0)
	new_pool_limit = Config.MemPools.limit;
    else
	new_pool_limit = mem_unlimited_size;
    /* currently, we cannot decrease current memory pool */
    if (new_pool_limit < TheMeter.idle.level) {
	debug(63, 0) ("Warning: configured mem pool limit is below current consumpion.\n");
	debug(63, 0) ("         seting limit[MB] to %.2f instead of %.2f, was %.2f.\n",
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
    int i;
    int dirty_count = 0;
    for (i = 0; i < Pools.count; i++) {
	MemPool *pool = Pools.items[i];
	if (memPoolInUseCount(pool)) {
	    memPoolDescribe(pool);
	    dirty_count++;
	} else {
	    memPoolDestroy(pool);
	    Pools.items[i] = NULL;
	}
    }
    if (dirty_count)
	debug(13, 2) ("memCleanModule: %d pools are left dirty\n", dirty_count);
    /* we clean the stack anyway */
    stackClean(&Pools);
}

/* MemPoolMeter */

static void
memPoolMeterReport(const MemPoolMeter * pm, size_t obj_size,
    int alloc_count, int inuse_count, int idle_count, StoreEntry * e)
{
    assert(pm);
    storeAppendPrintf(e, "%d\t %d\t %d\t %.2f\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\n",
    /* alloc */
	alloc_count,
	toKB(obj_size * pm->alloc.level),
	toKB(obj_size * pm->alloc.hwater_level),
	(double)((squid_curtime - pm->alloc.hwater_stamp)/3600.),
	xpercentInt(obj_size * pm->alloc.level, TheMeter.alloc.level),
    /* in use */
	inuse_count,
	toKB(obj_size * pm->inuse.level),
	toKB(obj_size * pm->inuse.hwater_level),
	xpercentInt(pm->inuse.level, pm->alloc.level),
    /* idle */
	idle_count,
	toKB(obj_size * pm->idle.level),
	toKB(obj_size * pm->idle.hwater_level),
    /* (int)rint(xpercent(pm->idle.level, pm->alloc.level)), */
    /* saved */
	xpercentInt(pm->saved.count, mem_traffic_volume.count),
	xpercentInt(obj_size * gb_to_double(&pm->saved), gb_to_double(&mem_traffic_volume)));
    /* (int)rint(xpercent(obj_size * pm->saved.level, mem_traffic_volume))); */
}

/* MemMeter */

void
memMeterSyncHWater(MemMeter *m)
{
    assert(m);
    if (m->hwater_level < m->level) {
	m->hwater_level = m->level;
	m->hwater_stamp = squid_curtime;
    }
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
memPoolDestroy(MemPool * pool)
{
    assert(pool);
    stackClean(&pool->pstack);
    xfree(pool);
}

void *
memPoolAlloc(MemPool * pool)
{
    assert(pool);
    memMeterInc(pool->meter.inuse);
    memMeterAdd(TheMeter.inuse, pool->obj_size);
    gb_inc(&mem_traffic_volume, pool->obj_size);
    if (pool->pstack.count) {
	assert(pool->meter.idle.level);
	memMeterDec(pool->meter.idle);
	memMeterDel(TheMeter.idle, pool->obj_size);
	gb_inc(&pool->meter.saved, 1);
	gb_inc(&TheMeter.saved, pool->obj_size);
	return stackPop(&pool->pstack);
    } else {
	assert(!pool->meter.idle.level);
	memMeterInc(pool->meter.alloc);
	memMeterAdd(TheMeter.alloc, pool->obj_size);
	return xcalloc(1, pool->obj_size);
    }
}

void
memPoolFree(MemPool * pool, void *obj)
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
memPoolWasUsed(const MemPool * pool)
{
    assert(pool);
    return pool->meter.alloc.hwater_level > 0;
}

int
memPoolInUseCount(const MemPool * pool)
{
    assert(pool);
    return pool->meter.inuse.level;
}

size_t
memPoolInUseSize(const MemPool * pool)
{
    assert(pool);
    return pool->obj_size * pool->meter.inuse.level;
}

void
memPoolDescribe(const MemPool * pool)
{
    assert(pool);
    debug(63, 1) ("%-20s: %6d x %4d bytes = %5d KB\n",
	pool->label, memPoolInUseCount(pool), pool->obj_size,
	toKB(memPoolInUseSize(pool)));
}

size_t
memTotalAllocated()
{
    return TheMeter.alloc.level;
}

void
memPoolReport(const MemPool * pool, StoreEntry * e)
{
    assert(pool);
    storeAppendPrintf(e, "%-20s\t %4d\t ",
	pool->label, pool->obj_size);
    memPoolMeterReport(&pool->meter, pool->obj_size,
	pool->meter.alloc.level, pool->meter.inuse.level, pool->meter.idle.level,
	e);
}

void
memReport(StoreEntry * e)
{
    size_t overhd_size = 0;
    int alloc_count = 0;
    int inuse_count = 0;
    int idle_count = 0;
    int i;
    /* caption */
    storeAppendPrintf(e, "Current memory usage:\n");
    /* heading */
    storeAppendPrintf(e, "Pool\t Obj Size\t"
	"Allocated\t\t\t\t\t In Use\t\t\t\t Idle\t\t\t Allocations Saved\t\t\n"
	" \t (bytes)\t"
	"(#)\t (KB)\t high (KB)\t high (hrs)\t impact (%%total)\t"
	"(#)\t (KB)\t high (KB)\t portion (%%alloc)\t"
	"(#)\t (KB)\t high (KB)\t"
	"(%%number)\t (%%volume)"
	"\n");
    /* main table */
    for (i = 0; i < Pools.count; i++) {
	const MemPool *pool = Pools.items[i];
	if (memPoolWasUsed(pool)) {
	    memPoolReport(pool, e);
	    alloc_count += pool->meter.alloc.level;
	    inuse_count += pool->meter.inuse.level;
	    idle_count += pool->meter.idle.level;
	}
	overhd_size += sizeof(MemPool) + sizeof(MemPool *) +
	    strlen(pool->label) + 1 +
	    pool->pstack.capacity * sizeof(void *);
    }
    overhd_size += sizeof(Pools) + Pools.capacity * sizeof(MemPool *);
    /* totals */
    storeAppendPrintf(e, "%-20s\t %-4s\t ", "Total", "-");
    memPoolMeterReport(&TheMeter, 1, alloc_count, inuse_count, idle_count, e);
    storeAppendPrintf(e, "Cumulative allocated volume: %s\n", gb_to_str(&mem_traffic_volume));
    /* overhead */
    storeAppendPrintf(e, "Current overhead: %d bytes (%.3f%%)\n",
	overhd_size, xpercent(overhd_size, TheMeter.inuse.level));
    /* limits */
    storeAppendPrintf(e, "Idle pool limit: %.2f MB\n", toMB(mem_idle_limit));
}
