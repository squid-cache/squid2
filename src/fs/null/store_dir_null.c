
/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
#if HAVE_STATVFS
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#endif

#include "store_null.h"

#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256
#define STORE_META_BUFSZ 4096

static int null_initialised = 0;
static void storeNullDirInit(SwapDir * sd);
static void storeNullDirStats(SwapDir * SD, StoreEntry * sentry);

int
storeNullDirMapBitTest(SwapDir * SD, int fn)
{
    return 1;
}

void
storeNullDirMapBitSet(SwapDir * SD, int fn)
{
    (void) 0;
}

void
storeNullDirMapBitReset(SwapDir * SD, int fn)
{
    (void) 0;
}

int
storeNullDirMapBitAllocate(SwapDir * SD)
{
    static int fn = 0;
    if (fn < 0)
	fn = 0;
    return fn++;
}

const StoreEntry *
storeNullDirCleanLogNextEntry(SwapDir * sd)
{
    return NULL;
}

int
storeNullDirValidFileno(SwapDir * SD, sfileno filn, int flag)
{
    return 1;
}

void
storeNullDirMaintain(SwapDir * SD)
{
    (void) 0;
}

int
storeNullDirCheckObj(SwapDir * SD, const StoreEntry * e)
{
    return 1;
}

void
storeNullDirRefObj(SwapDir * SD, StoreEntry * e)
{
    (void) 0;
}

void
storeNullDirUnrefObj(SwapDir * SD, StoreEntry * e)
{
    (void) 0;
}

void
storeNullDirUnlinkFile(SwapDir * SD, sfileno f)
{
    (void) 0;
}

void
storeNullDirReplAdd(SwapDir * SD, StoreEntry * e)
{
    (void) 0;
}

void
storeNullDirReplRemove(StoreEntry * e)
{
    (void) 0;
}


void
storeNullDirReconfigure(SwapDir * sd, int index, char *path)
{
    (void) 0;
}

void
storeNullDirDump(StoreEntry * entry, const char *name, SwapDir * s)
{
    storeAppendPrintf(entry, "%s null\n", name);
}


void
storeNullDirParse(SwapDir * sd, int index, char *path)
{
    sd->index = index;
    sd->path = xstrdup(path);
    sd->statfs = storeNullDirStats;
    sd->init = storeNullDirInit;
}

void
storeNullDirDone(void)
{
    null_initialised = 0;
}

void
storeFsSetup_null(storefs_entry_t * storefs)
{
    assert(!null_initialised);
    storefs->parsefunc = storeNullDirParse;
    storefs->reconfigurefunc = storeNullDirReconfigure;
    storefs->donefunc = storeNullDirDone;
    null_initialised = 1;
}

/* ==== STATIC FUNCTIONS ==== */

static void
storeNullDirStats(SwapDir * SD, StoreEntry * sentry)
{
    (void) 0;
}

static void
storeNullDirInit(SwapDir * sd)
{
    (void) 0;
}
