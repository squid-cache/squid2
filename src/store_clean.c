

/*
 * $Id$
 *
 * DEBUG: section 36    Cache Directory Cleanup
 * AUTHOR: Duane Wessels
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

static QS rev_int_sort;
static char *storeCleanSubSubDir(int index, char *);

static int
rev_int_sort(const void *A, const void *B)
{
    const int *i1 = A;
    const int *i2 = B;
    return *i2 - *i1;
}

static char *
storeCleanSubSubDir(int index, char *path)
{
    int nd = Config.cacheSwap.n_configured;
    int dirn = index % nd;
    int L1 = Config.cacheSwap.swapDirs[dirn].l1;
    int L2 = Config.cacheSwap.swapDirs[dirn].l2;
    snprintf(path, SQUID_MAXPATHLEN, "%s/%02X/%02X",
	Config.cacheSwap.swapDirs[dirn].path,
	(index / nd) % L1,
	((index / nd) / L1) % L2);
    return path;
}

void
storeDirClean(void *datanotused)
{
    static int swap_index = 0;
    DIR *dp = NULL;
    struct dirent *de = NULL;
    LOCAL_ARRAY(char, p1, MAXPATHLEN + 1);
    LOCAL_ARRAY(char, p2, MAXPATHLEN + 1);
    int files[20];
    int swapfileno;
    int n = 0;
    int k = 0;
    eventAdd("storeDirClean", storeDirClean, NULL, 15);
    if (store_rebuilding)
	return;
    storeCleanSubSubDir(swap_index, p1);
    debug(36, 3) ("storeDirClean: Cleaning directory %s\n", p1);
    dp = opendir(p1);
    if (dp == NULL) {
	swap_index++;
	if (errno == ENOENT) {
	    debug(36, 0) ("storeDirClean: WARNING: Creating %s\n", p1);
	    if (mkdir(p1, 0777) == 0)
		return;
	}
	debug(50, 0) ("storeDirClean: %s: %s\n", p1, xstrerror());
	safeunlink(p1, 1);
	return;
    }
    while ((de = readdir(dp)) != NULL && k < 20) {
	if (sscanf(de->d_name, "%X", &swapfileno) != 1)
	    continue;
	if (storeDirValidFileno(swapfileno))
	    if (storeDirMapBitTest(swapfileno))
		continue;
	files[k++] = swapfileno;
    }
    closedir(dp);
    swap_index++;
    if (k == 0)
	return;
    qsort(files, k, sizeof(int), rev_int_sort);
    if (k > 10)
	k = 10;
    for (n = 0; n < k; n++) {
	debug(36, 3) ("storeDirClean: Cleaning file %08X\n", files[n]);
	snprintf(p2, MAXPATHLEN + 1, "%s/%08X", p1, files[n]);
	safeunlink(p2, 0);
    }
    debug(36, 3) ("Cleaned %d unused files from %s\n", k, p1);
}
