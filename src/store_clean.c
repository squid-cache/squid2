/*
 * $Id$
 *
 * DEBUG: section 36    Cache Directory Cleanup
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#if HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)
#else /* HAVE_DIRENT_H */
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#if HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif /* HAVE_SYS_NDIR_H */
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif /* HAVE_SYS_DIR_H */
#if HAVE_NDIR_H
#include <ndir.h>
#endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */

void storeDirClean()
{
    static int index = 0;
    static DIR *dp = NULL;
    struct dirent *de = NULL;
    static char p2[MAXPATHLEN + 1];
    static char p1[MAXPATHLEN + 1];
    int fileno;
    static int count;
    int n = 0;
    sprintf(p1, "%s/%02d",
	swappath(index),
	(index / ncache_dirs) % SWAP_DIRECTORIES);
    debug(36, 3, "storeDirClean: Cleaning directory %s\n", p1);
    if (dp == NULL) {
	count = 0;
	dp = opendir(p1);
	if (dp == NULL) {
	    debug(36, 0, "storeDirClean: %s: %s\n", p1, xstrerror());
	    fatal_dump(NULL);
	}
    }
    while ((de = readdir(dp)) && n < 10) {
	if (sscanf(de->d_name, "%d", &fileno) != 1)
	    continue;
	if (file_map_bit_test(fileno))
	    continue;
	sprintf(p2, "%s/%s", p1, de->d_name);
	debug(36, 3, "storeDirClean: Cleaning file %d\n", fileno);
	if (safeunlink(p2, 0) == 0)
	    count++, n++;
    }
    if (de == NULL) {
	debug(36, count ? 1 : 3, "Cleaned %d unused files from %s\n",
	    count, p1);
	closedir(dp);
	dp = NULL;
	index++;
    }
}
