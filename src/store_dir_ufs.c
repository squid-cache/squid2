
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

#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256

static char *storeUfsSwapSubDir(int dirn, int subdirn);
static int storeUfsCreateDirectory(const char *path, int);
static int storeUfsVerifyCacheDirs(void);
static int storeUfsVerifyDirectory(const char *path);
static void storeUfsCreateSwapSubDirs(int j);

static char *
storeUfsSwapSubDir(int dirn, int subdirn)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    SwapDir *SD;
    assert(0 <= dirn && dirn < Config.cacheSwap.n_configured);
    SD = &Config.cacheSwap.swapDirs[dirn];
    assert(0 <= subdirn && subdirn < SD->u.ufs.l1);
    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%02X",
	Config.cacheSwap.swapDirs[dirn].path,
	subdirn);
    return fullfilename;
}

/*
 * Does swapfile number 'fn' belong in cachedir #F0,
 * level1 dir #F1, level2 dir #F2?
 *
 * Don't check that (fn >> SWAP_DIR_SHIFT) == F0 because
 * 'fn' may not have the directory bits set.
 */
int
storeUfsFilenoBelongsHere(int fn, int F0, int F1, int F2)
{
    int D1, D2;
    int L1, L2;
    int filn = fn & SWAP_FILE_MASK;
    assert(F0 < Config.cacheSwap.n_configured);
    L1 = Config.cacheSwap.swapDirs[F0].u.ufs.l1;
    L2 = Config.cacheSwap.swapDirs[F0].u.ufs.l2;
    D1 = ((filn / L2) / L2) % L1;
    if (F1 != D1)
	return 0;
    D2 = (filn / L2) % L2;
    if (F2 != D2)
	return 0;
    return 1;
}

static int
storeUfsCreateDirectory(const char *path, int should_exist)
{
    int created = 0;
    struct stat st;
    getCurrentTime();
    if (0 == stat(path, &st)) {
	if (S_ISDIR(st.st_mode)) {
	    debug(20, should_exist ? 3 : 1) ("%s exists\n", path);
	} else {
	    fatalf("Swap directory %s is not a directory.", path);
	}
    } else if (0 == mkdir(path, 0755)) {
	debug(20, should_exist ? 1 : 3) ("%s created\n", path);
	created = 1;
    } else {
	fatalf("Failed to make swap directory %s: %s",
	    path, xstrerror());
    }
    return created;
}

static int
storeUfsVerifyDirectory(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) < 0) {
	debug(20, 0) ("%s: %s\n", path, xstrerror());
	return -1;
    }
    if (S_ISDIR(sb.st_mode) == 0) {
	debug(20, 0) ("%s is not a directory\n", path);
	return -1;
    }
    return 0;
}

/*
 * This function is called by storeInit().  If this returns < 0,
 * then Squid exits, complains about swap directories not
 * existing, and instructs the admin to run 'squid -z'
 */
static int
storeUfsVerifyCacheDirs(void)
{
    int i;
    int j;
    const char *path;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	path = Config.cacheSwap.swapDirs[i].path;
	if (storeUfsVerifyDirectory(path) < 0)
	    return -1;
	for (j = 0; j < Config.cacheSwap.swapDirs[i].u.ufs.l1; j++) {
	    path = storeUfsSwapSubDir(i, j);
	    if (storeUfsVerifyDirectory(path) < 0)
		return -1;
	}
    }
    return 0;
}

static void
storeUfsCreateSwapSubDirs(int j)
{
    int i, k;
    int should_exist;
    SwapDir *SD = &Config.cacheSwap.swapDirs[j];
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < SD->u.ufs.l1; i++) {
	snprintf(name, MAXPATHLEN, "%s/%02X", SD->path, i);
	if (storeUfsCreateDirectory(name, 0))
	    should_exist = 0;
	else
	    should_exist = 1;
	debug(47, 1) ("Making directories in %s\n", name);
	for (k = 0; k < SD->u.ufs.l2; k++) {
	    snprintf(name, MAXPATHLEN, "%s/%02X/%02X", SD->path, i, k);
	    storeUfsCreateDirectory(name, should_exist);
	}
    }
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
storeUfsCreateSwapDirectories(void)
{
    int i;
    const char *path = NULL;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	path = Config.cacheSwap.swapDirs[i].path;
	debug(47, 3) ("Creating swap space in %s\n", path);
	storeUfsCreateDirectory(path, 0);
	storeUfsCreateSwapSubDirs(i);
    }
}

void
storeUfsDirSwapLog(const StoreEntry * e, int op)
{
    storeSwapLogData *s = xcalloc(1, sizeof(storeSwapLogData));
    int dirn = e->swap_file_number >> SWAP_DIR_SHIFT;
    s->op = (char) op;
    s->swap_file_number = e->swap_file_number;
    s->timestamp = e->timestamp;
    s->lastref = e->lastref;
    s->expires = e->expires;
    s->lastmod = e->lastmod;
    s->swap_file_sz = e->swap_file_sz;
    s->refcount = e->refcount;
    s->flags = e->flags;
    xmemcpy(s->key, e->key, MD5_DIGEST_CHARS);
    file_write(Config.cacheSwap.swapDirs[dirn].u.ufs.swaplog_fd,
	-1,
	s,
	sizeof(storeSwapLogData),
	NULL,
	NULL,
	xfree);
}

char *
storeUfsDirSwapLogFile(int dirn, const char *ext)
{
    LOCAL_ARRAY(char, path, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, digit, 32);
    if (Config.Log.swap) {
	xstrncpy(path, Config.Log.swap, SQUID_MAXPATHLEN - 64);
	strcat(path, ".");
	snprintf(digit, 32, "%02d", dirn);
	strncat(path, digit, 3);
    } else {
	xstrncpy(path, storeSwapDir(dirn), SQUID_MAXPATHLEN - 64);
	strcat(path, "/swap.state");
    }
    if (ext)
	strncat(path, ext, 16);
    return path;
}

void
storeUfsDirOpenSwapLogs(void)
{
    int i;
    char *path;
    int fd;
    SwapDir *SD;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	path = storeDirSwapLogFile(i, NULL);
	fd = file_open(path, O_WRONLY | O_CREAT, NULL, NULL, NULL);
	if (fd < 0) {
	    debug(50, 1) ("%s: %s\n", path, xstrerror());
	    fatal("storeDirOpenSwapLogs: Failed to open swap log.");
	}
	debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", i, fd);
	SD->u.ufs.swaplog_fd = fd;
    }
}

void
storeUfsDirCloseSwapLogs(void)
{
    int i;
    SwapDir *SD;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	if (SD->u.ufs.swaplog_fd < 0)	/* not open */
	    continue;
	file_close(SD->u.ufs.swaplog_fd);
	debug(47, 3) ("Cache Dir #%d log closed on FD %d\n", i, SD->u.ufs.swaplog_fd);
	SD->u.ufs.swaplog_fd = -1;
    }
}

FILE *
storeUfsDirOpenTmpSwapLog(int dirn, int *clean_flag, int *zero_flag)
{
    char *swaplog_path = xstrdup(storeDirSwapLogFile(dirn, NULL));
    char *clean_path = xstrdup(storeDirSwapLogFile(dirn, ".last-clean"));
    char *new_path = xstrdup(storeDirSwapLogFile(dirn, ".new"));
    struct stat log_sb;
    struct stat clean_sb;
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    FILE *fp;
    int fd;
    if (stat(swaplog_path, &log_sb) < 0) {
	debug(47, 1) ("Cache Dir #%d: No log file\n", dirn);
	safe_free(swaplog_path);
	safe_free(clean_path);
	safe_free(new_path);
	return NULL;
    }
    *zero_flag = log_sb.st_size == 0 ? 1 : 0;
    /* close the existing write-only FD */
    if (SD->u.ufs.swaplog_fd >= 0)
	file_close(SD->u.ufs.swaplog_fd);
    /* open a write-only FD for the new log */
    fd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL, NULL);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", new_path, xstrerror());
	fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }
    SD->u.ufs.swaplog_fd = fd;
    /* open a read-only stream of the old log */
    fp = fopen(swaplog_path, "r");
    if (fp == NULL) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("Failed to open swap log for reading");
    }
    memset(&clean_sb, '\0', sizeof(struct stat));
    if (stat(clean_path, &clean_sb) < 0)
	*clean_flag = 0;
    else if (clean_sb.st_mtime < log_sb.st_mtime)
	*clean_flag = 0;
    else
	*clean_flag = 1;
    safeunlink(clean_path, 1);
    safe_free(swaplog_path);
    safe_free(clean_path);
    safe_free(new_path);
    return fp;
}

void
storeUfsDirCloseTmpSwapLog(int dirn)
{
    char *swaplog_path = xstrdup(storeDirSwapLogFile(dirn, NULL));
    char *new_path = xstrdup(storeDirSwapLogFile(dirn, ".new"));
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    int fd;
    file_close(SD->u.ufs.swaplog_fd);
#ifdef _SQUID_OS2_
    if (unlink(swaplog_path) < 0) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeUfsDirCloseTmpSwapLog: unlink failed");
    }
#endif
    if (rename(new_path, swaplog_path) < 0) {
	debug(50, 0) ("%s,%s: %s\n", new_path, swaplog_path, xstrerror());
	fatal("storeUfsDirCloseTmpSwapLog: rename failed");
    }
    fd = file_open(swaplog_path, O_WRONLY | O_CREAT, NULL, NULL, NULL);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeUfsDirCloseTmpSwapLog: Failed to open swap log.");
    }
    safe_free(swaplog_path);
    safe_free(new_path);
    SD->u.ufs.swaplog_fd = fd;
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", dirn, fd);
}

void
storeUfsDirStats(StoreEntry * sentry)
{
    int i;
    SwapDir *SD;
#if HAVE_STATVFS
    struct statvfs sfs;
#endif
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	storeAppendPrintf(sentry, "\n");
	storeAppendPrintf(sentry, "Store Directory #%d: %s\n", i, SD->path);
	storeAppendPrintf(sentry, "First level subdirectories: %d\n", SD->u.ufs.l1);
	storeAppendPrintf(sentry, "Second level subdirectories: %d\n", SD->u.ufs.l2);
	storeAppendPrintf(sentry, "Maximum Size: %d KB\n", SD->max_size);
	storeAppendPrintf(sentry, "Current Size: %d KB\n", SD->cur_size);
	storeAppendPrintf(sentry, "Percent Used: %0.2f%%\n",
	    100.0 * SD->cur_size / SD->max_size);
	storeAppendPrintf(sentry, "Filemap bits in use: %d of %d (%d%%)\n",
	    SD->map->n_files_in_map, SD->map->max_n_files,
	    percent(SD->map->n_files_in_map, SD->map->max_n_files));
#if HAVE_STATVFS
#define fsbtoblk(num, fsbs, bs) \
        (((fsbs) != 0 && (fsbs) < (bs)) ? \
                (num) / ((bs) / (fsbs)) : (num) * ((fsbs) / (bs)))
	if (!statvfs(SD->path, &sfs)) {
	    storeAppendPrintf(sentry, "Filesystem Space in use: %d/%d KB (%d%%)\n",
		fsbtoblk((sfs.f_blocks - sfs.f_bfree), sfs.f_frsize, 1024),
		fsbtoblk(sfs.f_blocks, sfs.f_frsize, 1024),
		percent(sfs.f_blocks - sfs.f_bfree, sfs.f_blocks));
	    storeAppendPrintf(sentry, "Filesystem Inodes in use: %d/%d (%d%%)\n",
		sfs.f_files - sfs.f_ffree, sfs.f_files,
		percent(sfs.f_files - sfs.f_ffree, sfs.f_files));
	}
#endif
	storeAppendPrintf(sentry, "Flags:");
	if (SD->flags.selected)
	    storeAppendPrintf(sentry, " SELECTED");
	if (SD->flags.read_only)
	    storeAppendPrintf(sentry, " READ-ONLY");
	storeAppendPrintf(sentry, "\n");
    }
}

/*
 *  storeDirWriteCleanLogs
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
#define CLEAN_BUF_SZ 16384
int
storeUfsDirWriteCleanLogs(int reopen)
{
    StoreEntry *e = NULL;
    int *fd;
    int n = 0;
    time_t start, stop, r;
    struct stat sb;
    char **cur;
    char **new;
    char **cln;
    int dirn;
    int N = Config.cacheSwap.n_configured;
    dlink_node *m;
    char **outbuf;
    off_t *outbufoffset;
    storeSwapLogData s;
    size_t ss = sizeof(storeSwapLogData);
    if (store_rebuilding) {
	debug(20, 1) ("Not currently OK to rewrite swap log.\n");
	debug(20, 1) ("storeDirWriteCleanLogs: Operation aborted.\n");
	return 0;
    }
    debug(20, 1) ("storeDirWriteCleanLogs: Starting...\n");
    start = squid_curtime;
    fd = xcalloc(N, sizeof(int));
    cur = xcalloc(N, sizeof(char *));
    new = xcalloc(N, sizeof(char *));
    cln = xcalloc(N, sizeof(char *));
    for (dirn = 0; dirn < N; dirn++) {
	fd[dirn] = -1;
	cur[dirn] = xstrdup(storeDirSwapLogFile(dirn, NULL));
	new[dirn] = xstrdup(storeDirSwapLogFile(dirn, ".clean"));
	cln[dirn] = xstrdup(storeDirSwapLogFile(dirn, ".last-clean"));
	unlink(new[dirn]);
	unlink(cln[dirn]);
	fd[dirn] = file_open(new[dirn],
	    O_WRONLY | O_CREAT | O_TRUNC,
	    NULL,
	    NULL,
	    NULL);
	if (fd[dirn] < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
	    continue;
	}
	debug(20, 3) ("storeDirWriteCleanLogs: opened %s, FD %d\n",
	    new[dirn], fd[dirn]);
#if HAVE_FCHMOD
	if (stat(cur[dirn], &sb) == 0)
	    fchmod(fd[dirn], sb.st_mode);
#endif
    }
    outbuf = xcalloc(N, sizeof(char *));
    outbufoffset = xcalloc(N, sizeof(*outbufoffset));
    for (dirn = 0; dirn < N; dirn++) {
	outbuf[dirn] = xcalloc(CLEAN_BUF_SZ, 1);
	outbufoffset[dirn] = 0;
    }
    for (m = store_list.tail; m; m = m->prev) {
	e = m->data;
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAPOUT_DONE)
	    continue;
	if (e->swap_file_sz <= 0)
	    continue;
	if (EBIT_TEST(e->flags, RELEASE_REQUEST))
	    continue;
	if (EBIT_TEST(e->flags, KEY_PRIVATE))
	    continue;
	if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
	    continue;
	dirn = storeDirNumber(e->swap_file_number);
	assert(dirn < N);
	if (fd[dirn] < 0)
	    continue;
	memset(&s, '\0', ss);
	s.op = (char) SWAP_LOG_ADD;
	s.swap_file_number = e->swap_file_number;
	s.timestamp = e->timestamp;
	s.lastref = e->lastref;
	s.expires = e->expires;
	s.lastmod = e->lastmod;
	s.swap_file_sz = e->swap_file_sz;
	s.refcount = e->refcount;
	s.flags = e->flags;
	xmemcpy(&s.key, e->key, MD5_DIGEST_CHARS);
	xmemcpy(outbuf[dirn] + outbufoffset[dirn], &s, ss);
	outbufoffset[dirn] += ss;
	/* buffered write */
	if (outbufoffset[dirn] + ss > CLEAN_BUF_SZ) {
	    if (write(fd[dirn], outbuf[dirn], outbufoffset[dirn]) < 0) {
		debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
		    new[dirn], xstrerror());
		debug(20, 0) ("storeDirWriteCleanLogs: Current swap logfile not replaced.\n");
		file_close(fd[dirn]);
		fd[dirn] = -1;
		unlink(new[dirn]);
		continue;
	    }
	    outbufoffset[dirn] = 0;
	}
	if ((++n & 0xFFFF) == 0) {
	    getCurrentTime();
	    debug(20, 1) ("  %7d entries written so far.\n", n);
	}
    }
    /* flush */
    for (dirn = 0; dirn < N; dirn++) {
	if (outbufoffset[dirn] == 0)
	    continue;
	if (fd[dirn] < 0)
	    continue;
	if (write(fd[dirn], outbuf[dirn], outbufoffset[dirn]) < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
		new[dirn], xstrerror());
	    debug(20, 0) ("storeDirWriteCleanLogs: Current swap logfile not replaced.\n");
	    file_close(fd[dirn]);
	    fd[dirn] = -1;
	    unlink(new[dirn]);
	    continue;
	}
	safe_free(outbuf[dirn]);
    }
    safe_free(outbuf);
    safe_free(outbufoffset);
    /*
     * You can't rename open files on Microsoft "operating systems"
     * so we have to close before renaming.
     */
    storeUfsDirCloseSwapLogs();
    /* rename */
    for (dirn = 0; dirn < N; dirn++) {
	if (fd[dirn] < 0)
	    continue;
#ifdef _SQUID_OS2_
	file_close(fd[dirn]);
	fd[dirn] = -1;
	if (unlink(cur[dirn]) < 0)
	    debug(50, 0) ("storeDirWriteCleanLogs: unlinkd failed: %s, %s\n",
		xstrerror(), cur[dirn]);
#endif
	if (rename(new[dirn], cur[dirn]) < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: rename failed: %s, %s -> %s\n",
		xstrerror(), new[dirn], cur[dirn]);
	}
    }
    if (reopen)
	storeDirOpenSwapLogs();
    stop = squid_curtime;
    r = stop - start;
    debug(20, 1) ("  Finished.  Wrote %d entries.\n", n);
    debug(20, 1) ("  Took %d seconds (%6.1f entries/sec).\n",
	r > 0 ? (int) r : 0,
	(double) n / (r > 0 ? r : 1));
    /* touch a timestamp file if we're not still validating */
    if (!store_rebuilding) {
	for (dirn = 0; dirn < N; dirn++) {
	    if (fd[dirn] < 0)
		continue;
	    file_close(file_open(cln[dirn],
		    O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL, NULL));
	}
    }
    /* close */
    for (dirn = 0; dirn < N; dirn++) {
	safe_free(cur[dirn]);
	safe_free(new[dirn]);
	safe_free(cln[dirn]);
	if (fd[dirn] < 0)
	    continue;
	file_close(fd[dirn]);
	fd[dirn] = -1;
    }
    safe_free(cur);
    safe_free(new);
    safe_free(cln);
    safe_free(fd);
    return n;
}
#undef CLEAN_BUF_SZ

void
storeUfsDirInit(void)
{
    static const char *errmsg =
    "\tFailed to verify one of the swap directories, Check cache.log\n"
    "\tfor details.  Run 'squid -z' to create swap directories\n"
    "\tif needed, or if running Squid for the first time.";
    if (storeUfsVerifyCacheDirs() < 0)
	fatal(errmsg);
    storeUfsDirOpenSwapLogs();
    storeUfsRebuildStart();
}

void
storeUfsDirParse(cacheSwap * swap)
{
    char *token;
    char *path;
    int i;
    int size;
    int l1;
    int l2;
    unsigned int read_only = 0;
    SwapDir *sd = NULL;
    if ((path = strtok(NULL, w_space)) == NULL)
	self_destruct();
    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeUfsDirParse: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeUfsDirParse: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeUfsDirParse: invalid level 2 directories value");
    if ((token = strtok(NULL, w_space)))
	if (!strcasecmp(token, "read-only"))
	    read_only = 1;
    for (i = 0; i < swap->n_configured; i++) {
	sd = swap->swapDirs + i;
	if (!strcmp(path, sd->path)) {
	    /* just reconfigure it */
	    if (size == sd->max_size)
		debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
		    path, size);
	    else
		debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
		    path, size);
	    sd->max_size = size;
	    if (sd->flags.read_only != read_only)
		debug(3, 1) ("Cache dir '%s' now %s\n",
		    path, read_only ? "Read-Only" : "Read-Write");
	    sd->flags.read_only = read_only;
	    return;
	}
    }
    allocate_new_swapdir(swap);
    sd = swap->swapDirs + swap->n_configured;
    sd->path = xstrdup(path);
    sd->max_size = size;
    sd->u.ufs.l1 = l1;
    sd->u.ufs.l2 = l2;
    sd->u.ufs.swaplog_fd = -1;
    sd->flags.read_only = read_only;
    sd->open = storeUfsOpen;
    sd->close = storeUfsClose;
    sd->read = storeUfsRead;
    sd->write = storeUfsWrite;
    sd->unlink = storeUfsUnlink;
    swap->n_configured++;
}

void
storeUfsDirDump(StoreEntry * entry, const char *name, SwapDir * s)
{
    storeAppendPrintf(entry, "%s %s %s %d %d %d\n",
	name,
	SwapDirType[s->type],
	s->path,
	s->max_size >> 10,
	s->u.ufs.l1,
	s->u.ufs.l2);
}

/*
 * Only "free" the filesystem specific stuff here
 */
void
storeUfsDirFree(SwapDir * s)
{
    if (s->u.ufs.swaplog_fd > -1) {
	file_close(s->u.ufs.swaplog_fd);
	s->u.ufs.swaplog_fd = -1;
    }
}
