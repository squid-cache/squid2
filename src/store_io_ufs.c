/*
 * DEBUG 78
 */

#include "squid.h"

#define SWAP_DIR_SHIFT 24
#define SWAP_FILE_MASK 0x00FFFFFF

static FOCB storeUfsOpenDone;
static DRCB storeUfsReadDone;
static DWCB storeUfsWriteDone;
static void storeUfsIOCallback(storeIOState * sio, int errflag);

/* === PUBLIC =========================================================== */

storeIOState *
storeUfsOpen(sfileno f, mode_t mode, STIOCB * callback, void *callback_data)
{
    char *path = storeUfsFullPath(f, NULL);
    storeIOState *sio;
    debug(78, 3) ("storeUfsOpen: fileno %08X, mode %d\n", f, mode);
    assert(mode == O_RDONLY || mode == O_WRONLY);
    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, memFree, MEM_STORE_IO);
    sio->fd = -1;
    sio->swap_file_number = f;
    sio->mode = mode;
    sio->callback = callback;
    sio->callback_data = callback_data;
    if (mode == O_WRONLY)
	mode |= (O_CREAT | O_TRUNC);
    file_open(path, mode, storeUfsOpenDone, sio, NULL);
    store_open_disk_fd++;
    return sio;
}

void
storeUfsClose(storeIOState * sio)
{
    debug(78, 3) ("storeUfsClose: fileno %08X, FD %d\n",
	sio->swap_file_number, sio->fd);
    if (sio->type.ufs.flags.reading || sio->type.ufs.flags.writing) {
        sio->type.ufs.flags.close_request = 1;
	return;
    }
    storeUfsIOCallback(sio, 0);
}

void
storeUfsRead(storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = callback_data;
    cbdataLock(callback_data);
    debug(78, 3) ("storeUfsRead: fileno %08X, FD %d\n",
	sio->swap_file_number, sio->fd);
    sio->offset = offset;
    sio->type.ufs.flags.reading = 1;
    file_read(sio->fd,
	buf,
	size,
	offset,
	storeUfsReadDone,
	sio);
}

void
storeUfsWrite(storeIOState * sio, char *buf, size_t size, off_t offset)
{
    debug(78, 3) ("storeUfsWrite: fileno %08X, FD %d\n", sio->swap_file_number, sio->fd);
    sio->type.ufs.flags.writing = 1;
    file_write(sio->fd,
	offset,
	buf,
	size,
	storeUfsWriteDone,
	sio,
	NULL);
}

void
storeUfsUnlink(sfileno f)
{
    debug(78, 3) ("storeUfsUnlink: fileno %08X\n", f);
#if USE_ASYNC_IO
    safeunlink(storeSwapFullPath(f, NULL), 1);
#else
    unlinkdUnlink(storeSwapFullPath(f, NULL));
#endif
}

/*  === STATIC =========================================================== */

static void
storeUfsOpenDone(void *my_data, int fd, int errflag)
{
    storeIOState *sio = my_data;
    struct stat sb;
    debug(78, 3) ("storeUfsOpenDone: fileno %08X, FD %d\n",
	sio->swap_file_number, fd);
    sio->type.ufs.flags.writing = 0;
    if (errflag) {
	debug(78, 3) ("storeUfsOpenDone: got failure (%d)\n", errflag);
	storeUfsIOCallback(sio, errflag);
	return;
    }
    sio->fd = fd;
    if (sio->mode == O_RDONLY)
	if (fstat(fd, &sb) == 0)
	    sio->st_size = sb.st_size;
}

static void
storeUfsReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
{
    storeIOState *sio = my_data;
    STRCB *callback = sio->read.callback;
    void *their_data = sio->read.callback_data;
    debug(78, 3) ("storeUfsReadDone: fileno %08X, FD %d, len %d\n",
	sio->swap_file_number, fd, len);
    sio->type.ufs.flags.reading = 0;
    if (errflag) {
	debug(78, 3) ("storeUfsReadDone: got failure (%d)\n", errflag);
	storeUfsIOCallback(sio, errflag);
	return;
    }
    sio->offset += len;
    assert(callback);
    assert(their_data);
    sio->read.callback = sio->read.callback_data = NULL;
    if (cbdataValid(their_data))
        callback(their_data, buf, (size_t) len, errflag);
    cbdataUnlock(their_data);
}

static void
storeUfsWriteDone(int fd, int errflag, size_t len, void *my_data)
{
    storeIOState *sio = my_data;
    debug(78, 3) ("storeUfsWriteDone: fileno %08X, FD %d, len %d\n",
	sio->swap_file_number, fd, len);
    sio->type.ufs.flags.writing = 0;
    if (errflag) {
	debug(78, 0) ("storeUfsWriteDone: got failure (%d)\n", errflag);
	storeUfsIOCallback(sio, errflag);
    }
    sio->offset += len;
    if (sio->type.ufs.flags.close_request)
        storeUfsIOCallback(sio, errflag);
}

char *
storeUfsFullPath(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int filn = fn & SWAP_FILE_MASK;
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    int L1 = SD->l1;
    int L2 = SD->l2;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X/%08X",
	Config.cacheSwap.swapDirs[dirn].path,
	((filn / L2) / L2) % L1,
	(filn / L2) % L2,
	filn);
    return fullpath;
}

static void
storeUfsIOCallback(storeIOState * sio, int errflag)
{
    debug(78, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    if (sio->fd > -1) {
        file_close(sio->fd);
        store_open_disk_fd--;
    }
    sio->callback(sio->callback_data, errflag, sio);
    cbdataFree(sio);
}
