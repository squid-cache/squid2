
/*
 * DEBUG 78
 */

#include "squid.h"

#define SWAP_DIR_SHIFT 24
#define SWAP_FILE_MASK 0x00FFFFFF

static AIOCB storeAufsReadDone;
static AIOCB storeAufsWriteDone;
static void storeAufsIOCallback(storeIOState * sio, int errflag);
static AIOCB storeAufsOpenDone;

/* === PUBLIC =========================================================== */

storeIOState *
storeAufsOpen(sfileno f, mode_t mode, STIOCB * callback, void *callback_data)
{
    char *path = storeUfsFullPath(f, NULL);
    storeIOState *sio;
    debug(78, 3) ("storeAufsOpen: fileno %08X, mode %d\n", f, mode);
    assert(mode == O_RDONLY || mode == O_WRONLY);
    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, memFree, MEM_STORE_IO);
    sio->type.aufs.fd = -1;
    sio->swap_file_number = f;
    sio->mode = mode;
    sio->callback = callback;
    sio->callback_data = callback_data;
    if (mode == O_WRONLY)
	mode |= (O_CREAT | O_TRUNC);
    aioOpen(path, mode, 0644, storeAufsOpenDone, sio);
    store_open_disk_fd++;
    Opening_FD++;
    return sio;
}

void
storeAufsClose(storeIOState * sio)
{
    debug(78, 3) ("storeAufsClose: fileno %08X, FD %d\n",
	sio->swap_file_number, sio->type.aufs.fd);
    if (sio->type.aufs.flags.reading || sio->type.aufs.flags.writing) {
	sio->type.aufs.flags.close_request = 1;
	return;
    }
    storeAufsIOCallback(sio, 0);
}

void
storeAufsRead(storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = callback_data;
    sio->type.aufs.read_buf = buf;
    cbdataLock(callback_data);
    debug(78, 3) ("storeAufsRead: fileno %08X, FD %d\n",
	sio->swap_file_number, sio->type.aufs.fd);
    sio->offset = offset;
    sio->type.aufs.flags.reading = 1;
    aioRead(sio->type.aufs.fd, offset, buf, size, storeAufsReadDone, sio);
}

void
storeAufsWrite(storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    debug(78, 3) ("storeAufsWrite: fileno %08X, FD %d\n",
	sio->swap_file_number, sio->type.aufs.fd);
    sio->type.aufs.flags.writing = 1;
    aioWrite(sio->type.aufs.fd,
	offset,
	buf,
	size,
	storeAufsWriteDone,
	sio,
	free_func);
}

void
storeAufsUnlink(sfileno f)
{
    debug(78, 3) ("storeAufsUnlink: fileno %08X\n", f);
    aioUnlink(storeUfsFullPath(f, NULL), NULL, NULL);
}

/*  === STATIC =========================================================== */

static void
storeAufsOpenDone(int unused, void *my_data, int fd, int errflag)
{
    storeIOState *sio = my_data;
    debug(78, 3) ("storeAufsOpenDone: FD %d, errflag %d\n", fd, errflag);
    Opening_FD--;
    if (errflag || fd < 0) {
	debug(78, 0) ("storeAufsOpenDone: got failure (%d)\n", errflag);
	storeAufsIOCallback(sio, errflag);
	return;
    }
    sio->type.aufs.fd = fd;
    commSetCloseOnExec(fd);
    fd_open(fd, FD_FILE, storeUfsFullPath(sio->swap_file_number, NULL));
}

static void
storeAufsReadDone(int fd, void *my_data, int len, int errflag)
{
    storeIOState *sio = my_data;
    STRCB *callback = sio->read.callback;
    void *their_data = sio->read.callback_data;
    debug(78, 3) ("storeAufsReadDone: fileno %08X, FD %d, len %d\n",
	sio->swap_file_number, fd, len);
    sio->type.aufs.flags.reading = 0;
    if (errflag) {
	debug(78, 3) ("storeAufsReadDone: got failure (%d)\n", errflag);
	storeAufsIOCallback(sio, errflag);
	return;
    }
    sio->offset += len;
    assert(callback);
    assert(their_data);
    sio->read.callback = sio->read.callback_data = NULL;
    if (cbdataValid(their_data))
	callback(their_data, sio->type.aufs.read_buf, (size_t) len);
    cbdataUnlock(their_data);
}

static void
storeAufsWriteDone(int fd, void *my_data, int len, int errflag)
{
    storeIOState *sio = my_data;
    debug(78, 3) ("storeAufsWriteDone: fileno %08X, FD %d, len %d\n",
	sio->swap_file_number, fd, len);
    sio->type.aufs.flags.writing = 0;
    if (errflag) {
	debug(78, 0) ("storeAufsWriteDone: got failure (%d)\n", errflag);
	storeAufsIOCallback(sio, errflag);
	return;
    }
    sio->offset += len;
    if (sio->type.aufs.flags.close_request)
	storeAufsIOCallback(sio, errflag);
}

static void
storeAufsIOCallback(storeIOState * sio, int errflag)
{
    debug(78, 3) ("storeAufsIOCallback: errflag=%d\n", errflag);
    if (sio->type.aufs.fd > -1) {
	aioClose(sio->type.aufs.fd);
	store_open_disk_fd--;
    }
    sio->callback(sio->callback_data, errflag, sio);
    cbdataFree(sio);
}
