
#include "config.h"
#include "squid.h"


#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#undef assert
#include <assert.h>

enum {
    _MQD_NOP,
    _MQD_OPEN,
    _MQD_CLOSE,
    _MQD_READ,
    _MQD_WRITE,
    _MQD_UNLINK
};

typedef struct _diomsg {
    long mtype;
    int id;
    void *callback_data;
    int size;
    int offset;
    int status;
    int shm_offset;
} diomsg;


#if DISKD_DAEMON

#define STDERR_DEBUG 0

typedef struct _file_state file_state;

struct _file_state {
    void *key;
    file_state *next;
    int id;
    int fd;
    off_t offset;
};

static hash_table *hash = NULL;
static pid_t mypid;
static char *shmbuf;

static int
do_open(diomsg * r, int len, const char *buf)
{
    int fd;
    file_state *fs;
    /*
     * note r->offset holds open() flags
     */
    fd = open(buf, r->offset, 0600);
    if (fd < 0) {
	fprintf(stderr, "%d %p: ", mypid, buf);
	perror("open");
	return -errno;
    }
    fs = xcalloc(1, sizeof(*fs));
    fs->id = r->id;
    fs->key = &fs->id;		/* gack */
    fs->fd = fd;
    hash_join(hash, (hash_link *) fs);
#if STDERR_DEBUG
    fprintf(stderr, "%d OPEN  id %d, FD %d, fs %p\n",
	(int) mypid,
	fs->id,
	fs->fd,
	fs);
#endif
    return fd;
}

static int
do_close(diomsg * r, int len)
{
    int fd;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);
    if (NULL == fs) {
	errno = EBADF;
	fprintf(stderr, "%d CLOSE id %d: ", (int) mypid, r->id);
	perror("do_close");
	return -EBADF;
    }
    fd = fs->fd;
    hash_remove_link(hash, (hash_link *) fs);
#if STDERR_DEBUG
    fprintf(stderr, "%d CLOSE id %d, FD %d, fs %p\n",
	(int) mypid,
	r->id,
	fs->fd,
	fs);
#endif
    xfree(fs);
    return close(fd);
}

static int
do_read(diomsg * r, int len, char *buf)
{
    int x;
    int readlen = r->size;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);
    if (NULL == fs) {
	errno = EBADF;
	fprintf(stderr, "%d READ  id %d: ", (int) mypid, r->id);
	perror("do_read");
	return -EBADF;
    }
    if (r->offset > -1 && r->offset != fs->offset) {
#if STDERR_DEBUG
	fprintf(stderr, "seeking to %d\n", r->offset);
#endif
	if (lseek(fs->fd, r->offset, SEEK_SET) < 0) {
	    fprintf(stderr, "%d FD %d, offset %d: ", mypid, fs->fd, r->offset);
	    perror("lseek");
	}
    }
    x = read(fs->fd, buf, readlen);
#if STDERR_DEBUG
    fprintf(stderr, "%d READ %d,%d,%d ret %d\n", (int) mypid,
	fs->fd, readlen, r->offset, x);
#endif
    if (x < 0) {
	fprintf(stderr, "%d FD %d: ", mypid, fs->fd);
	perror("read");
	return -errno;
    }
    fs->offset = r->offset + x;
    return x;
}

static int
do_write(diomsg * r, int len, const char *buf)
{
    int wrtlen = r->size;
    int x;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);
    if (NULL == fs) {
	errno = EBADF;
	fprintf(stderr, "%d WRITE id %d: ", (int) mypid, r->id);
	perror("do_write");
	return -EBADF;
    }
    if (r->offset > -1 && r->offset != fs->offset) {
	if (lseek(fs->fd, r->offset, SEEK_SET) < 0) {
	    fprintf(stderr, "%d FD %d, offset %d: ", mypid, fs->fd, r->offset);
	    perror("lseek");
	}
    }
#if STDERR_DEBUG
    fprintf(stderr, "%d WRITE %d,%d,%d\n", (int) mypid,
	fs->fd, wrtlen, r->offset);
#endif
    x = write(fs->fd, buf, wrtlen);
    if (x < 0) {
	fprintf(stderr, "%d FD %d: ", mypid, fs->fd);
	perror("write");
	return -errno;
    }
    fs->offset = r->offset + x;
    return x;
}

static int
do_unlink(diomsg * r, int len, const char *buf)
{
    if (unlink(buf) < 0) {
	fprintf(stderr, "%d UNLNK id %d: ", (int) mypid, r->id);
	perror("unlink");
	return -errno;
    }
#if STDERR_DEBUG
    fprintf(stderr, "%d UNLNK %s\n", (int) mypid, buf);
#endif
    return 0;
}

static void
msg_handle(diomsg * r, int rl, diomsg * s)
{
    char *buf = NULL;
    s->mtype = r->mtype;
    s->callback_data = r->callback_data;
    s->shm_offset = r->shm_offset;
    if (s->shm_offset > -1)
	buf = shmbuf + s->shm_offset;
    switch (r->mtype) {
    case _MQD_OPEN:
	s->status = do_open(r, rl, buf);
	break;
    case _MQD_CLOSE:
	s->status = do_close(r, rl);
	break;
    case _MQD_READ:
	s->status = do_read(r, rl, buf);
	break;
    case _MQD_WRITE:
	s->status = do_write(r, rl, buf);
	break;
    case _MQD_UNLINK:
	s->status = do_unlink(r, rl, buf);
	break;
    default:
	assert(0);
	break;
    }
}

int
fsCmp(const void *a, const void *b)
{
    const int *A = a;
    const int *B = b;
    return *A != *B;
}

unsigned int
fsHash(const void *key, unsigned int n)
{
    /* note, n must be a power of 2! */
    const int *k = key;
    return (*k & (--n));
}

static void
alarm_handler(int sig)
{
    (void) 0;
}

int
main(int argc, char *argv[])
{
    int key;
    int rmsgid;
    int smsgid;
    int shmid;
    diomsg rmsg;
    diomsg smsg;
    int rlen;
    char rbuf[512];
    struct sigaction sa;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    mypid = getpid();
    assert(4 == argc);
    key = atoi(argv[1]);
    rmsgid = msgget(key, 0600);
    if (rmsgid < 0) {
	perror("msgget");
	return 1;
    }
    key = atoi(argv[2]);
    smsgid = msgget(key, 0600);
    if (smsgid < 0) {
	perror("msgget");
	return 1;
    }
    key = atoi(argv[3]);
    shmid = shmget(key, 0, 0600);
    if (shmid < 0) {
	perror("shmget");
	return 1;
    }
    shmbuf = shmat(shmid, NULL, 0);
    if (shmbuf == (void *) -1) {
	perror("shmat");
	return 1;
    }
    hash = hash_create(fsCmp, 1 << 4, fsHash);
    assert(hash);
    fcntl(0, F_SETFL, SQUID_NONBLOCK);
    memset(&sa, '\0', sizeof(sa));
    sa.sa_handler = alarm_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);
    for (;;) {
	alarm(1);
	rlen = msgrcv(rmsgid, &rmsg, sizeof(rmsg), 0, 0);
	if (rlen < 0) {
	    if (EINTR == errno) {
		if (read(0, rbuf, 512) <= 0) {
		    if (EWOULDBLOCK == errno)
			(void) 0;
		    else if (EAGAIN == errno)
			(void) 0;
		    else
			break;
		}
	    }
	    if (EAGAIN == errno) {
		continue;
	    }
	    perror("msgrcv");
	    break;
	}
	alarm(0);
	msg_handle(&rmsg, rlen, &smsg);
	if (msgsnd(smsgid, &smsg, sizeof(smsg), 0) < 0) {
	    perror("msgsnd");
	    break;
	}
    }
#if STDERR_DEBUG
    fprintf(stderr, "%d diskd exiting\n", (int) mypid);
#endif
    if (msgctl(rmsgid, IPC_RMID, 0) < 0)
	perror("msgctl IPC_RMID");
    if (msgctl(smsgid, IPC_RMID, 0) < 0)
	perror("msgctl IPC_RMID");
    if (shmdt(shmbuf) < 0)
	perror("shmdt");
    if (shmctl(shmid, IPC_RMID, 0) < 0)
	perror("shmctl IPC_RMID");
    return 0;
}

#elif USE_DISKD

/*
 * DEBUG 79
 */

static int sent_count = 0;
static int recv_count = 0;
static int shmbuf_count = 0;
static int sio_id = 0;

static int storeDiskdSend(int, SwapDir *, int, storeIOState *, int, int, int);
static void storeDiskdShmPut(SwapDir *, int);
static void *storeDiskdShmGet(SwapDir *, int *);
static void storeDiskdHandle(diomsg * M, SwapDir *);
static void storeDiskdIOCallback(storeIOState * sio, int errflag);
static void storeDiskdReadIndividualQueue(SwapDir * sd);
static SwapDir *swapDirFromFileno(sfileno f);

/*
 * MAGIC1 = (256/2)/(ndisks=6) ~= 22
 */
#define MAGIC1 40
/*
 * MAGIC2 = (256 * 3 / 4) / 6 = 32
 */
#define MAGIC2 48

#define SHMBUFS 64
#define SHMBUF_BLKSZ DISK_PAGE_SIZE

/* === PUBLIC =========================================================== */

storeIOState *
storeDiskdOpen(sfileno f, mode_t mode, STIOCB * callback, void *callback_data)
{
    int x;
    storeIOState *sio;
    char *buf;
    int shm_offset;
    SwapDir *sd = swapDirFromFileno(f);
    debug(78, 3) ("storeDiskdOpen: fileno %08X, mode %d\n", f, mode);
    if (sd->u.diskd.away > MAGIC1)
	return NULL;
    assert(mode == O_RDONLY || mode == O_WRONLY);
    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, memFree, MEM_STORE_IO);
    sio->swap_file_number = f;
    sio->mode = mode;
    sio->callback = callback;
    sio->callback_data = callback_data;
    sio->type.diskd.id = sio_id++;
    if (mode == O_WRONLY)
	mode |= (O_CREAT | O_TRUNC);
    buf = storeDiskdShmGet(sd, &shm_offset);
    storeUfsFullPath(f, buf);
    x = storeDiskdSend(_MQD_OPEN,
	sd,
	sio->type.diskd.id,
	sio,
	strlen(buf) + 1,
	mode,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend OPEN: %s\n", xstrerror());
	storeDiskdShmPut(sd, shm_offset);
	cbdataFree(sio);
	return NULL;
    }
    return sio;
}

void
storeDiskdClose(storeIOState * sio)
{
    int x;
    debug(78, 3) ("storeDiskdClose: fileno %08X\n", sio->swap_file_number);
    x = storeDiskdSend(_MQD_CLOSE,
	swapDirFromFileno(sio->swap_file_number),
	sio->type.diskd.id,
	sio,
	0,
	0,
	-1);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend CLOSE: %s\n", xstrerror());
	storeDiskdIOCallback(sio, errno);
    }
}

void
storeDiskdRead(storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    int x;
    int shm_offset;
    char *rbuf;
    SwapDir *sd = swapDirFromFileno(sio->swap_file_number);
    if (!cbdataValid(sio))
	return;
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = callback_data;
    sio->type.diskd.read_buf = buf;	/* the one passed from above */
    cbdataLock(callback_data);
    debug(78, 3) ("storeDiskdRead: fileno %08X\n", sio->swap_file_number);
    sio->offset = offset;
    sio->type.diskd.flags.reading = 1;
    rbuf = storeDiskdShmGet(sd, &shm_offset);
    assert(rbuf);
    x = storeDiskdSend(_MQD_READ,
	sd,
	sio->type.diskd.id,
	sio,
	(int) size,
	(int) offset,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend READ: %s\n", xstrerror());
	storeDiskdShmPut(sd, shm_offset);
	storeDiskdIOCallback(sio, errno);
    }
}

void
storeDiskdWrite(storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    int x;
    char *sbuf;
    int shm_offset;
    SwapDir *sd = swapDirFromFileno(sio->swap_file_number);
    debug(78, 3) ("storeDiskdWrite: fileno %08X\n", sio->swap_file_number);
    if (!cbdataValid(sio)) {
	free_func(buf);
	return;
    }
    sio->type.diskd.flags.writing = 1;
    sbuf = storeDiskdShmGet(sd, &shm_offset);
    xmemcpy(sbuf, buf, size);
    free_func(buf);
    x = storeDiskdSend(_MQD_WRITE,
	sd,
	sio->type.diskd.id,
	sio,
	(int) size,
	(int) offset,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend WRITE: %s\n", xstrerror());
	storeDiskdShmPut(sd, shm_offset);
	storeDiskdIOCallback(sio, errno);
    }
}

void
storeDiskdUnlink(sfileno f)
{
    int x;
    int shm_offset;
    char *buf;
    SwapDir *sd = swapDirFromFileno(f);
    debug(78, 3) ("storeDiskdUnlink: fileno %08X\n", f);
    buf = storeDiskdShmGet(sd, &shm_offset);
    storeUfsFullPath(f, buf);
    x = storeDiskdSend(_MQD_UNLINK,
	sd,
	f,
	NULL,
	0,
	0,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend UNLINK: %s\n", xstrerror());
	unlink(buf);
	storeDiskdShmPut(sd, shm_offset);
    }
}

void
storeDiskdInit(SwapDir * sd)
{
    int x;
    int i;
    int rfd;
    int ikey = (getpid() << 16) + (sd->index << 4);
    char *args[5];
    char skey1[32];
    char skey2[32];
    char skey3[32];
    storeUfsDirInit(sd);
    sd->u.diskd.smsgid = msgget((key_t) ikey, 0700 | IPC_CREAT);
    if (sd->u.diskd.smsgid < 0) {
	debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
	fatal("msgget failed");
    }
    sd->u.diskd.rmsgid = msgget((key_t) (ikey + 1), 0700 | IPC_CREAT);
    if (sd->u.diskd.rmsgid < 0) {
	debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
	fatal("msgget failed");
    }
    sd->u.diskd.shm.id = shmget((key_t) (ikey + 2),
	SHMBUFS * SHMBUF_BLKSZ, 0600 | IPC_CREAT);
    if (sd->u.diskd.shm.id < 0) {
	debug(50, 0) ("storeDiskdInit: shmget: %s\n", xstrerror());
	fatal("shmget failed");
    }
    sd->u.diskd.shm.buf = shmat(sd->u.diskd.shm.id, NULL, 0);
    if (sd->u.diskd.shm.buf == (void *) -1) {
	debug(50, 0) ("storeDiskdInit: shmat: %s\n", xstrerror());
	fatal("shmat failed");
    }
    for (i = 0; i < SHMBUFS; i++) {
	storeDiskdShmPut(sd, i * SHMBUF_BLKSZ);
	shmbuf_count++;
    }
    snprintf(skey1, 32, "%d", ikey);
    snprintf(skey2, 32, "%d", ikey + 1);
    snprintf(skey3, 32, "%d", ikey + 2);
    args[0] = "diskd";
    args[1] = skey1;
    args[2] = skey2;
    args[3] = skey3;
    args[4] = NULL;
#if HAVE_POLL && defined(_SQUID_OSF_)
    /* pipes and poll() don't get along on DUNIX -DW */
    x = ipcCreate(IPC_TCP_SOCKET,
#else
    x = ipcCreate(IPC_FIFO,
#endif
	"/usr/local/squid/bin/diskd",
	args,
	"diskd",
	&rfd,
	&sd->u.diskd.wfd);
    if (x < 0)
	fatal("execl /usr/local/squid/bin/diskd failed");
    if (rfd != sd->u.diskd.wfd)
	comm_close(rfd);
    fd_note(sd->u.diskd.wfd, "squid -> diskd");
    commSetTimeout(sd->u.diskd.wfd, -1, NULL, NULL);
    commSetNonBlocking(sd->u.diskd.wfd);
    debug(79, 1) ("diskd started\n");
}

void
storeDiskdReadQueue(void)
{
    SwapDir *sd;
    int i;
    static time_t last_report = 0;
    static int record_away = 0;
    static int record_shmbuf = 0;
    if (sent_count - recv_count > record_away) {
	record_away = sent_count - recv_count;
	record_shmbuf = shmbuf_count;
    }
    if (squid_curtime - last_report > 10) {
	if (record_away)
	    debug(79, 1) ("DISKD: %d msgs away, %d shmbufs in use\n",
		record_away, record_shmbuf);
	last_report = squid_curtime;
	record_away = record_shmbuf = 0;
    }
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	sd = &Config.cacheSwap.swapDirs[i];
	if (sd->type != SWAPDIR_DISKD)
	    continue;
	storeDiskdReadIndividualQueue(sd);
    }
}


/*  === STATIC =========================================================== */

static void
storeDiskdOpenDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    Counter.syscalls.disk.opens++;
    debug(79, 3) ("storeDiskdOpenDone: fileno %08x status %d\n",
	sio->swap_file_number, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
    }
}

static void
storeDiskdCloseDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    Counter.syscalls.disk.closes++;
    debug(79, 3) ("storeDiskdCloseDone: fileno %08x status %d\n",
	sio->swap_file_number, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    storeDiskdIOCallback(sio, DISK_OK);
}

static void
storeDiskdReadDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    STRCB *callback = sio->read.callback;
    void *their_data = sio->read.callback_data;
    char *their_buf = sio->type.diskd.read_buf;
    char *sbuf;
    size_t len;
    SwapDir *sd = swapDirFromFileno(sio->swap_file_number);
    Counter.syscalls.disk.reads++;
    sio->type.diskd.flags.reading = 0;
    debug(79, 3) ("storeDiskdReadDone: fileno %08x status %d\n",
	sio->swap_file_number, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    sbuf = sd->u.diskd.shm.buf + M->shm_offset;
    len = M->status;
    xmemcpy(their_buf, sbuf, len);	/* yucky copy */
    sio->offset += len;
    assert(callback);
    assert(their_data);
    sio->read.callback = NULL;
    sio->read.callback_data = NULL;
    if (cbdataValid(their_data))
	callback(their_data, their_buf, len);
    cbdataUnlock(their_data);
}

static void
storeDiskdWriteDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    Counter.syscalls.disk.writes++;
    sio->type.diskd.flags.writing = 0;
    debug(79, 3) ("storeDiskdWriteDone: fileno %08x status %d\n",
	sio->swap_file_number, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    sio->offset += M->status;
}

static void
storeDiskdUnlinkDone(diomsg * M)
{
    debug(79, 3) ("storeDiskdUnlinkDone: fileno %08x status %d\n",
	M->id, M->status);
    Counter.syscalls.disk.unlinks++;
}

static void
storeDiskdHandle(diomsg * M, SwapDir * sd)
{
    void *data = M->callback_data;
    if (NULL == data || cbdataValid(data)) {
	switch (M->mtype) {
	case _MQD_OPEN:
	    storeDiskdOpenDone(M);
	    break;
	case _MQD_CLOSE:
	    storeDiskdCloseDone(M);
	    break;
	case _MQD_READ:
	    storeDiskdReadDone(M);
	    break;
	case _MQD_WRITE:
	    storeDiskdWriteDone(M);
	    break;
	case _MQD_UNLINK:
	    storeDiskdUnlinkDone(M);
	    break;
	default:
	    assert(0);
	    break;
	}
    } else {
	debug(79, 1) ("storeDiskdHandle: Invalid callback_data %p\n", data);
    }
    if (M->shm_offset > -1)
	storeDiskdShmPut(sd, M->shm_offset);
    cbdataUnlock(data);
}

static void
storeDiskdIOCallback(storeIOState * sio, int errflag)
{
    debug(79, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    sio->callback(sio->callback_data, errflag, sio);
    cbdataFree(sio);
}

static int
storeDiskdSend(int mtype, SwapDir * sd, int id, storeIOState * sio, int size, int offset, int shm_offset)
{
    int x;
    diomsg M;
    static int send_errors = 0;
    M.mtype = mtype;
    M.callback_data = sio;
    M.size = size;
    M.offset = offset;
    M.status = -1;
    M.shm_offset = shm_offset;
    M.id = id;
    if (sio)
	cbdataLock(sio);
    x = msgsnd(sd->u.diskd.smsgid, &M, sizeof(M), IPC_NOWAIT);
    if (0 == x) {
	sent_count++;
	sd->u.diskd.away++;
    } else {
	cbdataUnlock(sio);
	assert(++send_errors < 100);
    }
    if (sd->u.diskd.away > MAGIC2) {
	debug(79, 3) ("%d msgs away!  Trying to read queue...\n", sd->u.diskd.away);
	storeDiskdReadIndividualQueue(sd);
    }
    return x;
}

static void *
storeDiskdShmGet(SwapDir * sd, int *shm_offset)
{
    char *buf;
    buf = linklistShift(&sd->u.diskd.shm.stack);
    assert(buf);
    *shm_offset = buf - sd->u.diskd.shm.buf;
    assert(0 <= *shm_offset && *shm_offset < SHMBUFS * SHMBUF_BLKSZ);
    shmbuf_count++;
    return buf;
}

static void
storeDiskdShmPut(SwapDir * sd, int offset)
{
    char *buf;
    assert(offset >= 0);
    assert(offset < SHMBUFS * SHMBUF_BLKSZ);
    buf = sd->u.diskd.shm.buf + offset;
    linklistPush(&sd->u.diskd.shm.stack, buf);
    shmbuf_count--;
}

static void
storeDiskdReadIndividualQueue(SwapDir * sd)
{
    static diomsg M;
    int x;
    int flag;
    while (sd->u.diskd.away > 0) {
	flag = (sd->u.diskd.away > MAGIC2) ? 0 : IPC_NOWAIT;
	x = msgrcv(sd->u.diskd.rmsgid, &M, sizeof(M), 0, flag);
	if (x < 0)
	    break;
	recv_count++;
	sd->u.diskd.away--;
	storeDiskdHandle(&M, sd);
    }
}

static SwapDir *
swapDirFromFileno(sfileno f)
{
    return &Config.cacheSwap.swapDirs[f >> SWAP_DIR_SHIFT];
}

#endif
