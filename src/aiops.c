
/*
 * $Id$
 *
 * DEBUG: section 43    AIOPS
 * AUTHOR: Stewart Forster <slf@connect.com.au>
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

#if USE_ASYNC_IO

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<pthread.h>
#include	<errno.h>
#include	<dirent.h>
#include	"aiops.h"

#define	MAXTHREADS	1024

#define _THREAD_FREE	0
#define _THREAD_DOING	1
#define _THREAD_DONE	2

#define _AIO_OP_OPEN	0
#define _AIO_OP_READ	1
#define _AIO_OP_WRITE	2
#define _AIO_OP_CLOSE	3
#define _AIO_OP_UNLINK	4
#define _AIO_OP_OPENDIR	5
#define _AIO_OP_STAT	6

typedef struct aio_thread_t {
    pthread_t thread;
    int status;
    int operation;
    aio_result_t *resultp;
    void *aiodp;
    struct aio_thread_t *next;
} aio_thread_t;


typedef struct aioopen_d {
    char *path;
    int oflag;
    mode_t mode;
} aio_open_d;


typedef struct aio_write_d {
    int fd;
    char *bufp;
    int bufs;
    off_t offset;
    int whence;
} aio_write_d;


typedef struct aio_read_d {
    int fd;
    char *bufp;
    int bufs;
    off_t offset;
    int whence;
} aio_read_d;


typedef struct aio_close_d {
    int fd;
} aio_close_d;


typedef struct aio_stat_d {
    char *path;
    struct stat *sb;
} aio_stat_d;


typedef struct aio_unlink_d {
    char *path;
} aio_unlink_d;


typedef struct aio_opendir_d {
    char *path;
} aio_opendir_d;

int aio_cancel(aio_result_t *);
int aio_open(const char *, int, mode_t, aio_result_t *);
int aio_read(int, char *, int, off_t, int, aio_result_t *);
int aio_write(int, char *, int, off_t, int, aio_result_t *);
int aio_close(int, aio_result_t *);
int aio_unlink(const char *, aio_result_t *);
int aio_opendir();
aio_result_t *aio_poll_done();

static int aio_init();
static aio_thread_t *aio_alloc_thread(aio_result_t *);
static void aio_free_thread(aio_thread_t *);
static void aio_cleanup_and_free(aio_thread_t *);
static void *aio_thread_open(void *);
static void *aio_thread_read(void *);
static void *aio_thread_write(void *);
static void *aio_thread_close(void *);
static void *aio_thread_stat(void *);
static void *aio_thread_unlink(void *);
static void *aio_thread_opendir(void *);
static void aio_debug(aio_thread_t *);

static aio_thread_t thread[MAXTHREADS];
static int aio_initialised = 0;

static aio_thread_t *free_threads = NULL;
static aio_thread_t *used_threads = NULL;
static aio_thread_t *tail_threads = NULL;

static int
aio_init()
{
    static int init = 0;
    int i;

    if (aio_initialised)
	return;
    for (i = 0; i < MAXTHREADS; i++) {
	thread[i].next = free_threads;
	free_threads = thread + i;
    }
    aio_initialised = 1;
}


static aio_thread_t *
aio_alloc_thread(aio_result_t * resultp)
{
    aio_thread_t *threadp;

    if (free_threads == NULL) {
	errno = EAGAIN;
	return NULL;
    }
    for (threadp = used_threads; threadp != NULL; threadp = threadp->next)
	if (threadp->resultp == resultp)
	    break;
    if (threadp != NULL) {
	errno = EINVAL;
	return NULL;
    }
    threadp = free_threads;
    free_threads = threadp->next;

    if (tail_threads == NULL)
	used_threads = threadp;
    else
	tail_threads->next = threadp;
    tail_threads = threadp;

    threadp->status = _THREAD_DOING;
    threadp->resultp = NULL;
    threadp->next = NULL;
    return threadp;
}


static void
aio_free_thread(aio_thread_t * threadp)
{
    aio_thread_t *c;

    if (threadp == NULL)
	return;
    if (used_threads == NULL)
	return;
    if (used_threads == threadp) {
	if ((used_threads = threadp->next) == NULL)
	    tail_threads = NULL;
    } else {
	for (c = used_threads; c != NULL && c->next != threadp; c = c->next);
	if (c == NULL)
	    return;
	if ((c->next = threadp->next) == NULL)
	    tail_threads = c;
    }
    threadp->next = free_threads;
    free_threads = threadp;
}


static void
aio_cleanup_and_free(aio_thread_t * threadp)
{
    aio_open_d *od;
    aio_unlink_d *ud;
    aio_opendir_d *odd;
    aio_stat_d *sd;

    switch (threadp->operation) {
    case _AIO_OP_OPEN:
	od = (aio_open_d *) threadp->aiodp;
	free(od->path);
	break;
    case _AIO_OP_UNLINK:
	ud = (aio_unlink_d *) threadp->aiodp;
	free(ud->path);
	break;
    case _AIO_OP_STAT:
	sd = (aio_stat_d *) threadp->aiodp;
	free(sd->path);
	break;
    case _AIO_OP_OPENDIR:
	odd = (aio_opendir_d *) threadp->aiodp;
	free(odd->path);
	break;
    default:
	break;
    }
    free(threadp->aiodp);
    aio_free_thread(threadp);
}


int
aio_cancel(aio_result_t * resultp)
{
    aio_thread_t *threadp;
    int ret;

    for (threadp = used_threads; threadp != NULL; threadp = threadp->next);
    if (threadp == NULL) {
	errno = ENOENT;
	return -1;
    }
    ret = pthread_cancel(threadp->thread);
    aio_cleanup_and_free(threadp);
    return ret;
}


int
aio_open(const char *path, int oflag, mode_t mode, aio_result_t * resultp)
{
    aio_open_d *aiodp;
    aio_thread_t *threadp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((threadp = aio_alloc_thread(resultp)) == NULL)
	return -1;
    if ((aiodp = (aio_open_d *) malloc(sizeof(aio_open_d))) == NULL) {
	aio_free_thread(threadp);
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((aiodp->path = (char *) malloc(len)) == NULL) {
	aio_free_thread(threadp);
	free(aiodp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(aiodp->path, path, len);
    aiodp->oflag = oflag;
    aiodp->mode = mode;
    threadp->aiodp = aiodp;
    threadp->resultp = resultp;
    threadp->operation = _AIO_OP_OPEN;
    if (pthread_create(&(threadp->thread), NULL, aio_thread_open, threadp) < 0) {
	free(aiodp->path);
	free(aiodp);
	aio_free_thread(threadp);
	return -1;
    }
    return 0;
}


static void *
aio_thread_open(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_open_d *aiodp;

    aiodp = (aio_open_d *) threadp->aiodp;
    threadp->resultp->aio_return = open(aiodp->path, aiodp->oflag, aiodp->mode);
    threadp->resultp->aio_errno = errno;
    threadp->status = _THREAD_DONE;
}


int
aio_read(int fd, char *bufp, int bufs, off_t offset, int whence, aio_result_t * resultp)
{
    aio_read_d *aiodp;
    aio_thread_t *threadp;

    if (!aio_initialised)
	aio_init();
    if ((threadp = aio_alloc_thread(resultp)) == NULL)
	return -1;
    if ((aiodp = (aio_read_d *) malloc(sizeof(aio_read_d))) == NULL) {
	aio_free_thread(threadp);
	errno = ENOMEM;
	return -1;
    }
    aiodp->fd = fd;
    aiodp->bufp = bufp;
    aiodp->bufs = bufs;
    aiodp->offset = offset;
    aiodp->whence = whence;
    threadp->aiodp = aiodp;
    threadp->resultp = resultp;
    threadp->operation = _AIO_OP_READ;
    if (pthread_create(&(threadp->thread), NULL, aio_thread_read, threadp) < 0) {
	free(aiodp);
	aio_free_thread(threadp);
	return -1;
    }
    return 0;
}


static void *
aio_thread_read(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_read_d *aiodp;

    aiodp = (aio_read_d *) threadp->aiodp;
    lseek(aiodp->fd, aiodp->offset, aiodp->whence);
    threadp->resultp->aio_return = read(aiodp->fd, aiodp->bufp, aiodp->bufs);
    threadp->resultp->aio_errno = errno;
    threadp->status = _THREAD_DONE;
}


int
aio_write(int fd, char *bufp, int bufs, off_t offset, int whence, aio_result_t * resultp)
{
    aio_write_d *aiodp;
    aio_thread_t *threadp;

    if (!aio_initialised)
	aio_init();
    if ((threadp = aio_alloc_thread(resultp)) == NULL)
	return -1;
    if ((aiodp = (aio_write_d *) malloc(sizeof(aio_write_d))) == NULL) {
	aio_free_thread(threadp);
	errno = ENOMEM;
	return -1;
    }
    aiodp->fd = fd;
    aiodp->bufp = bufp;
    aiodp->bufs = bufs;
    aiodp->offset = offset;
    aiodp->whence = whence;
    threadp->aiodp = aiodp;
    threadp->resultp = resultp;
    threadp->operation = _AIO_OP_WRITE;
    if (pthread_create(&(threadp->thread), NULL, aio_thread_write, threadp) < 0) {
	free(aiodp);
	aio_free_thread(threadp);
	return -1;
    }
    return 0;
}


static void *
aio_thread_write(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_write_d *aiodp;

    aiodp = (aio_write_d *) threadp->aiodp;
    threadp->resultp->aio_return = write(aiodp->fd, aiodp->bufp, aiodp->bufs);
    threadp->resultp->aio_errno = errno;
    threadp->status = _THREAD_DONE;
}


int
aio_close(int fd, aio_result_t * resultp)
{
    aio_close_d *aiodp;
    aio_thread_t *threadp;

    if (!aio_initialised)
	aio_init();
    if ((threadp = aio_alloc_thread(resultp)) == NULL)
	return -1;
    if ((aiodp = (aio_close_d *) malloc(sizeof(aio_close_d))) == NULL) {
	aio_free_thread(threadp);
	errno = ENOMEM;
	return -1;
    }
    aiodp->fd = fd;
    threadp->aiodp = aiodp;
    threadp->resultp = resultp;
    threadp->operation = _AIO_OP_CLOSE;
    if (pthread_create(&(threadp->thread), NULL, aio_thread_close, threadp) < 0) {
	free(aiodp);
	aio_free_thread(threadp);
	return -1;
    }
    return 0;
}


static void *
aio_thread_close(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_close_d *aiodp;

    aiodp = (aio_close_d *) threadp->aiodp;
    threadp->resultp->aio_return = close(aiodp->fd);
    threadp->resultp->aio_errno = errno;
    threadp->status = _THREAD_DONE;
}


int
aio_stat(const char *path, struct stat *sb, aio_result_t * resultp)
{
    aio_stat_d *aiodp;
    aio_thread_t *threadp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((threadp = aio_alloc_thread(resultp)) == NULL)
	return -1;
    if ((aiodp = (aio_stat_d *) malloc(sizeof(aio_stat_d))) == NULL) {
	aio_free_thread(threadp);
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((aiodp->path = (char *) malloc(len)) == NULL) {
	aio_free_thread(threadp);
	free(aiodp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(aiodp->path, path, len);
    aiodp->sb = sb;
    threadp->aiodp = aiodp;
    threadp->resultp = resultp;
    threadp->operation = _AIO_OP_STAT;
    if (pthread_create(&(threadp->thread), NULL, aio_thread_stat, threadp) < 0) {
	free(aiodp->path);
	free(aiodp);
	aio_free_thread(threadp);
	return -1;
    }
    return 0;
}


static void *
aio_thread_stat(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_stat_d *aiodp;

    aiodp = (aio_stat_d *) threadp->aiodp;
    threadp->resultp->aio_return = stat(aiodp->path, aiodp->sb);
    threadp->resultp->aio_errno = errno;
    threadp->status = _THREAD_DONE;
}


int
aio_unlink(const char *path, aio_result_t * resultp)
{
    aio_unlink_d *aiodp;
    aio_thread_t *threadp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((threadp = aio_alloc_thread(resultp)) == NULL)
	return -1;
    if ((aiodp = (aio_unlink_d *) malloc(sizeof(aio_unlink_d))) == NULL) {
	aio_free_thread(threadp);
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((aiodp->path = (char *) malloc(len)) == NULL) {
	aio_free_thread(threadp);
	free(aiodp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(aiodp->path, path, len);
    threadp->aiodp = aiodp;
    threadp->resultp = resultp;
    threadp->operation = _AIO_OP_UNLINK;
    if (pthread_create(&(threadp->thread), NULL, aio_thread_unlink, threadp) < 0) {
	free(aiodp->path);
	free(aiodp);
	aio_free_thread(threadp);
	return -1;
    }
    return 0;
}


static void *
aio_thread_unlink(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_unlink_d *aiodp;

    aiodp = (aio_unlink_d *) threadp->aiodp;
    threadp->resultp->aio_return = unlink(aiodp->path);
    threadp->resultp->aio_errno = errno;
    threadp->status = _THREAD_DONE;
}


int
aio_opendir(const char *path, aio_result_t * resultp)
{
}


static void *
aio_thread_opendir(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
}


aio_result_t *
aio_poll_done()
{
    aio_thread_t *threadp;
    aio_result_t *resultp;

    for (threadp = used_threads; threadp != NULL; threadp = threadp->next) {
	debug(43, 3, "%d: %d -> %d\n",
	    threadp->thread,
	    threadp->operation,
	    threadp->status);
	if (threadp->status == _THREAD_DONE)
	    break;
    }
    if (threadp == NULL)
	return NULL;
    pthread_join(threadp->thread, NULL);
    resultp = threadp->resultp;
    aio_debug(threadp);
    debug(43, 3, "DONE: %d -> %d\n",
	resultp->aio_return,
	resultp->aio_errno);
    aio_cleanup_and_free(threadp);
    return resultp;
}

static void
aio_debug(aio_thread_t * threadp)
{
    aio_open_d *od;
    aio_read_d *rd;
    aio_write_d *wd;
    aio_close_d *cd;
    aio_unlink_d *ud;

    switch (threadp->operation) {
    case _AIO_OP_OPEN:
	od = (aio_open_d *) threadp->aiodp;
	debug(43, 3, "OPEN of %s to FD %d\n", od->path, threadp->resultp->aio_return);
	break;
    case _AIO_OP_READ:
	rd = (aio_read_d *) threadp->aiodp;
	debug(43, 3, "READ on fd: %d\n", rd->fd);
	break;
    case _AIO_OP_WRITE:
	wd = (aio_write_d *) threadp->aiodp;
	debug(43, 3, "WRITE on fd: %d\n", wd->fd);
	break;
    case _AIO_OP_CLOSE:
	cd = (aio_close_d *) threadp->aiodp;
	debug(43, 3, "CLOSE of fd: %d\n", cd->fd);
	break;
    case _AIO_OP_UNLINK:
	ud = (aio_unlink_d *) threadp->aiodp;
	debug(43, 3, "UNLINK of %s\n", ud->path);
	break;
    default:
	break;
    }
}

#endif /* USE_ASYNC_IO */
