
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

#include "squid.h"

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<pthread.h>
#include	<errno.h>
#include	<dirent.h>
#include	<signal.h>

#define	NUMTHREADS		16
#define RIDICULOUS_LENGTH	4096

#define _THREAD_STARTING	0
#define _THREAD_WAITING		1
#define _THREAD_BUSY		2
#define _THREAD_FAILED		3


#define _AIO_OP_OPEN	0
#define _AIO_OP_READ	1
#define _AIO_OP_WRITE	2
#define _AIO_OP_CLOSE	3
#define _AIO_OP_UNLINK	4
#define _AIO_OP_OPENDIR	5
#define _AIO_OP_STAT	6

typedef struct aio_request_t {
    int request_type;
    int cancelled;
    char *path;
    int oflag;
    mode_t mode;
    int fd;
    char *bufferp;
    char *tmpbufp;
    int buflen;
    off_t offset;
    int whence;
    int ret;
    int err;
    struct stat *tmpstatp;
    struct stat *statp;
    aio_result_t *resultp;
    struct aio_request_t *next;
} aio_request_t;


typedef struct aio_thread_t {
    pthread_t thread;
    int status;
    pthread_mutex_t mutex;	/* Mutex for testing condition variable */
    pthread_cond_t cond;	/* Condition variable */
    struct aio_request_t *req;
    struct aio_request_t *donereq;
    struct aio_thread_t *next;
} aio_thread_t;


int aio_cancel(aio_result_t *);
int aio_open(const char *, int, mode_t, aio_result_t *);
int aio_read(int, char *, int, off_t, int, aio_result_t *);
int aio_write(int, char *, int, off_t, int, aio_result_t *);
int aio_close(int, aio_result_t *);
int aio_unlink(const char *, aio_result_t *);
int aio_opendir(const char *, aio_result_t *);
aio_result_t *aio_poll_done();

static void aio_init(void);
static void aio_free_thread(aio_thread_t *);
static void aio_cleanup_and_free(aio_thread_t *);
static void aio_queue_request(aio_request_t *);
static void aio_process_request_queue(void);
static void aio_cleanup_request(aio_request_t *);
static void *aio_thread_loop(void *);
static void aio_thread_open(aio_thread_t *);
static void aio_thread_read(aio_thread_t *);
static void aio_thread_write(aio_thread_t *);
static void aio_thread_close(aio_thread_t *);
static void aio_thread_stat(aio_thread_t *);
static void aio_thread_unlink(aio_thread_t *);
#if 0
static void *aio_thread_opendir(void *);
#endif
static void aio_debug(aio_request_t *);

static aio_thread_t thread[NUMTHREADS];
static int aio_initialised = 0;

static int request_queue_len = 0;
static aio_request_t *free_requests = NULL;
static int num_free_requests = 0;
static aio_request_t *request_queue_head = NULL;
static aio_request_t *request_queue_tail = NULL;
static aio_thread_t *wait_threads = NULL;
static aio_thread_t *busy_threads_head = NULL;
static aio_thread_t *busy_threads_tail = NULL;
static pthread_attr_t globattr;
static struct sched_param globsched;

static void
aio_init(void)
{
    int i;
    pthread_t self;
    aio_thread_t *threadp;

    if (aio_initialised)
	return;

    pthread_attr_init(&globattr);
    pthread_attr_setscope(&globattr, PTHREAD_SCOPE_SYSTEM);
    globsched.sched_priority = 1;
    self = pthread_self();
    pthread_setschedparam(self, SCHED_OTHER, &globsched);
    globsched.sched_priority = 2;
    pthread_attr_setschedparam(&globattr, &globsched);

    /* Create threads and get them to sit in their wait loop */

    for (i = 0; i < NUMTHREADS; i++) {
	threadp = thread + i;
	threadp->status = _THREAD_STARTING;
	if (pthread_mutex_init(&(threadp->mutex), NULL)) {
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
	if (pthread_cond_init(&(threadp->cond), NULL)) {
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
	threadp->req = NULL;
	threadp->donereq = NULL;
	if (pthread_create(&(threadp->thread), &globattr, aio_thread_loop, threadp)) {
	    fprintf(stderr, "Thread creation failed\n");
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
	threadp->next = wait_threads;
	wait_threads = threadp;
    }

    aio_initialised = 1;
}


static void *
aio_thread_loop(void *ptr)
{
    aio_thread_t *threadp = (aio_thread_t *) ptr;
    aio_request_t *request;
    struct timespec abstime;
    int ret;
    sigset_t new;

    /* Make sure to ignore signals which may possibly get sent to the parent */
    /* squid thread.  Causes havoc with mutex's and condition waits otherwise */

    sigemptyset(&new);
    sigaddset(&new, SIGPIPE);
    sigaddset(&new, SIGCHLD);
    sigaddset(&new, SIGUSR1);
    sigaddset(&new, SIGUSR2);
    sigaddset(&new, SIGHUP);
    sigaddset(&new, SIGTERM);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    while (1) {
	/* BELOW is done because Solaris 2.5.1 doesn't support semaphores!!! */
	/* Use timed wait to avoid race where thread context switches after */
	/* threadp->status gets set but before the condition wait happens. */
	/* In that case, a race occurs when the parent signals the condition */
	/* but this thread will never receive it.  Recheck every 2-3 secs. */
	/* Also provides bonus of keeping thread contexts hot in CPU cache */
	/* (ie. faster thread reactions) at slight expense of CPU time. */
	while (threadp->req == NULL) {
	    abstime.tv_sec = squid_curtime + 3;
	    abstime.tv_nsec = 0;
	    threadp->status = _THREAD_WAITING;
	    ret = pthread_cond_timedwait(&(threadp->cond),
		&(threadp->mutex),
		&abstime);
	}
	request = threadp->req;
	switch (request->request_type) {
	case _AIO_OP_OPEN:
	    aio_thread_open(threadp);
	    break;
	case _AIO_OP_READ:
	    aio_thread_read(threadp);
	    break;
	case _AIO_OP_WRITE:
	    aio_thread_write(threadp);
	    break;
	case _AIO_OP_CLOSE:
	    aio_thread_close(threadp);
	    break;
	case _AIO_OP_UNLINK:
	    aio_thread_unlink(threadp);
	    break;
#if 0
	    /* Opendir not implemented yet */
	case _AIO_OP_OPENDIR:
	    aio_thread_opendir(threadp);
	    break;
#endif
	case _AIO_OP_STAT:
	    aio_thread_stat(threadp);
	    break;
	default:
	    threadp->donereq->ret = -1;
	    threadp->donereq->err = EINVAL;
	    break;
	}
	threadp->req = NULL;
    }				/* while */
}				/* aio_thread_loop */


static aio_request_t *
aio_alloc_request()
{
    aio_request_t *req;

    if ((req = free_requests) != NULL) {
	free_requests = req->next;
	num_free_requests--;
	return req;
    }
    return (aio_request_t *) xmalloc(sizeof(aio_request_t));
}				/* aio_alloc_request */


static void
aio_free_request(aio_request_t * req)
{
    /* Below doesn't have to be NUMTHREADS but it's a kinda cute value since */
    /* it reflects the sort of load the squid server will experience.  A */
    /* higher load will mean a need for more threads, which will in turn mean */
    /* a need for a bigger free request pool. */

    if (num_free_requests >= NUMTHREADS) {
	xfree(req);
	return;
    }
    req->next = free_requests;
    free_requests = req;
    num_free_requests++;
}				/* aio_free_request */


static void
aio_do_request(aio_request_t * requestp)
{
    aio_thread_t *threadp;

    if (wait_threads == NULL && busy_threads_head == NULL) {
	fprintf(stderr, "PANIC: No threads to service requests with!\n");
	exit(-1);
    }
    aio_queue_request(requestp);
    aio_process_request_queue();
}				/* aio_do_request */


static void
aio_queue_request(aio_request_t * requestp)
{
    aio_request_t *rp;
    static int last_warn = 0;
    int i;

    if (request_queue_head == NULL) {
	request_queue_head = requestp;
	request_queue_tail = requestp;
    } else {
	request_queue_tail->next = requestp;
	request_queue_tail = requestp;
    }
    requestp->next = NULL;
    if (++request_queue_len > NUMTHREADS) {
	if (squid_curtime > (last_warn + 15)) {
	    debug(43, 1) ("aio_queue_request: WARNING - Async request queue growing: Length = %d\n", request_queue_len);
	    debug(43, 1) ("aio_queue_request: Perhaps you should increase NUMTHREADS in aiops.c\n");
	    debug(43, 1) ("aio_queue_request: First %d items on request queue\n", NUMTHREADS);
	    rp = request_queue_head;
	    for (i = 1; i <= NUMTHREADS; i++) {
		switch (rp->request_type) {
		case _AIO_OP_OPEN:
		    debug(43, 1) ("aio_queue_request: %d : open -> %s\n", i, rp->path);
		    break;
		case _AIO_OP_READ:
		    debug(43, 1) ("aio_queue_request: %d : read -> FD = %d\n", i, rp->fd);
		    break;
		case _AIO_OP_WRITE:
		    debug(43, 1) ("aio_queue_request: %d : write -> FD = %d\n", i, rp->fd);
		    break;
		case _AIO_OP_CLOSE:
		    debug(43, 1) ("aio_queue_request: %d : close -> FD = %d\n", i, rp->fd);
		    break;
		case _AIO_OP_UNLINK:
		    debug(43, 1) ("aio_queue_request: %d : unlink -> %s\n", i, rp->path);
		    break;
		case _AIO_OP_STAT:
		    debug(43, 1) ("aio_queue_request: %d : stat -> %s\n", i, rp->path);
		    break;
		default:
		    debug(43, 1) ("aio_queue_request: %d : Unimplemented request type: %d\n", i, rp->request_type);
		    break;
		}
		if ((rp = rp->next) == NULL)
		    break;
	    }
	    last_warn = squid_curtime;
	}
    }
    if (request_queue_len > RIDICULOUS_LENGTH) {
	debug(43, 0) ("aio_queue_request: Async request queue growing uncontrollably!\n");
	debug(43, 0) ("aio_queue_request: Possible infinite loop somewhere in squid. Restarting...\n");
	abort();
    }
}				/* aio_queue_request */


static void
aio_process_request_queue()
{
    aio_thread_t *threadp;
    aio_request_t *requestp;

    for (;;) {
	if (wait_threads == NULL || request_queue_head == NULL)
	    return;

	requestp = request_queue_head;
	if ((request_queue_head = request_queue_head->next) == NULL)
	    request_queue_tail = NULL;
	request_queue_len--;

	if (requestp->cancelled) {
	    aio_cleanup_request(requestp);
	    continue;
	}
	threadp = wait_threads;
	wait_threads = wait_threads->next;

	threadp->req = requestp;
	threadp->donereq = requestp;
	if (busy_threads_head != NULL)
	    busy_threads_tail->next = threadp;
	else
	    busy_threads_head = threadp;
	busy_threads_tail = threadp;
	threadp->next = NULL;

	threadp->status = _THREAD_BUSY;
	pthread_cond_signal(&(threadp->cond));
    }
}				/* aio_process_request_queue */


static void
aio_cleanup_request(aio_request_t * requestp)
{
    aio_result_t *resultp = requestp->resultp;
    int cancelled = requestp->cancelled;

    /* Free allocated structures and copy data back to user space if the */
    /* request hasn't been cancelled */
    switch (requestp->request_type) {
    case _AIO_OP_STAT:
	if (!cancelled && requestp->ret == 0)
	    xmemcpy(requestp->statp, requestp->tmpstatp, sizeof(struct stat));
	xfree(requestp->tmpstatp);
    case _AIO_OP_OPEN:
    case _AIO_OP_UNLINK:
    case _AIO_OP_OPENDIR:
	xfree(requestp->path);
	break;
    case _AIO_OP_READ:
	if (!cancelled && requestp->ret > 0)
	    xmemcpy(requestp->bufferp, requestp->tmpbufp, requestp->ret);
    case _AIO_OP_WRITE:
	xfree(requestp->tmpbufp);
	break;
    default:
	break;
    }
    if (!cancelled) {
	resultp->aio_return = requestp->ret;
	resultp->aio_errno = requestp->err;
    }
    aio_free_request(requestp);
}				/* aio_cleanup_request */


int
aio_cancel(aio_result_t * resultp)
{
    aio_thread_t *threadp;
    aio_request_t *requestp;
    int ret;

    for (threadp = busy_threads_head; threadp != NULL; threadp = threadp->next)
	if (threadp->donereq->resultp == resultp)
	    threadp->donereq->cancelled = 1;
    for (requestp = request_queue_head; requestp != NULL; requestp = requestp->next)
	if (requestp->resultp == resultp)
	    requestp->cancelled = 1;
    return 0;
}				/* aio_cancel */


int
aio_open(const char *path, int oflag, mode_t mode, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((requestp->path = (char *) xmalloc(len)) == NULL) {
	aio_free_request(requestp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(requestp->path, path, len);
    requestp->oflag = oflag;
    requestp->mode = mode;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_OPEN;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_thread_open(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;

    requestp->ret = open(requestp->path, requestp->oflag, requestp->mode);
    requestp->err = errno;
}


int
aio_read(int fd, char *bufp, int bufs, off_t offset, int whence, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    requestp->fd = fd;
    requestp->bufferp = bufp;
    if ((requestp->tmpbufp = (char *) xmalloc(bufs)) == NULL) {
	aio_free_request(requestp);
	errno = ENOMEM;
	return -1;
    }
    requestp->buflen = bufs;
    requestp->offset = offset;
    requestp->whence = whence;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_READ;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_thread_read(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;

    lseek(requestp->fd, requestp->offset, requestp->whence);
    requestp->ret = read(requestp->fd, requestp->tmpbufp, requestp->buflen);
    requestp->err = errno;
}


int
aio_write(int fd, char *bufp, int bufs, off_t offset, int whence, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    requestp->fd = fd;
    if ((requestp->tmpbufp = (char *) xmalloc(bufs)) == NULL) {
	aio_free_request(requestp);
	errno = ENOMEM;
	return -1;
    }
    xmemcpy(requestp->tmpbufp, bufp, bufs);
    requestp->buflen = bufs;
    requestp->offset = offset;
    requestp->whence = whence;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_WRITE;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_thread_write(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;

    requestp->ret = write(requestp->fd, requestp->tmpbufp, requestp->buflen);
    requestp->err = errno;
}


int
aio_close(int fd, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    requestp->fd = fd;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_CLOSE;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_thread_close(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;

    requestp->ret = close(requestp->fd);
    requestp->err = errno;
}


int
aio_stat(const char *path, struct stat *sb, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((requestp->path = (char *) xmalloc(len)) == NULL) {
	aio_free_request(requestp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(requestp->path, path, len);
    requestp->statp = sb;
    if ((requestp->tmpstatp = (struct stat *) xmalloc(sizeof(struct stat))) == NULL) {
	xfree(requestp->path);
	aio_free_request(requestp);
	errno = ENOMEM;
	return -1;
    }
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_STAT;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_thread_stat(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;

    requestp->ret = stat(requestp->path, requestp->tmpstatp);
    requestp->err = errno;
}


int
aio_unlink(const char *path, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((requestp->path = (char *) xmalloc(len)) == NULL) {
	aio_free_request(requestp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(requestp->path, path, len);
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_UNLINK;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_thread_unlink(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;

    requestp->ret = unlink(requestp->path);
    requestp->err = errno;
}


#if 0
/* XXX aio_opendir NOT implemented? */

int
aio_opendir(const char *path, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = aio_alloc_request()) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    return -1;
}

static void *
aio_thread_opendir(aio_thread_t * threadp)
{
    aio_request_t *requestp = threadp->req;
    aio_result_t *resultp = requestp->resultp;

    return threadp;
}
#endif


aio_result_t *
aio_poll_done()
{
    aio_thread_t *prev;
    aio_thread_t *threadp;
    aio_request_t *requestp;
    aio_result_t *resultp;
    int cancelled;

  AIO_REPOLL:
    prev = NULL;
    threadp = busy_threads_head;
    while (threadp) {
	debug(43, 3) ("%d: %d -> %d\n",
	    threadp->thread,
	    threadp->donereq->request_type,
	    threadp->status);
	if (!threadp->req)
	    break;
	prev = threadp;
	threadp = threadp->next;
    }
    if (threadp == NULL)
	return NULL;

    if (prev == NULL)
	busy_threads_head = busy_threads_head->next;
    else
	prev->next = threadp->next;

    if (busy_threads_tail == threadp)
	busy_threads_tail = prev;

    requestp = threadp->donereq;
    threadp->donereq = NULL;
    resultp = requestp->resultp;
    aio_debug(requestp);
    debug(43, 3) ("DONE: %d -> %d\n", requestp->ret, requestp->err);
    threadp->next = wait_threads;
    wait_threads = threadp;
    cancelled = requestp->cancelled;
    aio_cleanup_request(requestp);
    aio_process_request_queue();
    if (cancelled)
	goto AIO_REPOLL;
    return resultp;
}				/* aio_poll_done */


static void
aio_debug(aio_request_t * requestp)
{
    switch (requestp->request_type) {
    case _AIO_OP_OPEN:
	debug(43, 3) ("OPEN of %s to FD %d\n", requestp->path, requestp->ret);
	break;
    case _AIO_OP_READ:
	debug(43, 3) ("READ on fd: %d\n", requestp->fd);
	break;
    case _AIO_OP_WRITE:
	debug(43, 3) ("WRITE on fd: %d\n", requestp->fd);
	break;
    case _AIO_OP_CLOSE:
	debug(43, 3) ("CLOSE of fd: %d\n", requestp->fd);
	break;
    case _AIO_OP_UNLINK:
	debug(43, 3) ("UNLINK of %s\n", requestp->path);
	break;
    default:
	break;
    }
}
