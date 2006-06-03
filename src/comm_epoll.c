
/*
 * $Id$
 *
 * DEBUG: section 5     Socket Functions
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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

static int MAX_POLL_TIME = 1000;	/* see also comm_quick_poll_required() */

/* epoll structs */
static int kdpfd;
static struct epoll_event *pevents;
static int epoll_fds = 0;

static void checkTimeouts(void);
static int commDeferRead(int fd);


static const char *
epolltype_atoi(int x)
{
    switch (x) {

    case EPOLL_CTL_ADD:
	return "EPOLL_CTL_ADD";

    case EPOLL_CTL_DEL:
	return "EPOLL_CTL_DEL";

    case EPOLL_CTL_MOD:
	return "EPOLL_CTL_MOD";

    default:
	return "UNKNOWN_EPOLLCTL_OP";
    }
}

/* Defer reads from this fd */
void
commDeferFD(int fd)
{
    fde *F = &fd_table[fd];

    /* die if we have no fd (very unlikely), if the fd has no existing epoll 
     * state, if we are given a bad fd, or if the fd is not open. */
    assert(fd >= 0);
    assert(F->epoll_state);
    assert(F->flags.open);

    /* Return if the fd is already backed off */
    if (F->epoll_backoff) {
	return;
    }
    F->epoll_backoff = 1;
    commUpdateEvents(fd, 0);
}

/* Resume reading from the given fd */
void
commResumeFD(int fd)
{
    fde *F = &fd_table[fd];

    if (!F->epoll_backoff)
	return;

    F->epoll_backoff = 0;

    if (!F->read_handler) {
	debug(5, 2) ("commResumeFD: fd=%d ignoring read_handler=%p\n", fd, F->read_handler);
	return;
    }
    commUpdateEvents(fd, 0);
}

void
comm_select_init()
{
    pevents = (struct epoll_event *) xmalloc(SQUID_MAXFD * sizeof(struct epoll_event));
    if (!pevents) {
	fatalf("comm_select_init: xmalloc() failed: %s\n", xstrerror());
    }
    kdpfd = epoll_create(SQUID_MAXFD);
    fd_open(kdpfd, FD_UNKNOWN, "epoll ctl");
    commSetCloseOnExec(kdpfd);

    if (kdpfd < 0) {
	fatalf("comm_select_init: epoll_create(): %s\n", xstrerror());
    }
}

void
comm_select_shutdown()
{
    close(kdpfd);
    fd_close(kdpfd);
    kdpfd = -1;
    safe_free(pevents);
}

void
commSetEvents(int fd, int need_read, int need_write, int force)
{
    fde *F = &fd_table[fd];
    int epoll_ctl_type = 0;
    struct epoll_event ev;

    assert(fd >= 0);
    assert(F->flags.open);
    debug(5, 8) ("commUpdateEvents(fd=%d)\n", fd);

    if (RUNNING_ON_VALGRIND) {
	/* Keep valgrind happy.. complains about uninitialized bytes otherwise */
	memset(&ev, 0, sizeof(ev));
    }
    ev.events = 0;
    ev.data.fd = fd;

    if (need_read & !F->epoll_backoff)
	ev.events |= EPOLLIN;

    if (need_write)
	ev.events |= EPOLLOUT;

    if (ev.events)
	ev.events |= EPOLLHUP | EPOLLERR;

    /* If the type is 0, force adding the fd to the epoll set */
    if (force)
	F->epoll_state = 0;

    if (ev.events != F->epoll_state) {
	/* If the struct is already in epoll MOD or DEL, else ADD */
	if (F->epoll_state) {
	    epoll_ctl_type = ev.events ? EPOLL_CTL_MOD : EPOLL_CTL_DEL;
	} else {
	    epoll_ctl_type = EPOLL_CTL_ADD;
	}

	/* Update the state */
	F->epoll_state = ev.events;

	if (epoll_ctl(kdpfd, epoll_ctl_type, fd, &ev) < 0) {
	    debug(5, 1) ("commSetSelect: epoll_ctl(%s): failed on fd=%d: %s\n",
		epolltype_atoi(epoll_ctl_type), fd, xstrerror());
	}
	switch (epoll_ctl_type) {
	case EPOLL_CTL_ADD:
	    epoll_fds++;
	    break;
	case EPOLL_CTL_DEL:
	    epoll_fds--;
	    break;
	default:
	    break;
	}
    }
}

static void
comm_call_handlers(int fd, int read_event, int write_event)
{
    fde *F = &fd_table[fd];
    debug(5, 8) ("comm_call_handlers(): got fd=%d read_event=%x write_event=%x F->read_handler=%p F->write_handler=%p\n"
	,fd, read_event, write_event, F->read_handler, F->write_handler);
    if (F->read_handler) {
	int do_read = 0;
	switch (F->read_pending) {
	case COMM_PENDING_NORMAL:
	case COMM_PENDING_WANTS_READ:
	    do_read = read_event;
	    break;
	case COMM_PENDING_WANTS_WRITE:
	    do_read = write_event;
	    break;
	case COMM_PENDING_NOW:
	    do_read = 1;
	    break;
	}
	if (do_read) {
	    PF *hdl = F->read_handler;
	    void *hdl_data = F->read_data;
	    /* If the descriptor is meant to be deferred, don't handle */
	    switch (commDeferRead(fd)) {
	    case 1:
		if (!(F->epoll_backoff)) {
		    debug(5, 1) ("comm_epoll(): WARNING defer handler for fd=%d (desc=%s) does not call commDeferFD() - backing off manually\n", fd, F->desc);
		    commDeferFD(fd);
		}
		break;
	    default:
		debug(5, 8) ("comm_epoll(): Calling read handler on fd=%d\n", fd);
#if SIMPLE_COMM_HANDLER
		commUpdateReadHandler(fd, NULL, NULL);
		hdl(fd, hdl_data);
#else
		/* Optimized version to avoid the fd bouncing in/out of the waited set */
		F->read_handler = NULL;
		F->read_data = NULL;
		F->read_pending = COMM_PENDING_NORMAL;
		hdl(fd, hdl_data);
		if (F->flags.open && !F->read_handler)
		    commUpdateEvents(fd, 0);
#endif
		statCounter.select_fds++;
	    }
	}
    }
    if (F->write_handler) {
	int do_write = 0;
	switch (F->write_pending) {
	case COMM_PENDING_WANTS_READ:
	    do_write = read_event;
	    break;
	case COMM_PENDING_NORMAL:
	case COMM_PENDING_WANTS_WRITE:
	    do_write = write_event;
	    break;
	case COMM_PENDING_NOW:
	    do_write = 1;
	    break;
	}
	if (do_write) {
	    PF *hdl = F->write_handler;
	    void *hdl_data = F->write_data;
#if SIMPLE_COMM_HANDLER
	    commUpdateWriteHandler(fd, NULL, NULL);
	    hdl(fd, hdl_data);
#else
	    /* Optimized version to avoid the fd bouncing in/out of the waited set */
	    F->write_handler = NULL;
	    F->write_data = NULL;
	    F->write_pending = COMM_PENDING_NORMAL;
	    hdl(fd, hdl_data);
	    if (F->flags.open)
		commUpdateEvents(fd, 0);
#endif
	    statCounter.select_fds++;
	}
    }
}

int
comm_select(int msec)
{
    static time_t last_timeout = 0;
    int i;
    int num;
    int fd;
    struct epoll_event *cevents;
    double timeout;
    double start = current_dtime;

    timeout = current_dtime + (msec / 1000.0);

    debug(50, 3) ("comm_epoll: timeout %d\n", msec);

    if (epoll_fds == 0) {
	assert(shutting_down);
	return COMM_SHUTDOWN;
    }
    /* Check for disk io callbacks */
    storeDirCallback();

    /* Check timeouts once per second */
    if (last_timeout != squid_curtime) {
	last_timeout = squid_curtime;
	checkTimeouts();
    }
    statCounter.syscalls.polls++;
    num = epoll_wait(kdpfd, pevents, SQUID_MAXFD, msec);
    statCounter.select_loops++;

    if (num < 0) {
	getCurrentTime();
	if (ignoreErrno(errno))
	    return COMM_OK;

	debug(5, 1) ("comm_epoll: epoll failure: %s\n", xstrerror());
	return COMM_ERROR;
    }
    statHistCount(&statCounter.select_fds_hist, num);

    if (num > 0) {
	for (i = 0, cevents = pevents; i < num; i++, cevents++) {
	    fd = cevents->data.fd;
	    comm_call_handlers(fd, cevents->events & ~EPOLLOUT, cevents->events & ~EPOLLIN);
	}
	getCurrentTime();
	statCounter.select_time += (current_dtime - start);
	return COMM_OK;
    } else {
	getCurrentTime();
	debug(5, 8) ("comm_epoll: time out: %ld.\n", (long int) squid_curtime);
	return COMM_TIMEOUT;
    }
}

static int
commDeferRead(int fd)
{
    fde *F = &fd_table[fd];
    if (F->defer_check == NULL)
	return 0;
    return F->defer_check(fd, F->defer_data);
}

static void
checkTimeouts(void)
{
    int fd;
    fde *F = NULL;
    PF *callback;
    for (fd = 0; fd <= Biggest_FD; fd++) {
	F = &fd_table[fd];
	if (!F->flags.open)
	    continue;
	if (F->epoll_backoff)
	    commResumeFD(fd);
	if (F->timeout == 0)
	    continue;
	if (F->timeout > squid_curtime)
	    continue;
	debug(5, 5) ("checkTimeouts: FD %d Expired\n", fd);
	if (F->timeout_handler) {
	    debug(5, 5) ("checkTimeouts: FD %d: Call timeout handler\n", fd);
	    callback = F->timeout_handler;
	    F->timeout_handler = NULL;
	    callback(fd, F->timeout_data);
	} else {
	    debug(5, 5) ("checkTimeouts: FD %d: Forcing comm_close()\n", fd);
	    comm_close(fd);
	}
    }
}


/* Called by async-io or diskd to speed up the polling */
void
comm_quick_poll_required(void)
{
    MAX_POLL_TIME = 10;
}
