
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

#include <sys/epoll.h>

#define MAX_EVENTS	256	/* max events to process in one go */

/* epoll structs */
static int kdpfd;
static struct epoll_event events[MAX_EVENTS];
static int epoll_fds = 0;
static unsigned *epoll_state;	/* keep track of the epoll state */

#include "comm_generic.c"

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

void
comm_select_init()
{
    kdpfd = epoll_create(Squid_MaxFD);
    fd_open(kdpfd, FD_UNKNOWN, "epoll ctl");
    commSetCloseOnExec(kdpfd);

    if (kdpfd < 0) {
	fatalf("comm_select_init: epoll_create(): %s\n", xstrerror());
    }
    epoll_state = xcalloc(Squid_MaxFD, sizeof(*epoll_state));
}

void
comm_select_shutdown()
{
    fd_close(kdpfd);
    close(kdpfd);
    kdpfd = -1;
    safe_free(epoll_state);
}

void
commSetEvents(int fd, int need_read, int need_write)
{
    int epoll_ctl_type = 0;
    struct epoll_event ev;

    assert(fd >= 0);
    debug(5, 8) ("commSetEvents(fd=%d)\n", fd);

    if (RUNNING_ON_VALGRIND) {
	/* Keep valgrind happy.. complains about uninitialized bytes otherwise */
	memset(&ev, 0, sizeof(ev));
    }
    ev.events = 0;
    ev.data.fd = fd;

    if (need_read)
	ev.events |= EPOLLIN;

    if (need_write)
	ev.events |= EPOLLOUT;

    if (ev.events)
	ev.events |= EPOLLHUP | EPOLLERR;

    if (ev.events != epoll_state[fd]) {
	/* If the struct is already in epoll MOD or DEL, else ADD */
	if (!ev.events) {
	    epoll_ctl_type = EPOLL_CTL_DEL;
	} else if (epoll_state[fd]) {
	    epoll_ctl_type = EPOLL_CTL_MOD;
	} else {
	    epoll_ctl_type = EPOLL_CTL_ADD;
	}

	/* Update the state */
	epoll_state[fd] = ev.events;

	if (epoll_ctl(kdpfd, epoll_ctl_type, fd, &ev) < 0) {
	    debug(5, 1) ("commSetEvents: epoll_ctl(%s): failed on fd=%d: %s\n",
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

int
comm_select(int msec)
{
    static time_t last_timeout = 0;
    int i;
    int num;
    int fd;
    struct epoll_event *cevents;
    double start = current_dtime;

    if (msec > MAX_POLL_TIME)
	msec = MAX_POLL_TIME;

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
    num = epoll_wait(kdpfd, events, MAX_EVENTS, msec);
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
	for (i = 0, cevents = events; i < num; i++, cevents++) {
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
