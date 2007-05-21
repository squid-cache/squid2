
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
#include "comm_generic.c"

#include <sys/devpoll.h>


static int devpoll_fd;
static struct timespec zero_timespec;

/*
 * This is a very simple driver for Solaris /dev/poll.
 *
 * The updates are batched, one trip through the comm loop.
 * (like libevent.) We keep a pointer into the structs so we
 * can zero out an entry in the poll list if its active.
 */

struct _devpoll_state {
    char state;
};

struct _devpoll_events {
    int ds_used;
    int ds_size;
    struct pollfd *events;
};

static struct _devpoll_state *devpoll_state;
static struct _devpoll_events ds_events;
static struct dvpoll do_poll;
static int dpoll_nfds;

static void
do_select_init()
{
    devpoll_fd = open("/dev/poll", O_RDWR);
    if (devpoll_fd < 0)
	fatalf("comm_select_init: can't open /dev/poll: %s\n", xstrerror());

    zero_timespec.tv_sec = 0;
    zero_timespec.tv_nsec = 0;

    /* This tracks the FD devpoll offset+state */
    devpoll_state = xcalloc(Squid_MaxFD, sizeof(struct _devpoll_state));

    /* And this stuff is list used to submit events */
    ds_events.events = xcalloc(1024, sizeof(struct pollfd));
    ds_events.ds_used = 0;
    ds_events.ds_size = 1024;

    /* And this is the stuff we use to read events */
    do_poll.dp_fds = xcalloc(1024, sizeof(struct pollfd));
    dpoll_nfds = 1024;

    fd_open(devpoll_fd, FD_UNKNOWN, "devpoll ctl");
    commSetCloseOnExec(devpoll_fd);
}

static void
comm_update_fd(int fd, int events)
{
    struct pollfd pfd[1];
    int i;

    pfd[0].fd = fd;
    pfd[0].events = events;
    pfd[0].revents = 0;

    i = write(devpoll_fd, &pfd, sizeof(struct pollfd));
    assert(i == sizeof(struct pollfd));

}

void
comm_select_postinit()
{
    debug(5, 1) ("Using /dev/poll for the IO loop\n");
}

static void
do_select_shutdown()
{
    fd_close(devpoll_fd);
    close(devpoll_fd);
    devpoll_fd = -1;
    xfree(devpoll_state);
}

void
comm_select_status(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "\tIO loop method:                     /dev/poll\n");
}

void
commOpen(int fd)
{
    devpoll_state[fd].state = 0;
}

void
commClose(int fd)
{
    comm_update_fd(fd, POLLREMOVE);
}

void
commSetEvents(int fd, int need_read, int need_write)
{
    int st_new = (need_read ? POLLIN : 0) | (need_write ? POLLOUT : 0);
    int st_change;

    debug(5, 5) ("commSetEvents(fd=%d, read=%d, write=%d)\n", fd, need_read, need_write);

    st_change = devpoll_state[fd].state ^ st_new;
    if (!st_change)
	return;

    if (st_new)
	comm_update_fd(fd, st_new);
    else
	comm_update_fd(fd, POLLREMOVE);
    devpoll_state[fd].state = st_new;
}

static int
do_comm_select(int msec)
{
    int i;
    int num;

    statCounter.syscalls.polls++;

    do_poll.dp_timeout = msec;
    do_poll.dp_nfds = dpoll_nfds;
    /* dp_fds is already allocated */

    num = ioctl(devpoll_fd, DP_POLL, &do_poll);
    debug(5, 5) ("do_comm_select: ioctl() returned %d fds\n", num);

    if (num < 0) {
	getCurrentTime();
	if (ignoreErrno(errno))
	    return COMM_OK;

	debug(5, 1) ("comm_select: devpoll ioctl(DP_POLL) failure: %s\n", xstrerror());
	return COMM_ERROR;
    }
    statHistCount(&statCounter.select_fds_hist, num);
    if (num == 0)
	return COMM_TIMEOUT;

    for (i = 0; i < num; i++) {
	int fd = (int) do_poll.dp_fds[i].fd;
	if (do_poll.dp_fds[i].revents & POLLERR) {
	    debug(5, 3) ("comm_select: devpoll event error: fd %d\n", fd);
	    continue;		/* XXX! */
	}
	if (do_poll.dp_fds[i].revents & POLLIN) {
	    comm_call_handlers(fd, 1, 0);
	}
	if (do_poll.dp_fds[i].revents & POLLOUT) {
	    comm_call_handlers(fd, 0, 1);
	}
    }

    return COMM_OK;
}
