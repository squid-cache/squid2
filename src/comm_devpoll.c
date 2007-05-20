
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

#define	STATE_READ		1
#define	STATE_WRITE		2


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
    int offset;
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
comm_submit_updates()
{
    int i;

    if (ds_events.ds_used == 0)
	return;
    debug(5, 5) ("comm_submit_updates: have %d updates to submit..\n", ds_events.ds_used);
    i = write(devpoll_fd, ds_events.events, ds_events.ds_used * sizeof(struct pollfd));
    debug(5, 5) ("comm_submit_updates: .. and wrote %d bytes\n", i);
    /* Could we handle "partial" writes? */
    assert(i == (sizeof(struct pollfd) * ds_events.ds_used));
    ds_events.ds_used = 0;
    /* XXX bzero the array after? */
}

static void
comm_add_update(int fd, int events)
{
    debug(5, 5) ("comm_add_update: FD %d: added (%d) %s %s %s\n", fd, events, (events & POLLIN) ? "POLLIN" : "", (events & POLLOUT) ? "POLLOUT" : "", (events & POLLREMOVE) ? "POLLREMOVE" : "");
    int i = ds_events.ds_used;
    ds_events.events[i].fd = fd;
    ds_events.events[i].events = events;
    ds_events.events[i].revents = 0;
    ds_events.ds_used++;

    if (ds_events.ds_used == ds_events.ds_size)
	comm_submit_updates();
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
    devpoll_state[fd].offset = 0;
}

void
commClose(int fd)
{
    int o;
    /*
     * Is there a pending event in the array for this
     * particular FD? Delete if so.
     */
    o = devpoll_state[fd].offset;
    if (devpoll_state[fd].offset <= ds_events.ds_used && fd == ds_events.events[devpoll_state[fd].offset].fd) {
	ds_events.events[devpoll_state[fd].offset].events = 0;
	ds_events.events[devpoll_state[fd].offset].fd = 0;
    }
}

void
commSetEvents(int fd, int need_read, int need_write)
{
    int st_new = (need_read ? STATE_READ : 0) | (need_write ? STATE_WRITE : 0);
    int st_change;
    int events = 0;

    debug(5, 5) ("commSetEvents(fd=%d, read=%d, write=%d)\n", fd, need_read, need_write);

    st_change = devpoll_state[fd].state ^ st_new;
    if (!st_change)
	return;

    if (need_read)
	events |= POLLIN;
    if (need_write)
	events |= POLLOUT;
    if (events == 0)
	events |= POLLREMOVE;

    /* Is the existing poll entry ours? If so, then update it */
    if (devpoll_state[fd].offset < ds_events.ds_used && fd == ds_events.events[devpoll_state[fd].offset].fd) {
	/* Just update it */
	ds_events.events[devpoll_state[fd].offset].events = events;
    } else {
	/* Nope, new one required */
	comm_add_update(fd, events);
    }
}

static int
do_comm_select(int msec)
{
    int i;
    int num;

    statCounter.syscalls.polls++;

    comm_submit_updates();

    do_poll.dp_timeout = msec;
    do_poll.dp_nfds = dpoll_nfds;
    /* dp_fds is already allocated */

    num = ioctl(devpoll_fd, DP_POLL, &do_poll);

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
