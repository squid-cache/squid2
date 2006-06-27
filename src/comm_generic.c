
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


/* This file is not compiled separately. Instead it's included into
 * the comm loops using it
 */

static int MAX_POLL_TIME = 1000;	/* see also comm_quick_poll_required() */

/* Defer reads from this fd */
void
commDeferFD(int fd)
{
    fde *F = &fd_table[fd];

    assert(fd >= 0);
    assert(F->flags.open);

    if (F->backoff)
	return;

    F->backoff = 1;
    commUpdateEvents(fd);
}

/* Resume reading from the given fd */
void
commResumeFD(int fd)
{
    fde *F = &fd_table[fd];

    assert(fd >= 0);

    if (!F->flags.open) {
	debug(5, 1) ("commResumeFD: fd %d is closed. Ignoring\n", fd);
	F->backoff = 0;
	return;
    }
    if (!F->backoff)
	return;

    F->backoff = 0;
    commUpdateEvents(fd);
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
		if (!(F->backoff)) {
		    debug(5, 1) ("comm_call_handlers(): WARNING defer handler for fd=%d (desc=%s) does not call commDeferFD() - backing off manually\n", fd, F->desc);
		    commDeferFD(fd);
		}
		break;
	    default:
		debug(5, 8) ("comm_call_handlers(): Calling read handler on fd=%d\n", fd);
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
		    commUpdateEvents(fd);
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
		commUpdateEvents(fd);
#endif
	    statCounter.select_fds++;
	}
    }
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
	if (F->backoff)
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
