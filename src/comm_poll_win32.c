
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

#if HAVE_WINSOCK2_H
#include <Winsock2.h>
#endif

static WSAPOLLFD *pfds;
static int *pfd_map;
static int *pfd_map_fd;
static int nfds = 0;

static void
do_select_init()
{
    int i;
    pfds = xcalloc(sizeof(*pfds), Squid_MaxFD);
    pfd_map = xcalloc(sizeof(*pfd_map), Squid_MaxFD);
    pfd_map_fd = xcalloc(sizeof(*pfd_map_fd), Squid_MaxFD);
    for (i = 0; i < Squid_MaxFD; i++) {
	pfd_map_fd[i] = pfd_map[i] = -1;
    }
}

void
comm_select_postinit()
{
    debug(5, 1) ("Using poll for the IO loop\n");
}

static void
do_select_shutdown()
{
    safe_free(pfds);
    safe_free(pfd_map);
    safe_Free(pfd_map_fd);
}

void
comm_select_status(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "\tIO loop method:                     poll\n");
}

void
commSetEvents(int fd, int need_read, int need_write)
{
    int pfdn = pfd_map[fd];
    WSAPOLLFD *pfd = pfdn >= 0 ? &pfds[pfdn] : NULL;
    short events = (need_read ? POLLRDNORM : 0) | (need_write ? POLLWRNORM : 0);

    if (!pfd && !events)
	return;

    if (!pfd) {
	pfdn = nfds++;
	pfd_map[fd] = pfdn;
	pfd_map_fd[pfdn] = fd;
	pfd = &pfds[pfdn];
	pfd->fd = _get_osfhandle(fd);
	pfd->events = events;
    } else if (events) {
	pfd->events = events;
    } else {
	int *pfd_fd = &pfd_map_fd[pfdn];
	pfd_map[fd] = -1;
	nfds--;
	*pfd = pfds[nfds];
	*pfd_fd = pfd_map_fd[nfds];
	pfds[nfds].events = 0;
	pfds[nfds].revents = 0;
	pfds[nfds].fd = -1;
	if (pfd->fd >= 0)
	    pfd_map[*pfd_fd] = pfdn;
    }
}

static int
do_comm_select(int msec)
{
    int num;
    int i;

    if (nfds == 0) {
	assert(shutting_down);
	return COMM_SHUTDOWN;
    }
    statCounter.syscalls.selects++;
    num = WSAPoll(pfds, nfds, msec);
    if (num < 0) {
	getCurrentTime();
	if (ignoreErrno(errno))
	    return COMM_OK;

	debug(5, 1) ("comm_select: poll failure: %s\n", xstrerror());
	return COMM_ERROR;
    }
    statHistCount(&statCounter.select_fds_hist, num);

    if (num == 0)
	return COMM_TIMEOUT;

    for (i = nfds - 1; num > 0 && i >= 0; i--) {
	WSAPOLLFD *pfd = &pfds[i];
	short read_event, write_event;

	if (!pfd->revents)
	    continue;

	read_event = pfd->revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR);
	write_event = pfd->revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR);

	pfd->revents = 0;

	comm_call_handlers(pfd_map_fd[i], read_event, write_event);
	num--;
    }

    return COMM_OK;
}
