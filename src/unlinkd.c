/*
 * $Id$
 *
 * DEBUG: section 43    Unlink Daemon
 * AUTHOR: Duane Wessels
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

#define UNLINK_BUF_LEN 1024

static int unlinkd_fd = -1;

static int unlinkdCreate _PARAMS((void));

static int
unlinkdCreate(void)
{
    LOCAL_ARRAY(char, buf, UNLINK_BUF_LEN);
    char *t;
    pid_t pid;
    struct sockaddr_in S;
    int cfd;
    int sfd;
    int len;
    int fd;
    struct timeval slp;
    cfd = comm_open(SOCK_STREAM,
	0,
	local_addr,
	0,
	COMM_NOCLOEXEC,
	"unlinkd socket");
    if (cfd == COMM_ERROR) {
	debug(43, 0, "unlinkdCreate: Failed to create redirector\n");
	return -1;
    }
    len = sizeof(S);
    memset(&S, '\0', len);
    if (getsockname(cfd, (struct sockaddr *) &S, &len) < 0) {
	debug(50, 0, "unlinkdCreate: getsockname: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    listen(cfd, 1);
    if ((pid = fork()) < 0) {
	debug(50, 0, "unlinkdCreate: fork: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    if (pid > 0) {		/* parent */
	comm_close(cfd);	/* close shared socket with child */
	/* open new socket for parent process */
	sfd = comm_open(SOCK_STREAM,
	    0,
	    local_addr,
	    0,
	    0,
	    NULL);		/* blocking! */
	if (sfd == COMM_ERROR)
	    return -1;
	if (comm_connect_addr(sfd, &S) == COMM_ERROR) {
	    comm_close(sfd);
	    return -1;
	}
	comm_set_fd_lifetime(sfd, -1);
	debug(43, 4, "unlinkdCreate: FD %d connected to unlinkd.\n", sfd);
	slp.tv_sec = 0;
	slp.tv_usec = 250000;
	select(0, NULL, NULL, NULL, &slp);
	return sfd;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    if ((fd = accept(cfd, NULL, NULL)) < 0) {
	debug(50, 0, "unlinkdCreate: FD %d accept: %s\n", cfd, xstrerror());
	_exit(1);
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fileno(debug_log), 2);
    fclose(debug_log);
    close(fd);
    close(cfd);
    while (fgets(buf, UNLINK_BUF_LEN, stdin)) {
	if ((t = strchr(buf, '\n')))
		*t = '\0';
	unlink(buf);
    }
    exit(0);
}

void
unlinkdUnlink(const char *path)
{
    if (unlinkd_fd < 0)
	return;
    comm_write(unlinkd_fd,
	xstrdup(path),
	strlen(path),
	0,			/* timeout */
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
}

void
unlinkdClose(void)
{
    if (unlinkd_fd >= 0) {
	comm_close(unlinkd_fd);
	unlinkd_fd = -1;
    }
}

void
unlinkdInit(void)
{
    unlinkd_fd = unlinkdCreate();
    if (unlinkd_fd < 0)
	debug(43, 0, "unlinkdInit: failed to start unlinkd\n");
}
