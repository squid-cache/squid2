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

#ifdef UNLINK_DAEMON

/* This is the external unlinkd process */

#include "config.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#define UNLINK_BUF_LEN 1024

int
main(int argc, char *argv[])
{
    char buf[UNLINK_BUF_LEN];
    char *t;
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    while (fgets(buf, UNLINK_BUF_LEN, stdin)) {
	if ((t = strchr(buf, '\n')))
		*t = '\0';
fprintf (stderr, "unlinkd: %s\n", buf);
	if (unlink(buf) < 0)
		perror(buf);
    }
fprintf (stderr, "unlinkd exiting\n");
    exit(0);
}

#else /* UNLINK_DAEMON */

/* This code gets linked to Squid */

#include "squid.h"

static int unlinkd_fd = -1;

static int unlinkdCreate _PARAMS((void));

static int
unlinkdCreate(void)
{
    pid_t pid;
    int cfd;
    int pfd;
    int squid_to_unlinkd[2] = {-1,-1};
    struct timeval slp;
    if (pipe(squid_to_unlinkd) < 0) {
	debug(50, 0, "unlinkdCreate: pipe: %s\n", xstrerror());
	return -1;
    }
    cfd = squid_to_unlinkd[0];
    pfd = squid_to_unlinkd[1];
    if ((pid = fork()) < 0) {
	debug(50, 0, "unlinkdCreate: fork: %s\n", xstrerror());
	close(cfd);
	close(pfd);
	return -1;
    }
    if (pid > 0) {		/* parent process */
	close(cfd);		/* close child's FD */
	comm_set_fd_lifetime(pfd, -1);
	slp.tv_sec = 0;
	slp.tv_usec = 250000;
	select(0, NULL, NULL, NULL, &slp);
        file_open_fd(pfd, "unlinkd socket", FD_PIPE);
	return pfd;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    dup2(cfd, 0);
    close(cfd);			/* close FD since we dup'd it */
    close(pfd);			/* close parent's FD */
    fclose(debug_log);
    execlp(Config.Program.unlinkd, "(unlinkd)", NULL);
    debug(50, 0, "unlinkdCreate: %s: %s\n",
	Config.Program.unlinkd, xstrerror());
    _exit(1);
    return 0;
}

void
unlinkdUnlink(const char *path)
{
    char *buf;
    int l;
    if (unlinkd_fd < 0)
	return;
    l = strlen(path) + 1;
    buf = xcalloc(1, l + 1);
    strcpy(buf, path);
    strcat(buf, "\n");
    file_write(unlinkd_fd,
	buf,
	l,
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
    if (unlinkd_fd < 0) {
	debug(43, 0, "unlinkdInit: failed to start unlinkd\n");
	return;
    }
    debug(43, 0, "unlinkd opened on FD %d\n", unlinkd_fd);
}

#endif /* ndef UNLINK_DAEMON */
