/*
 * $Id$
 *
 * DEBUG: section 50    Log file handling
 * AUTHOR: Duane Wessels
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
#include "logfile_mod_daemon.h"

/* How many buffers to keep before we say we've buffered too much */
#define	LOGFILE_MAXBUFS		128

/* Size of the logfile buffer */
/* 
 * For optimal performance this should match LOGFILE_BUFSIZ in logfile-daemon.c
 */
#define	LOGFILE_BUFSZ		32768

/* How many seconds between warnings */
#define	LOGFILE_WARN_TIME	30

static LOGWRITE logfile_mod_daemon_writeline;
static LOGLINESTART logfile_mod_daemon_linestart;
static LOGLINEEND logfile_mod_daemon_lineend;
static LOGROTATE logfile_mod_daemon_rotate;
static LOGFLUSH logfile_mod_daemon_flush;
static LOGCLOSE logfile_mod_daemon_close;

static void logfile_mod_daemon_append(Logfile * lf, const char *buf, int len);

struct _l_daemon {
    int rfd, wfd;
    char eol;
    pid_t pid;
    int flush_pending;
    dlink_list bufs;
    int nbufs;
    int last_warned;
};

typedef struct _l_daemon l_daemon_t;

/* Internal code */
static void
logfileNewBuffer(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    logfile_buffer_t *b;

    debug(50, 5) ("logfileNewBuffer: %s: new buffer\n", lf->path);

    b = xcalloc(1, sizeof(logfile_buffer_t));
    assert(b != NULL);
    b->buf = xcalloc(1, LOGFILE_BUFSZ);
    assert(b->buf != NULL);
    b->size = LOGFILE_BUFSZ;
    b->written_len = 0;
    b->len = 0;
    dlinkAddTail(b, &b->node, &ll->bufs);
    ll->nbufs++;
}

static void
logfileFreeBuffer(Logfile * lf, logfile_buffer_t * b)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    assert(b != NULL);
    dlinkDelete(&b->node, &ll->bufs);
    ll->nbufs--;
    xfree(b->buf);
    xfree(b);
}

static void
logfileHandleWrite(int fd, void *data)
{
    Logfile *lf = (Logfile *) data;
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    int ret;
    logfile_buffer_t *b;

    /*
     * We'll try writing the first entry until its done - if we
     * get a partial write then we'll re-schedule until its completed.
     * Its naive but it'll do for now.
     */
    b = ll->bufs.head->data;
    assert(b != NULL);
    ll->flush_pending = 0;

    ret = FD_WRITE_METHOD(ll->wfd, b->buf + b->written_len, b->len - b->written_len);
    debug(50, 3) ("logfileHandleWrite: %s: write returned %d\n", lf->path, ret);
    if (ret < 0) {
	if (ignoreErrno(errno)) {
	    /* something temporary */
	    goto reschedule;
	}
	debug(50, 1) ("logfileHandleWrite: %s: error writing (%s)\n", lf->path, xstrerror());
	/* XXX should handle this better */
	fatal("I don't handle this error well!");
    }
    if (ret == 0) {
	/* error? */
	debug(50, 1) ("logfileHandleWrite: %s: wrote 0 bytes?\n", lf->path);
	/* XXX should handle this better */
	fatal("I don't handle this error well!");
    }
    /* ret > 0, so something was written */
    b->written_len += ret;
    assert(b->written_len <= b->len);
    if (b->written_len == b->len) {
	/* written the whole buffer! */
	logfileFreeBuffer(lf, b);
	b = NULL;
    }
    /* Is there more to write? */
    if (ll->bufs.head == NULL) {
	goto finish;
    }
    /* there is, so schedule more */

  reschedule:
    commSetSelect(ll->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
    ll->flush_pending = 1;
  finish:
    return;
}

static void
logfileQueueWrite(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    if (ll->flush_pending || ll->bufs.head == NULL) {
	return;
    }
    ll->flush_pending = 1;
    if (ll->bufs.head) {
	logfile_buffer_t *b = ll->bufs.head->data;
	if (b->len + 2 <= b->size)
	    logfile_mod_daemon_append(lf, "F\n", 2);
    }
    /* Ok, schedule a write-event */
    commSetSelect(ll->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
}

static void
logfile_mod_daemon_append(Logfile * lf, const char *buf, int len)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    logfile_buffer_t *b;
    int s;

    /* Is there a buffer? If not, create one */
    if (ll->bufs.head == NULL) {
	logfileNewBuffer(lf);
    }
    debug(50, 3) ("logfile_mod_daemon_append: %s: appending %d bytes\n", lf->path, len);
    /* Copy what can be copied */
    while (len > 0) {
	b = ll->bufs.tail->data;
	debug(50, 3) ("logfile_mod_daemon_append: current buffer has %d of %d bytes before append\n", b->len, b->size);
	s = XMIN(len, (b->size - b->len));
	xmemcpy(b->buf + b->len, buf, s);
	len = len - s;
	buf = buf + s;
	b->len = b->len + s;
	assert(b->len <= LOGFILE_BUFSZ);
	assert(len >= 0);
	if (len > 0) {
	    logfileNewBuffer(lf);
	}
    }
}

/*
 * only schedule a flush (write) if one isn't scheduled.
 */
static void
logfileFlushEvent(void *data)
{
    Logfile *lf = (Logfile *) data;

    /*
     * This might work better if we keep track of when we wrote last and only
     * schedule a write if we haven't done so in the last second or two.
     */
    logfileQueueWrite(lf);
    eventAdd("logfileFlush", logfileFlushEvent, lf, 1.0, 1);
}


/* External code */

int
logfile_mod_daemon_open(Logfile * lf, const char *path, size_t bufsz, int fatal_flag)
{
    const char *args[5];
    char *tmpbuf;
    l_daemon_t *ll;

    cbdataLock(lf);
    debug(50, 1) ("Logfile Daemon: opening log %s\n", path);
    ll = xcalloc(1, sizeof(*ll));
    lf->data = ll;
    ll->eol = 1;
    {
	args[0] = "(logfile-daemon)";
	args[1] = path;
	args[2] = NULL;
	ll->pid = ipcCreate(IPC_STREAM, Config.Program.logfile_daemon, args, "logfile-daemon", &ll->rfd, &ll->wfd, NULL);
	if (ll->pid < 0)
	    fatal("Couldn't start logfile helper");
    }
    ll->nbufs = 0;

    /* Queue the initial control data */
    tmpbuf = (char *) xmalloc(BUFSIZ);
    snprintf(tmpbuf, BUFSIZ, "r%d\nb%d\n", Config.Log.rotateNumber, Config.onoff.buffered_logs);
    logfile_mod_daemon_append(lf, tmpbuf, strlen(tmpbuf));
    xfree(tmpbuf);

    /* Start the flush event */
    eventAdd("logfileFlush", logfileFlushEvent, lf, 1.0, 1);

    lf->f_close = logfile_mod_daemon_close;
    lf->f_linewrite = logfile_mod_daemon_writeline;
    lf->f_linestart = logfile_mod_daemon_linestart;
    lf->f_lineend = logfile_mod_daemon_lineend;
    lf->f_flush = logfile_mod_daemon_flush;
    lf->f_rotate = logfile_mod_daemon_rotate;

    return 1;
}

static void
logfile_mod_daemon_close(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    debug(50, 1) ("Logfile Daemon: closing log %s\n", lf->path);
    logfileFlush(lf);
    fd_close(ll->rfd);
    fd_close(ll->wfd);
    kill(ll->pid, SIGTERM);
    eventDelete(logfileFlushEvent, lf);
    xfree(ll);
    lf->data = NULL;
    cbdataUnlock(lf);
}

static void
logfile_mod_daemon_rotate(Logfile * lf)
{
    char tb[3];
    debug(50, 1) ("logfileRotate: %s\n", lf->path);
    tb[0] = 'R';
    tb[1] = '\n';
    tb[2] = '\0';
    logfile_mod_daemon_append(lf, tb, 2);
}

/*
 * This routine assumes that up to one line is written. Don't try to
 * call this routine with more than one line or subsequent lines
 * won't be prefixed with the command type and confuse the logging
 * daemon somewhat.
 */
static void
logfile_mod_daemon_writeline(Logfile * lf, const char *buf, size_t len)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    /* Make sure the logfile buffer isn't too large */
    if (ll->nbufs > LOGFILE_MAXBUFS) {
	if (ll->last_warned < squid_curtime - LOGFILE_WARN_TIME) {
	    ll->last_warned = squid_curtime;
	    debug(50, 1) ("Logfile: %s: queue is too large; some log messages have been lost.\n", lf->path);
	}
	return;
    }
    /* Append this data to the end buffer; create a new one if needed */
    /* Are we eol? If so, prefix with our logfile command byte */
    logfile_mod_daemon_append(lf, buf, len);
}

static void
logfile_mod_daemon_linestart(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    char tb[2];
    assert(ll->eol == 1);
    ll->eol = 0;
    tb[0] = 'L';
    tb[1] = '\0';
    logfile_mod_daemon_append(lf, tb, 1);
}

static void
logfile_mod_daemon_lineend(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    logfile_buffer_t *b;
    assert(ll->eol == 0);
    ll->eol = 1;
    /* Kick a write off if the head buffer is -full- */
    if (ll->bufs.head != NULL) {
	b = ll->bufs.head->data;
	if (b->node.next != NULL || !Config.onoff.buffered_logs)
	    logfileQueueWrite(lf);
    }
}

static void
logfile_mod_daemon_flush(Logfile * lf)
{
    l_daemon_t *ll = (l_daemon_t *) lf->data;
    if (commUnsetNonBlocking(ll->wfd)) {
	debug(50, 1) ("Logfile Daemon: Couldn't set the pipe blocking for flush! You're now missing some log entries.\n");
	return;
    }
    while (ll->bufs.head != NULL) {
	logfileHandleWrite(ll->wfd, lf);
    }
    if (commSetNonBlocking(ll->wfd)) {
	fatalf("Logfile Daemon: %s: Couldn't set the pipe non-blocking for flush!\n", lf->path);
	return;
    }
}
