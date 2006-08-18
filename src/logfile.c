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

/* How many buffers to keep before we say we've buffered too much */
#define	LOGFILE_MAXBUFS		128

/* Size of the logfile buffer */
/* 
 * For optimal performance this should match LOGFILE_BUFSIZ in logfile-daemon.c
 */
#define	LOGFILE_BUFSZ		32768

/* How many seconds between warnings */
#define	LOGFILE_WARN_TIME	30

#if HAVE_SYSLOG

/* Define LOG_AUTHPRIV as LOG_AUTH on systems still using the old deprecated LOG_AUTH */
#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

typedef struct {
    const char *name;
    int value;
} syslog_symbol_t;

static int
syslog_ntoa(const char *s)
{
#define syslog_symbol(a) #a, a
    static syslog_symbol_t symbols[] =
    {
#ifdef LOG_AUTHPRIV
	{syslog_symbol(LOG_AUTHPRIV)},
#endif
#ifdef LOG_DAEMON
	{syslog_symbol(LOG_DAEMON)},
#endif
#ifdef LOG_LOCAL0
	{syslog_symbol(LOG_LOCAL0)},
#endif
#ifdef LOG_LOCAL1
	{syslog_symbol(LOG_LOCAL1)},
#endif
#ifdef LOG_LOCAL2
	{syslog_symbol(LOG_LOCAL2)},
#endif
#ifdef LOG_LOCAL3
	{syslog_symbol(LOG_LOCAL3)},
#endif
#ifdef LOG_LOCAL4
	{syslog_symbol(LOG_LOCAL4)},
#endif
#ifdef LOG_LOCAL5
	{syslog_symbol(LOG_LOCAL5)},
#endif
#ifdef LOG_LOCAL6
	{syslog_symbol(LOG_LOCAL6)},
#endif
#ifdef LOG_LOCAL7
	{syslog_symbol(LOG_LOCAL7)},
#endif
#ifdef LOG_USER
	{syslog_symbol(LOG_USER)},
#endif
#ifdef LOG_ERR
	{syslog_symbol(LOG_ERR)},
#endif
#ifdef LOG_WARNING
	{syslog_symbol(LOG_WARNING)},
#endif
#ifdef LOG_NOTICE
	{syslog_symbol(LOG_NOTICE)},
#endif
#ifdef LOG_INFO
	{syslog_symbol(LOG_INFO)},
#endif
#ifdef LOG_DEBUG
	{syslog_symbol(LOG_DEBUG)},
#endif
	{NULL, 0}
    };
    syslog_symbol_t *p;

    for (p = symbols; p->name != NULL; ++p)
	if (!strcmp(s, p->name) || !strcmp(s, p->name + 4))
	    return p->value;
    return 0;
}

#define PRIORITY_MASK (LOG_ERR | LOG_WARNING | LOG_NOTICE | LOG_INFO | LOG_DEBUG)
#endif /* HAVE_SYSLOG */

/* Internal code */
static void
logfileNewBuffer(Logfile * lf)
{
    logfile_buffer_t *b;

    debug(50, 5) ("logfileNewBuffer: %s: new buffer\n", lf->path);


    b = xcalloc(1, sizeof(logfile_buffer_t));
    assert(b != NULL);
    b->buf = xcalloc(1, LOGFILE_BUFSZ);
    assert(b->buf != NULL);
    b->size = LOGFILE_BUFSZ;
    b->written_len = 0;
    b->len = 0;
    dlinkAddTail(b, &b->node, &lf->bufs);
    lf->nbufs++;
}

static void
logfileFreeBuffer(Logfile * lf, logfile_buffer_t * b)
{
    assert(b != NULL);
    dlinkDelete(&b->node, &lf->bufs);
    lf->nbufs--;
    xfree(b->buf);
    xfree(b);
}

static void
logfileHandleWrite(int fd, void *data)
{
    Logfile *lf = (Logfile *) data;
    int ret;
    logfile_buffer_t *b;

    /*
     * We'll try writing the first entry until its done - if we
     * get a partial write then we'll re-schedule until its completed.
     * Its naive but it'll do for now.
     */
    b = lf->bufs.head->data;
    assert(b != NULL);
    lf->flush_pending = 0;

    ret = FD_WRITE_METHOD(lf->wfd, b->buf + b->written_len, b->len - b->written_len);
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
    if (lf->bufs.head == NULL) {
	goto finish;
    }
    /* there is, so schedule more */

  reschedule:
    commSetSelect(lf->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
    lf->flush_pending = 1;
  finish:
    return;
}

static void
logfileQueueWrite(Logfile * lf)
{
    if (lf->flush_pending || lf->bufs.head == NULL) {
	return;
    }
    /* Ok, schedule a write-event */
    commSetSelect(lf->wfd, COMM_SELECT_WRITE, logfileHandleWrite, lf, 0);
    lf->flush_pending = 1;
}

static void
logfileAppend(Logfile * lf, char *buf, int len)
{
    logfile_buffer_t *b;
    int s;

    /* Is there a buffer? If not, create one */
    if (lf->bufs.head == NULL) {
	logfileNewBuffer(lf);
    }
    debug(50, 3) ("logfileAppend: %s: appending %d bytes\n", lf->path, len);
    /* Copy what can be copied */
    while (len > 0) {
	b = lf->bufs.tail->data;
	debug(50, 3) ("logfileAppend: current buffer has %d of %d bytes before append\n", b->len, b->size);
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

CBDATA_TYPE(Logfile);
Logfile *
logfileOpen(const char *path, size_t bufsz, int fatal_flag)
{
    Logfile *lf;
    const char *args[5];
    char *tmpbuf;
    CBDATA_INIT_TYPE(Logfile);
    lf = cbdataAlloc(Logfile);
    cbdataLock(lf);
    debug(50, 1) ("Logfile: opening log %s\n", path);
    xstrncpy(lf->path, path, MAXPATHLEN);
    lf->eol = 1;
#if HAVE_SYSLOG
    if (strcmp(path, "syslog") == 0 || strncmp(path, "syslog:", 7) == 0) {
	lf->flags.syslog = 1;
	lf->rfd = -1;
	lf->wfd = -1;
	if (path[6] != '\0') {
	    const char *priority = path + 7;
	    char *facility = (char *) strchr(priority, '|');
	    if (facility) {
		*facility++ = '\0';
		lf->syslog_priority |= syslog_ntoa(facility);
	    }
	    lf->syslog_priority |= syslog_ntoa(priority);
	}
	if ((lf->syslog_priority & PRIORITY_MASK) == 0)
	    lf->syslog_priority |= LOG_INFO;
    } else
#endif
    {
	args[0] = "(logfile-daemon)";
	args[1] = path;
	args[2] = NULL;
	lf->pid = ipcCreate(IPC_STREAM, Config.Program.logfile_daemon, args, "logfile-daemon", &lf->rfd, &lf->wfd);
	if (lf->pid < 0)
	    fatal("Couldn't start logfile helper");
    }
    lf->nbufs = 0;

    /* Queue the initial control data */
    asprintf(&tmpbuf, "r%d\nb%d\n", Config.Log.rotateNumber, Config.onoff.buffered_logs);
    logfileAppend(lf, tmpbuf, strlen(tmpbuf));
    xfree(tmpbuf);

    /* Start the flush event */
    eventAdd("logfileFlush", logfileFlushEvent, lf, 1.0, 1);

    if (fatal_flag)
	lf->flags.fatal = 1;
    return lf;
}

void
logfileClose(Logfile * lf)
{
    debug(50, 1) ("Logfile: closing log %s\n", lf->path);
    logfileFlush(lf);
    fd_close(lf->rfd);
    fd_close(lf->wfd);
    kill(lf->pid, SIGTERM);
    eventDelete(logfileFlushEvent, lf);
    cbdataUnlock(lf);
    cbdataFree(lf);
}

void
logfileRotate(Logfile * lf)
{
    char tb[3];
    debug(50, 1) ("logfileRotate: %s\n", lf->path);
    tb[0] = 'R';
    tb[1] = '\n';
    tb[2] = '\0';
    logfileAppend(lf, tb, 2);
}


/*
 * This routine assumes that up to one line is written. Don't try to
 * call this routine with more than one line or subsequent lines
 * won't be prefixed with the command type and confuse the logging
 * daemon somewhat.
 */
void
logfileWrite(Logfile * lf, char *buf, size_t len)
{
#if HAVE_SYSLOG
    if (lf->flags.syslog) {
	syslog(lf->syslog_priority, "%s", (char *) buf);
	return;
    }
#endif

    /* Make sure the logfile buffer isn't too large */
    if (lf->nbufs > LOGFILE_MAXBUFS) {
	if (lf->last_warned < squid_curtime - LOGFILE_WARN_TIME) {
	    lf->last_warned = squid_curtime;
	    debug(50, 1) ("Logfile: %s: queue is too large; some log messages have been lost.\n", lf->path);
	}
	return;
    }
    /* Append this data to the end buffer; create a new one if needed */
    /* Are we eol? If so, prefix with our logfile command byte */
    logfileAppend(lf, buf, len);
}

void
logfileLineStart(Logfile * lf)
{
    char tb[2];
    assert(lf->eol == 1);
    lf->eol = 0;
    tb[0] = 'L';
    tb[1] = '\0';
    logfileAppend(lf, tb, 1);
}

void
logfileLineEnd(Logfile * lf)
{
    logfile_buffer_t *b;
    assert(lf->eol == 0);
    lf->eol = 1;
    /* Kick a write off if the head buffer is -full- */
    if (lf->bufs.head != NULL) {
	b = lf->bufs.head->data;
	if (b->node.next != NULL)
	    logfileQueueWrite(lf);
    }
}

void
#if STDC_HEADERS
logfilePrintf(Logfile * lf, const char *fmt,...)
#else
logfilePrintf(va_alist)
     va_dcl
#endif
{
    va_list args;
    char buf[8192];
    int s;
#if STDC_HEADERS
    va_start(args, fmt);
#else
    Logfile *lf;
    const char *fmt;
    va_start(args);
    lf = va_arg(args, Logfile *);
    fmt = va_arg(args, char *);
#endif
    s = vsnprintf(buf, 8192, fmt, args);
    if (s > 8192) {
	s = 8192;
	if (fmt[strlen(fmt) - 1] == '\n')
	    buf[8191] = '\n';
    }
    if (s > 0)
	logfileWrite(lf, buf, (size_t) s);
    else
	debug(50, 1) ("Failed to format log data for %s\n", lf->path);
    va_end(args);
}

void
logfileFlush(Logfile * lf)
{
    if (commUnsetNonBlocking(lf->wfd)) {
	debug(50, 1) ("Logfile: Couldn't set the pipe blocking for flush! You're now missing some log entries.\n");
	return;
    }
    while (lf->bufs.head != NULL) {
	logfileHandleWrite(lf->wfd, lf);
    }
    if (commSetNonBlocking(lf->wfd)) {
	fatalf("Logfile: %s: Couldn't set the pipe non-blocking for flush!\n", lf->path);
	return;
    }
}
