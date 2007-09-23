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
#if HAVE_SYSLOG
#include "logfile_mod_syslog.h"
#endif
#include "logfile_mod_stdio.h"
#include "logfile_mod_udp.h"

CBDATA_TYPE(Logfile);
Logfile *
logfileOpen(const char *path, size_t bufsz, int fatal_flag)
{
    Logfile *lf;
    const char *patharg;
    int ret;

    debug(50, 1) ("Logfile: opening log %s\n", path);

    CBDATA_INIT_TYPE(Logfile);
    lf = cbdataAlloc(Logfile);
    cbdataLock(lf);
    xstrncpy(lf->path, path, MAXPATHLEN);
    patharg = path;

    /* need to call the per-logfile-type code */
    if (strncmp(path, "stdio:", 6) == 0) {
	patharg = path + 6;
	ret = logfile_mod_stdio_open(lf, patharg, bufsz, fatal_flag);
    } else if (strncmp(path, "daemon:", 7) == 0) {
	patharg = path + 7;
	ret = logfile_mod_daemon_open(lf, patharg, bufsz, fatal_flag);
    } else if (strncmp(path, "udp:", 4) == 0) {
	patharg = path + 4;
	ret = logfile_mod_udp_open(lf, patharg, bufsz, fatal_flag);
#if HAVE_SYSLOG
    } else if (strncmp(path, "syslog:", 7) == 0) {
	patharg = path + 7;
	ret = logfile_mod_syslog_open(lf, patharg, bufsz, fatal_flag);
#endif
    } else {
	ret = logfile_mod_stdio_open(lf, patharg, bufsz, fatal_flag);
    }
    if (fatal_flag && !ret) {
	fatalf("logfileOpen: path %s: couldn't open!\n", path);
    }
    assert(lf->data != NULL);

    if (fatal_flag)
	lf->flags.fatal = 1;
    lf->sequence_number = 0;
    return lf;
}

void
logfileClose(Logfile * lf)
{
    debug(50, 1) ("Logfile: closing log %s\n", lf->path);
    lf->f_flush(lf);
    lf->f_close(lf);
    cbdataUnlock(lf);
    cbdataFree(lf);
}

void
logfileRotate(Logfile * lf)
{
    debug(50, 1) ("logfileRotate: %s\n", lf->path);
    lf->f_rotate(lf);
}


void
logfileWrite(Logfile * lf, char *buf, size_t len)
{
    lf->f_linewrite(lf, buf, len);
}

void
logfileLineStart(Logfile * lf)
{
    lf->f_linestart(lf);
}

void
logfileLineEnd(Logfile * lf)
{
    lf->f_lineend(lf);
    lf->sequence_number++;
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
    lf->f_flush(lf);
}
