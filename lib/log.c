/*
 * $Id$
 *
 * DEBUG: 
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if __STDC__ && HAVE_STDARG_H
#include <stdarg.h>
#elif HAVE_VARARGS_H
#include <varargs.h>
#endif

#include "ansiproto.h"
#include "util.h"

#ifdef _SQUID_NEXT_
typedef int pid_t;
extern pid_t getpid _PARAMS((void));
#endif


/* Local functions */
static char *standard_msg _PARAMS((void));

/* Local variables */
static FILE *fp_log = NULL;
static FILE *fp_errs = NULL;
static int pid;
static char *pname = NULL;
static char lbuf[2048];

void
init_log3(char *pn, FILE * a, FILE * b)
{
    fp_log = a;
    fp_errs = b;
    pid = getpid();
    pname = xstrdup(pn);
    if ((int) strlen(pname) > 8)
	*(pname + 8) = '\0';
    if (fp_log)
	setbuf(fp_log, NULL);
    if (fp_errs)
	setbuf(fp_errs, NULL);
}

/*
 *  Log() - used like printf(3).  Prints message to stdout.
 */
#if __STDC__
void
Log(char *fmt,...)
{
    va_list ap;

    if (fp_log == NULL)
	return;

    va_start(ap, fmt);
#else
void
Log(va_alist)
     va_dcl
{
    va_list ap;
    char *fmt;

    if (fp_log == NULL)
	return;

    va_start(ap);
    fmt = va_arg(ap, char *);
#endif /* __STDC__ */
    if (fp_log == NULL)
	return;

    lbuf[0] = '\0';
    vsprintf(lbuf, fmt, ap);
    va_end(ap);
    fprintf(fp_log, "%s: %s", standard_msg(), lbuf);
}

/*
 *  errorlog() - used like printf(3).  Prints error message to stderr.
 */
#if __STDC__
void
errorlog(char *fmt,...)
{
    va_list ap;

    if (fp_errs == NULL)
	return;

    va_start(ap, fmt);
#else
void
errorlog(va_alist)
     va_dcl
{
    va_list ap;
    char *fmt;

    if (fp_errs == NULL)
	return;

    va_start(ap);
    fmt = va_arg(ap, char *);
#endif /* __STDC__ */

    if (fp_errs == NULL)
	return;

    lbuf[0] = '\0';
    vsprintf(lbuf, fmt, ap);
    va_end(ap);
    fprintf(fp_errs, "%s: ERROR: %s", standard_msg(), lbuf);
}

/*
 *  fatal() - used like printf(3).  Prints error message to stderr and exits
 */
#if __STDC__
void
fatal(char *fmt,...)
{
    va_list ap;

    if (fp_errs == NULL)
	exit(1);

    va_start(ap, fmt);
#else
void
fatal(va_alist)
     va_dcl
{
    va_list ap;
    char *fmt;

    if (fp_errs == NULL)
	exit(1);

    va_start(ap);
    fmt = va_arg(ap, char *);
#endif /* __STDC__ */

    if (fp_errs == NULL)
	exit(1);

    lbuf[0] = '\0';
    vsprintf(lbuf, fmt, ap);
    va_end(ap);
    fprintf(fp_errs, "%s: FATAL: %s", standard_msg(), lbuf);
    exit(1);
}

/*
 *  log_errno2() - Same as perror(); doesn't print when errno == 0
 */
void
log_errno2(char *file, int line, char *s)
{
    if (errno != 0)
	errorlog("%s [%d]: %s: %s\n", file, line, s, xstrerror());
}


/*
 *  standard_msg() - Prints the standard pid and timestamp
 */
static char *
standard_msg(void)
{
    time_t t;
    static char buf[BUFSIZ];

    t = time(NULL);
    buf[0] = '\0';
    if (pname != NULL)
	sprintf(buf, "[%s] %8.8s", mkhttpdlogtime(&t), pname);
    else
	sprintf(buf, "[%s] %8d", mkhttpdlogtime(&t), pid);
    return buf;
}
