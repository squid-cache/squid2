
/* $Id$ */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#if defined(__STRICT_ANSI__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif
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

#ifdef UNUSED_CODE
/*
 *  init_log() - Initializes the logging routines.  Log() prints to 
 *  FILE *a, and errorlog() prints to FILE *b;
 */
void init_log(a, b)
     FILE *a, *b;
{
    fp_log = a;
    fp_errs = b;
    pid = getpid();
    pname = NULL;
    if (fp_log)
	setbuf(fp_log, NULL);
    if (fp_errs)
	setbuf(fp_errs, NULL);
}
#endif

void init_log3(pn, a, b)
     char *pn;
     FILE *a, *b;
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
#if defined(__STRICT_ANSI__)
void Log(char *fmt,...)
{
    va_list ap;

    if (fp_log == NULL)
	return;

    va_start(ap, fmt);
#else
void Log(va_alist)
     va_dcl
{
    va_list ap;
    char *fmt;

    if (fp_log == NULL)
	return;

    va_start(ap);
    fmt = va_arg(ap, char *);
#endif /* __STRICT_ANSI__ */
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
#if defined(__STRICT_ANSI__)
void errorlog(char *fmt,...)
{
    va_list ap;

    if (fp_errs == NULL)
	return;

    va_start(ap, fmt);
#else
void errorlog(va_alist)
     va_dcl
{
    va_list ap;
    char *fmt;

    if (fp_errs == NULL)
	return;

    va_start(ap);
    fmt = va_arg(ap, char *);
#endif /* __STRICT_ANSI__ */

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
#if defined(__STRICT_ANSI__)
void fatal(char *fmt,...)
{
    va_list ap;

    if (fp_errs == NULL)
	exit(1);

    va_start(ap, fmt);
#else
void fatal(va_alist)
     va_dcl
{
    va_list ap;
    char *fmt;

    if (fp_errs == NULL)
	exit(1);

    va_start(ap);
    fmt = va_arg(ap, char *);
#endif /* __STRICT_ANSI__ */

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
void log_errno2(file, line, s)
     char *file;
     int line;
     char *s;
{
    if (errno != 0)
	errorlog("%s [%d]: %s: %s\n", file, line, s, xstrerror());
}


/*
 *  standard_msg() - Prints the standard pid and timestamp
 */
static char *standard_msg()
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
