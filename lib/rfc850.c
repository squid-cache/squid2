/* $Id$ */

#include "config.h"
#include "autoconf.h"
#include "version.h"


/*
 *  Adapted from HTSUtils.c in CERN httpd 3.0 (http://info.cern.ch/httpd/)
 *  by Darren Hardy <hardy@cs.colorado.edu>, November 1994.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include "config.h"
#include "util.h"

static int make_month _PARAMS((char *s));
static int make_num _PARAMS((char *s));

static char *month_names[12] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


static int make_num(s)
     char *s;
{
    if (*s >= '0' && *s <= '9')
	return 10 * (*s - '0') + *(s + 1) - '0';
    else
	return *(s + 1) - '0';
}

static int make_month(s)
     char *s;
{
    int i;

    *s = toupper(*s);
    *(s + 1) = tolower(*(s + 1));
    *(s + 2) = tolower(*(s + 2));

    for (i = 0; i < 12; i++)
	if (!strncmp(month_names[i], s, 3))
	    return i;
    return 0;
}


time_t parse_rfc850(str)
     char *str;
{
    char *s;
    struct tm tm;
    time_t t;

    if (!str)
	return 0;

    if ((s = strchr(str, ','))) {	/* Thursday, 10-Jun-93 01:29:59 GMT */
	s++;			/* or: Thu, 10 Jan 1993 01:29:59 GMT */
	while (*s && *s == ' ')
	    s++;
	if (strchr(s, '-')) {	/* First format */
	    if ((int) strlen(s) < 18)
		return 0;
	    tm.tm_mday = make_num(s);
	    tm.tm_mon = make_month(s + 3);
	    tm.tm_year = make_num(s + 7);
	    tm.tm_hour = make_num(s + 10);
	    tm.tm_min = make_num(s + 13);
	    tm.tm_sec = make_num(s + 16);
	} else {		/* Second format */
	    if ((int) strlen(s) < 20)
		return 0;
	    tm.tm_mday = make_num(s);
	    tm.tm_mon = make_month(s + 3);
	    tm.tm_year = (100 * make_num(s + 7) - 1900) + make_num(s + 9);
	    tm.tm_hour = make_num(s + 12);
	    tm.tm_min = make_num(s + 15);
	    tm.tm_sec = make_num(s + 18);

	}
    } else {			/* Try the other format:        */
	s = str;		/* Wed Jun  9 01:29:59 1993 GMT */
	while (*s && *s == ' ')
	    s++;
	if ((int) strlen(s) < 24)
	    return 0;
	tm.tm_mday = make_num(s + 8);
	tm.tm_mon = make_month(s + 4);
	tm.tm_year = make_num(s + 22);
	tm.tm_hour = make_num(s + 11);
	tm.tm_min = make_num(s + 14);
	tm.tm_sec = make_num(s + 17);
    }
    if (tm.tm_sec < 0 || tm.tm_sec > 59 ||
	tm.tm_min < 0 || tm.tm_min > 59 ||
	tm.tm_hour < 0 || tm.tm_hour > 23 ||
	tm.tm_mday < 1 || tm.tm_mday > 31 ||
	tm.tm_mon < 0 || tm.tm_mon > 11 ||
	tm.tm_year < 70 || tm.tm_year > 120) {
	return 0;
    }
    tm.tm_isdst = -1;

#ifdef HAVE_TIMEGM
    t = timegm(&tm);
#elif HAVE_TM_GMTOFF
    t = mktime(&tm);
    {
	time_t cur_t = time(NULL);
	struct tm *local = localtime(&cur_t);
	t += local->tm_gmtoff;
    }
#else
    /* some systems do not have tm_gmtoff so we fake it */
    t = mktime(&tm);
    {
	int dst = 0;
	/*
	 * The following assumes a fixed DST offset of 1 hour,
	 * which is probably wrong.
	 */
	if (tm.tm_isdst > 0)
	    dst = -3600;
	t -= (timezone + dst);
    }
#endif
    return t;
}

char *mkrfc850(t)
     time_t *t;
{
    static char buf[128];

    struct tm *gmt = gmtime(t);

    buf[0] = '\0';
    (void) strftime(buf, 127, "%A, %d-%b-%y %H:%M:%S GMT", gmt);
    return buf;
}

char *mkhttpdlogtime(t)
     time_t *t;
{
    static char buf[128];

    struct tm *gmt = gmtime(t);

#ifndef USE_GMT
    int gmt_min, gmt_hour, gmt_yday, day_offset;
    size_t len;
    struct tm *lt;

    /* localtime & gmtime may use the same static data */
    gmt_min = gmt->tm_min;
    gmt_hour = gmt->tm_hour;
    gmt_yday = gmt->tm_yday;

    lt = localtime(t);
    day_offset = lt->tm_yday - gmt_yday;

    /* wrap round on end of year */
    if (day_offset > 1)
	day_offset = -1;
    else if (day_offset < -1)
	day_offset = 1;

    len = strftime(buf, 127 - 5, "%d/%b/%Y:%H:%M:%S ", lt);
    (void) sprintf(buf + len, "%+03d%02d",
	lt->tm_hour - gmt_hour + 24 * day_offset,
	lt->tm_min - gmt_min);
#else /* USE_GMT */
    buf[0] = '\0';
    (void) strftime(buf, 127, "%d/%b/%Y:%H:%M:%S -000", gmt);
#endif /* USE_GMT */

    return buf;
}

#if 0
int main()
{
    char *x;
    time_t t, pt;

    t = time(NULL);
    x = mkrfc850(&t);
    printf("HTTP Time: %s\n", x);

    pt = parse_rfc850(x);
    printf("Parsed: %d vs. %d\n", pt, t);
}

#endif
