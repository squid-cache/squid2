/*
 *  $Id$
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>
#include "ansihelp.h"

extern int _db_level;
extern char *_db_file;
extern int _db_line;
extern int syslog_enable;
extern int stderr_enable;
extern FILE *debug_log;

void _db_init _PARAMS((char *, int, char *));
#if defined(__STRICT_ANSI__)
void _db_print _PARAMS((int,...));
#else
void _db_print();
#endif


/* always define debug, but DEBUG not define set the db_level to 0 */

#define debug \
	if ((_db_level >= 0) && \
	    (_db_file = __FILE__) && \
	    (_db_line = __LINE__)) \
        _db_print

#define safe_free(x)	if (x) { free(x); x = NULL; }

#endif /* _DEBUG_H_ */
