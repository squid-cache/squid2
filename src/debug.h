/*  $Id$ */

#ifndef _DEBUG_H_
#define _DEBUG_H_

extern char *_db_file;
extern int _db_line;
extern int syslog_enable;
extern FILE *debug_log;

void _db_init _PARAMS((char *logfile));
#if defined(__STRICT_ANSI__)
void _db_print _PARAMS((int, int, char *,...));
#else
void _db_print();
#endif


/* always define debug, but DEBUG not define set the db_level to 0 */

#define debug \
	if ((_db_file = __FILE__) && \
	    (_db_line = __LINE__)) \
        _db_print

#define safe_free(x)	if (x) { xfree(x); x = NULL; }

extern void _db_rotate_log _PARAMS((void));

#endif /* _DEBUG_H_ */
