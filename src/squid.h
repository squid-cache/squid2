
/* $Id$ */

#include "config.h"

#if SQUID_FD_SETSIZE > 256
#define FD_SETSIZE SQUID_FD_SETSIZE
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect NEXTSTEP */
#define _SQUID_NETDB_H_
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>	/* needs sys/time.h above it */
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_LIBC_H
#include <libc.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if defined(__STRICT_ANSI__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif

/* Make sure syslog goes after stdarg/varargs */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif

#define SQUID_INADDR_NONE -1

#if !defined(HAVE_RUSAGE) && defined(_SQUID_HPUX_)
#define HAVE_RUSAGE
#define getrusage(a, b)  syscall(SYS_GETRUSAGE, a, b)
#endif

#if !defined(HAVE_GETPAGESIZE) && defined(_SQUID_HPUX_)
#define HAVE_GETPAGESIZE
#define getpagesize( )   sysconf(_SC_PAGE_SIZE)
#endif

#ifndef BUFSIZ
#define BUFSIZ  4096		/* make reasonable guess */
#endif

#if !defined(SUN_LEN)
#define SUN_LEN(su) \
        (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

typedef struct sentry StoreEntry;
typedef struct mem_hdr *mem_ptr;
typedef struct _edge edge;
typedef struct icp_common_s icp_common_t;
typedef struct _cacheinfo cacheinfo;

/* 32 bit integer compatability hack */
#if SIZEOF_INT == 4
typedef int num32;
typedef unsigned int u_num32;
#elif SIZEOF_LONG == 4
typedef long num32;
typedef unsigned long u_num32;
#else
typedef long num32;		/* assume that long's are 32bit */
typedef unsigned long u_num32;
#endif
#define NUM32LEN sizeof(num32)	/* this should always be 4 */

#include "GNUregex.h"
#include "ansihelp.h"

typedef void (*SIH) _PARAMS((int, void *));	/* swap in */

#include "cache_cf.h"
#include "comm.h"
#include "debug.h"
#include "disk.h"
#include "dynamic_array.h"
#include "fdstat.h"
#include "filemap.h"
#include "hash.h"
#include "url.h"
#include "proto.h"
#include "icp.h"
#include "errorpage.h"		/* must go after icp.h */
#include "ipcache.h"
#include "mime.h"
#include "neighbors.h"
#include "stack.h"
#include "stat.h"
#include "stmem.h"
#include "store.h"
#include "tools.h"
#include "ttl.h"
#include "storetoString.h"
#include "http.h"
#include "ftp.h"
#include "gopher.h"
#include "wais.h"
#include "ssl.h"
#include "objcache.h"
#include "send-announce.h"
#include "acl.h"
#include "util.h"
#include "background.h"

#if !HAVE_TEMPNAM
#include "tempnam.h"
#endif

extern time_t squid_starttime;	/* main.c */
extern time_t next_cleaning;	/* main.c */
extern int catch_signals;	/* main.c */
extern int do_reuse;		/* main.c */
extern int theHttpConnection;	/* main.c */
extern int theIcpConnection;	/* main.c */
extern int shutdown_pending;	/* main.c */
extern int reread_pending;	/* main.c */
extern int opt_unlink_on_reload;	/* main.c */
extern int opt_reload_hit_only;	/* main.c */
extern int vhost_mode;		/* main.c */
extern char *version_string;	/* main.c */
extern char *appname;		/* main.c */
