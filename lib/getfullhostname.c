
/* $Id$ */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
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
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect on NEXTSTEP */
#define _SQUID_NETDB_H_
#include <netdb.h>
#endif

#include "util.h"

/*
 *  getfullhostname() - Returns the fully qualified name of the current 
 *  host, or NULL on error.  Pointer is only valid until the next call
 *  to the gethost*() functions.
 */
char *getfullhostname()
{
    struct hostent *hp = NULL;
    static char buf[SQUIDHOSTNAMELEN + 1];
    extern int gethostname();	/* UNIX system call */

    if (gethostname(buf, SQUIDHOSTNAMELEN) < 0)
	return (NULL);
    if ((hp = gethostbyname(buf)) == NULL)
	return (buf);
    return (hp->h_name);
}
