/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager Objects
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

#include "squid.h"

#define STAT_TTL 2

extern void shut_down(int);

cacheinfo *HTTPCacheInfo = NULL;
cacheinfo *ICPCacheInfo = NULL;

typedef struct objcache_ds {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    char request[1024];
    int reply_fd;
} ObjectCacheData;

/* user name for shutdown password in /etc/passwd */
char *username = "cache";


/* Parse a object_cache url into components.  By Anawat. */
int
objcache_url_parser(char *host, char *url, char *request, char *password)
{
    int t;

    host[0] = request[0] = password[0] = '\0';
    t = sscanf(url, "cache_object://%[^/]/%[^@]@%s", host, request, password);
    if (t < 2) {
	return -1;
    } else if (t == 2) {
	strcpy(password, "nopassword");
    }
    return 0;
}

int
objcache_CheckPassword(char *password, char *user)
{
    struct passwd *pwd = NULL;
#if HAVE_LIB_SHADOW && defined(SHADOW)
    struct spwd *spwd = NULL;
#endif
    if (!password || !user)
	return -1;
    /* get password record from /etc/passwd */
    if ((pwd = getpwnam(user)) == NULL)
	return -1;
#if HAVE_LIB_SHADOW && defined(SHADOW)
    /* get shadow password record if /etc/shadow exists */
    if (access(SHADOW, F_OK) == 0) {
	enter_suid();
	spwd = getspnam(pwd->pw_name);
	leave_suid();
	if (spwd == NULL)
	    goto try_nonshadow;
	if (strcmp(spwd->sp_pwdp, pw_encrypt(password, spwd->sp_pwdp)) == 0)
	    return 0;
    }
  try_nonshadow:
#endif
    if (strcmp(pwd->pw_passwd, (char *) crypt(password, pwd->pw_passwd)) == 0)
	return 0;
    return -1;
}

int
objcacheStart(int fd, char *url, StoreEntry * entry)
{
    char *buf = NULL;
    char *BADCacheURL = "Bad Object Cache URL %s ... negative cached.\n";
    char *BADPassword = "Incorrect password, sorry.\n";
    LOCAL_ARRAY(char, password, 64);
    struct sockaddr_in peer_socket_name;
    int sock_name_length = sizeof(peer_socket_name);

    /* Create state structure. */
    ObjectCacheData *data = xcalloc(1, sizeof(ObjectCacheData));
    data->reply_fd = fd;
    data->entry = entry;
    /* before we generate new object */
    data->entry->expires = squid_curtime + STAT_TTL;

    debug(16, 3, "objectcacheStart: '%s'\n", url);

    /* Parse url. */
    password[0] = '\0';
    if (objcache_url_parser(url, data->host, data->request, password)) {
	/* override negative TTL */
	data->entry->expires = squid_curtime + STAT_TTL;
	storeAbort(data->entry, "SQUID:OBJCACHE Invalid Syntax!\n");
	safe_free(data);
	safe_free(buf);
	return COMM_ERROR;
    }
    if (getpeername(fd, (struct sockaddr *) &peer_socket_name,
	    &sock_name_length) == -1) {
	debug(16, 1, "getpeername failed??\n");
    }
    /* retrieve object requested */
    if (strcmp(data->request, "shutdown") == 0) {
	if (objcache_CheckPassword(password, username) != 0) {
	    buf = xstrdup(BADPassword);
	    storeAppendPrintf(data->entry, buf);
	    storeAbort(data->entry, "SQUID:OBJCACHE Incorrect Password\n");
	    /* override negative TTL */
	    data->entry->expires = squid_curtime + STAT_TTL;
	    debug(16, 1, "Objcache: Attempt to shutdown %s with incorrect password\n", appname);
	} else {
	    debug(16, 0, "Shutdown by command.\n");
	    /* free up state datastructure */
	    safe_free(data);
	    safe_free(buf);
	    shut_down(0);
	}

    } else if (strcmp(data->request, "info") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->info_get(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/objects") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "objects", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/vm_objects") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "vm_objects", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/utilization") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "utilization", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/ipcache") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "ipcache", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/fqdncache") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "fqdncache", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/dns") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "dns", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/redirector") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "redirector", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/io") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "io", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/reply_headers") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "reply_headers", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/filedescriptors") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->stat_get(HTTPCacheInfo, "filedescriptors", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/status") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->log_status_get(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/enable") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->log_enable(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/disable") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->log_disable(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/clear") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->log_clear(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

#ifdef MENU_SHOW_LOG
    } else if (strcmp(data->request, "log") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->log_get_start(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
#endif

    } else if (strcmp(data->request, "parameter") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->parameter_get(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "server_list") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	HTTPCacheInfo->server_list(HTTPCacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "squid.conf") == 0) {
	HTTPCacheInfo->squid_get_start(HTTPCacheInfo, data->entry);

    } else {
	debug(16, 5, "Bad Object Cache URL %s ... negative cached.\n", url);
	storeAppendPrintf(entry, BADCacheURL, url);
	storeComplete(entry);
    }

    safe_free(data);
    safe_free(buf);
    return COMM_OK;
}
