static char rcsid[] = "$Id$";
/* 
 *  File:         objcache.c
 *  Description:  state machine for object_cache.
 *  Author:       Anawat Chankhunthod, USC
 *  Created:      May 12 1994
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "ansihelp.h"
#include "comm.h"
#include "store.h"
#include "stat.h"
#include "debug.h"
#include "cache_cf.h"
#include "util.h"

#define STAT_TTL 2

extern time_t cached_curtime;
extern void shut_down _PARAMS((int));

cacheinfo *CacheInfo = NULL;

typedef struct objcache_ds {
    StoreEntry *entry;
    char host[HARVESTHOSTNAMELEN + 1];
    char request[1024];
    int reply_fd;
} ObjectCacheData;

/* user name for shutdown password in /etc/passwd */
char *username = "cache";


/* Parse a object_cache url into components.  By Anawat. */
int objcache_url_parser(url, host, request, password)
     char *host;
     char *url;
     char *request;
     char *password;
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

int objcache_CheckPassword(password, user)
     char *password;
     char *user;
{
    struct passwd *pwd = NULL;
    char *salted_passwd = NULL;

    if (!password || !user)
	return -1;

    /* get password record from /etc/passwd */
    if ((pwd = getpwnam(user)) == NULL)
	return -1;

    salted_passwd = pwd->pw_passwd;
    if (strcmp(salted_passwd, (char *) crypt(password, salted_passwd)) == 0)
	return 0;
    return -1;

}

int objcacheStart(fd, url, entry)
     int fd;
     char *url;
     StoreEntry *entry;
{
    char *buf = NULL;
    char *badentry = NULL;
    char *BADCacheURL = "Bad Object Cache URL %s ... negative cached.\n";
    char *BADPassword = "Incorrect password, sorry.\n";
    char password[64];
    struct sockaddr_in peer_socket_name;
    int sock_name_length = sizeof(peer_socket_name);

    /* Create state structure. */
    ObjectCacheData *data = (ObjectCacheData *) xcalloc(1, sizeof(ObjectCacheData));
    data->reply_fd = fd;
    data->entry = entry;
    /* before we generate new object */
    data->entry->expires = cached_curtime + STAT_TTL;

    debug(3, "objectcacheStart - url: %s\n", url);

    /* Parse url. */
    password[0] = '\0';
    if (objcache_url_parser(url, data->host, data->request, password)) {
	/* override negative TTL */
	data->entry->expires = cached_curtime + STAT_TTL;
	storeAbort(data->entry, "CACHED:OBJCACHE Invalid Syntax!\n");
	safe_free(data);
	safe_free(buf);
	return COMM_ERROR;
    }
    if (getpeername(fd, (struct sockaddr *) &peer_socket_name,
	    &sock_name_length) == -1) {
	debug(1, "getpeername failed??\n");
    }
    if (ip_access_check(peer_socket_name.sin_addr, manager_ip_acl)
	== IP_DENY) {		/* Access Deny */
	storeAbort(data->entry, "CACHED:OBJCACHE Access Denied!\n");
	/* override negative TTL */
	data->entry->expires = cached_curtime + STAT_TTL;
	safe_free(data);
	safe_free(buf);
	return COMM_ERROR;
    }
    /* retrieve object requested */
    if (strncmp(data->request, "shutdown", strlen("shutdown")) == 0) {
	if (objcache_CheckPassword(password, username) != 0) {
	    buf = xstrdup(BADPassword);
	    storeAppend(data->entry, buf, strlen(buf));
	    storeAbort(data->entry, "CACHED:OBJCACHE Incorrect Password\n");
	    /* override negative TTL */
	    data->entry->expires = cached_curtime + STAT_TTL;
	    debug(1, "Objcache: Attempt to shutdown cached with incorrect password\n");
	} else {
	    debug(0, "Shutdown by command.\n");
	    /* free up state datastructure */
	    safe_free(data);
	    safe_free(buf);
	    shut_down(0);
	}

    } else if (strncmp(data->request, "info", strlen("info")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->info_get(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "stats/objects", strlen("stats/objects")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "objects", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "stats/vm_objects", strlen("stats/vm_objects")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "vm_objects", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "stats/utilization", strlen("stats/utilization")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "utilization", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "stats/general", strlen("stats/general")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "general", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "log/status", strlen("log/status")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_status_get(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "log/enable", strlen("log/enable")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_enable(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "log/disable", strlen("log/disable")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_disable(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "log/clear", strlen("log/clear")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_clear(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

#ifdef MENU_SHOW_LOG
    } else if (strncmp(data->request, "log", strlen("log")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_get_start(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
#endif

    } else if (strncmp(data->request, "parameter", strlen("parameter")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->parameter_get(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "server_list", strlen("server_list")) == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->server_list(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strncmp(data->request, "cached.conf", strlen("cached.conf")) == 0) {
	CacheInfo->cached_get_start(CacheInfo, data->entry);

    } else {
	debug(5, "Bad Object Cache URL %s ... negative cached.\n", url);
	badentry = (char *) xcalloc(1, strlen(BADCacheURL) + strlen(url));
	sprintf(badentry, BADCacheURL, url);
	storeAppend(entry, badentry, strlen(badentry));
	safe_free(badentry);
	storeComplete(entry);
    }

    safe_free(data);
    safe_free(buf);
    return COMM_OK;
}
