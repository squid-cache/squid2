/* $Id$ */

/*
 * DEBUG: Section 16          objcache
 */


#include "squid.h"

#define STAT_TTL 2

extern void shut_down _PARAMS((int));

cacheinfo *CacheInfo = NULL;

typedef struct objcache_ds {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
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
    char *BADCacheURL = "Bad Object Cache URL %s ... negative cached.\n";
    char *BADPassword = "Incorrect password, sorry.\n";
    char password[64];
    struct sockaddr_in peer_socket_name;
    int sock_name_length = sizeof(peer_socket_name);

    /* Create state structure. */
    ObjectCacheData *data = xcalloc(1, sizeof(ObjectCacheData));
    data->reply_fd = fd;
    data->entry = entry;
    /* before we generate new object */
    data->entry->expires = squid_curtime + STAT_TTL;

    debug(16, 3, "objectcacheStart - url: %s\n", url);

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
	CacheInfo->info_get(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/objects") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "objects", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/vm_objects") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "vm_objects", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/utilization") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "utilization", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/general") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "general", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/io") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "io", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "stats/reply_headers") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->stat_get(CacheInfo, "reply_headers", data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/status") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_status_get(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/enable") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_enable(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/disable") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_disable(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "log/clear") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_clear(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

#ifdef MENU_SHOW_LOG
    } else if (strcmp(data->request, "log") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->log_get_start(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
#endif

    } else if (strcmp(data->request, "parameter") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->parameter_get(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "server_list") == 0) {
	BIT_SET(data->entry->flag, DELAY_SENDING);
	CacheInfo->server_list(CacheInfo, data->entry);
	BIT_RESET(data->entry->flag, DELAY_SENDING);
	storeComplete(data->entry);

    } else if (strcmp(data->request, "squid.conf") == 0) {
	CacheInfo->squid_get_start(CacheInfo, data->entry);

    } else {
	debug(16, 5, "Bad Object Cache URL %s ... negative cached.\n", url);
	storeAppendPrintf(entry, BADCacheURL, url);
	storeComplete(entry);
    }

    safe_free(data);
    safe_free(buf);
    return COMM_OK;
}
