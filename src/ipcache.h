/*  $Id$ */

#ifndef _IPCACHE_H_
#define _IPCACHE_H_

typedef int (*IPH) _PARAMS((int, struct hostent *, void *));

typedef enum {
    IP_CACHED,
    IP_PENDING,
    IP_NEGATIVE_CACHED
} ipcache_status_t;

#define IP_BLOCKING_LOOKUP	0x01
#define IP_LOOKUP_IF_MISS	0x02
#define IP_LOCK_ENTRY		0x04

typedef struct _ipcache_entry {
    /* first two items must be equivalent to hash_link in hash.h */
    char *name;
    struct _ipcache_entry *next;
    time_t timestamp;
    time_t lastref;
    time_t ttl;
    unsigned char addr_count;
    unsigned char alias_count;
    unsigned char lock;
    struct hostent entry;
    struct _ip_pending *pending_head;
    ipcache_status_t status:3;
} ipcache_entry;

extern int ipcache_nbgethostbyname _PARAMS((char *name, int fd, IPH handler, void *handlerData));
extern int ipcache_unregister _PARAMS((char *, int));
extern struct hostent *ipcache_gethostbyname _PARAMS((char *, int flags));
extern void ipcache_init _PARAMS((void));
extern void stat_ipcache_get _PARAMS((StoreEntry *, cacheinfo *));
extern void ipcacheShutdownServers _PARAMS((void));
extern void ipcacheOpenServers _PARAMS((void));
extern void ipcacheLockEntry _PARAMS((char *));

extern char *dns_error_message;

#define IPCACHE_AV_FACTOR 1000

#endif
