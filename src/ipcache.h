/*  $Id$ */

#ifndef _IPCACHE_H_
#define _IPCACHE_H_

typedef int (*IPH) _PARAMS((int, struct hostent *, void *));


typedef struct _ipcache_entry {
    /* first two items must be equivalent to hash_link in hash.h */
    char *name;
    struct _ipcache_entry *next;
    long timestamp;
    long lastref;
    long ttl;
    unsigned char addr_count;
    unsigned char alias_count;
    enum {
	CACHED, PENDING, NEGATIVE_CACHED
    } status:3;
    struct hostent entry;
    struct _ip_pending *pending_head;
    struct _ip_pending *pending_tail;
} ipcache_entry;

extern int ipcache_nbgethostbyname _PARAMS((char *, int, IPH, void *));
extern int ipcache_unregister _PARAMS((char *, int));
extern struct hostent *ipcache_gethostbyname _PARAMS((char *));
extern void ipcache_flush _PARAMS((void));
extern void ipcache_init _PARAMS((void));
extern void stat_ipcache_get _PARAMS((StoreEntry *, cacheinfo *));
extern void ipcacheShutdownServers _PARAMS((void));

#endif
