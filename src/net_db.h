#ifndef NET_DB_H
#define NET_DB_H

typedef struct _net_db {
    char *key;
    struct _net_db *next;
    char network[16];
    int n;
    int pings_sent;
    int pings_recv;
    double hops;
    double rtt;
    time_t next_ping_time;
    time_t last_use_time;
    int link_count;
    struct in_addr addr;
    struct _net_db_name {
	char *name;
	struct _net_db_name *next;
    }           *hosts;
} netdbEntry;

extern void netdbHandlePingReply _PARAMS((const struct sockaddr_in *from, int hops, int rtt));
extern void netdbPingSite _PARAMS((const char *hostname));
extern void netdbInit _PARAMS((void));
extern void netdbDump _PARAMS((StoreEntry *));
extern int netdbHops _PARAMS((struct in_addr));
extern void netdbFreeMemory _PARAMS((void));

#endif /* NET_DB_H */
