/* $Id$ */

#ifndef STAT_H
#define STAT_H

/* logfile status */
#define LOG_ENABLE  1
#define LOG_DISABLE 0

typedef struct _proto_stat {
    char protoname[25];
    int object_count;

    struct _usage {
	int max;
	int avg;
	int min;
	int now;
    } kb;

    unsigned int hit;
    unsigned int miss;
    float hitratio;
    unsigned int transferrate;
    unsigned int refcount;
    unsigned int transferbyte;

} proto_stat;

typedef struct _meta_data_stat {
    int hot_vm;
    int store_entries;
    int store_in_mem_objects;
    int ipcache_count;
    int hash_links;
    int url_strings;
} Meta_data;

extern Meta_data meta_data;

struct _cacheinfo {

    /* information retrieval method */
    /* get a processed statistic object */
    void (*stat_get) _PARAMS((struct _cacheinfo * c, char *req, StoreEntry * sentry));

    /* get a processed info object */
    void (*info_get) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a processed logfile object */
    void (*log_get_start) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a processed logfile status */
    void (*log_status_get) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a processed squid.conf object */
    void (*squid_get_start) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a parameter object */
    void (*parameter_get) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));
    void (*server_list) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));


    /* get a total bytes for object in cache */
    int (*cache_size_get) _PARAMS((struct _cacheinfo * c));

    /* statistic update method */

    /* add a transaction to system log */
    void (*log_append) _PARAMS((struct _cacheinfo * obj, char *url, char *id,
	    int size, char *action, char *method, int http_code, int msec));

    /* clear logfile */
    void (*log_clear) _PARAMS((struct _cacheinfo * obj, StoreEntry * sentry));

    /* enable logfile */
    void (*log_enable) _PARAMS((struct _cacheinfo * obj, StoreEntry * sentry));

    /* disable logfile */
    void (*log_disable) _PARAMS((struct _cacheinfo * obj, StoreEntry * sentry));

    /* protocol specific stat update method */
    /* return a proto_id for a given url */
         protocol_t(*proto_id) _PARAMS((char *url));

    /* a new object cached. update obj count, size */
    void (*proto_newobject) _PARAMS((struct _cacheinfo * c, protocol_t proto_id, int len, int flag));

    /* an object purged */
    void (*proto_purgeobject) _PARAMS((struct _cacheinfo * c, protocol_t proto_id, int len));

    /* an object is referred to. */
    void (*proto_touchobject) _PARAMS((struct _cacheinfo * c, protocol_t proto_id, int len));

    /* a hit. update hit count, transfer byted. refcount */
    void (*proto_hit) _PARAMS((struct _cacheinfo * obj, protocol_t proto_id));

    /* a miss. update miss count. refcount */
    void (*proto_miss) _PARAMS((struct _cacheinfo * obj, protocol_t proto_id));

    /* dummy Notimplemented object handler */
    void (*NotImplement) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* stat table and data */
    char logfilename[256];	/* logfile name */
    int logfile_fd;		/* logfile fd */
    int logfile_access;		/* logfile access code */
    /* logfile status {enable, disable} */
    int logfile_status;

    /* protocol stat data */
    proto_stat proto_stat_data[PROTO_MAX + 1];

};

struct _iostats {
    struct {
	int reads;
	int reads_deferred;
	int read_hist[16];
	int writes;
	int write_hist[16];
    } Http, Ftp;
};

extern struct _iostats IOStats;

extern cacheinfo *CacheInfo;
extern unsigned long ntcpconn;
extern unsigned long nudpconn;

extern void stat_init _PARAMS((cacheinfo **, char *));
extern void stat_rotate_log _PARAMS((void));


#endif /*STAT_H */
