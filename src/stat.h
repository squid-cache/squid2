/* 
 *  $Id$
 *
 *  File:         stat.h
 *  Description:  prototype for stat module for object cache
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
#if !defined(STAT_H)
#define STAT_H

#include <malloc.h>
#include <sys/time.h>
#include "proto.h"
#include "store.h"
#include "ansihelp.h"

/* protocol id */
#define PROTOCOL_SUPPORTED 3
#define PROTOCOL_EXTRA     4	/* included total, cacheobj, abort, notimplemented */
#define TOTAL_ID     0
#define HTTP_ID      1
#define GOPHER_ID    2
#define FTP_ID       3
#define CACHEOBJ_ID  PROTOCOL_SUPPORTED + 1
#define ABORT_ID     PROTOCOL_SUPPORTED + 2
#define NOTIMPLE_ID  PROTOCOL_SUPPORTED + 3	/* for robustness */

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

typedef struct _cacheinfo {

    /* information retrieval method */
    /* get a processed statistic object */
    void (*stat_get) _PARAMS((struct _cacheinfo * c, char *req, StoreEntry * sentry));

    /* get a processed info object */
    void (*info_get) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a processed logfile object */
    void (*log_get_start) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a processed logfile status */
    void (*log_status_get) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a processed cached.conf object */
    void (*cached_get_start) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* get a parameter object */
    void (*parameter_get) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));
    void (*server_list) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));


    /* get a total bytes for object in cache */
    int (*cache_size_get) _PARAMS((struct _cacheinfo * c));

    /* statistic update method */

    /* add a transaction to system log */
    void (*log_append) _PARAMS((struct _cacheinfo * obj, char *url, char *id,
	    int size, char *action, char *method));

    /* clear logfile */
    void (*log_clear) _PARAMS((struct _cacheinfo * obj, StoreEntry * sentry));

    /* enable logfile */
    void (*log_enable) _PARAMS((struct _cacheinfo * obj, StoreEntry * sentry));

    /* disable logfile */
    void (*log_disable) _PARAMS((struct _cacheinfo * obj, StoreEntry * sentry));

    /* protocol specific stat update method */
    /* return a proto_id for a given url */
    int (*proto_id) _PARAMS((char *url));

    /* a new object cached. update obj count, size */
    void (*proto_newobject) _PARAMS((struct _cacheinfo * c, int proto_id, int len, int flag));

    /* an object purged */
    void (*proto_purgeobject) _PARAMS((struct _cacheinfo * c, int proto_id, int len));

    /* an object is referred to. */
    void (*proto_touchobject) _PARAMS((struct _cacheinfo * c, int proto_id, int len));

    /* a hit. update hit count, transfer byted. refcount */
    void (*proto_hit) _PARAMS((struct _cacheinfo * obj, int proto_id));

    /* a miss. update miss count. refcount */
    void (*proto_miss) _PARAMS((struct _cacheinfo * obj, int proto_id));

    /* dummy Notimplemented object handler */
    void (*NotImplement) _PARAMS((struct _cacheinfo * c, StoreEntry * sentry));

    /* stat table and data */
    char logfilename[256];	/* logfile name */
    int logfile_fd;		/* logfile fd */
    int logfile_access;		/* logfile access code */
    /* logfile status {enable, disable} */
    int logfile_status;

    /* protocol stat data */
    proto_stat proto_stat_data[PROTOCOL_SUPPORTED + PROTOCOL_EXTRA];


} cacheinfo;

extern cacheinfo *CacheInfo;

extern void stat_init();

#endif /*STAT_H */
