
/*
 * $Id$
 *
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

#ifndef _STORE_H_
#define _STORE_H_

#define MAX_FILE_NAME_LEN 	256
#define MIN_PENDING 		1
#define MIN_CLIENT 		1

#define BIT_SET(flag, bit) 	((flag) |= (bit))
#define BIT_RESET(flag, bit) 	((flag) &= ~(bit))
#define BIT_TEST(flag, bit) 	((flag) & (bit))

/* 
 * KEY_URL              If e->key and e->url point to the same location
 * KEY_CHANGE           If the key for this URL has been changed
 */

#define READ_DEFERRED		(1<<15)
#define ENTRY_NEGCACHED		(1<<14)
#define HIERARCHICAL 		(1<<13)		/* can we query neighbors? */
#define KEY_PRIVATE 		(1<<12)		/* is the key currently private? */
#define ENTRY_DISPATCHED 	(1<<11)
#define ENTRY_HTML 		(1<<10)
#define KEY_CHANGE 		(1<<9)
#define KEY_URL    		(1<<8)
#define ENTRY_CACHABLE   	(1<<7)
#define REFRESH_REQUEST   	(1<<6)
#define RELEASE_REQUEST 	(1<<5)
#define ABORT_MSG_PENDING 	(1<<4)
#define DELAY_SENDING 		(1<<3)
#define CLIENT_ABORT_REQUEST 	(1<<2)
#define DELETE_BEHIND   	(1<<1)
#define IP_LOOKUP_PENDING      	(1<<0)


/* keep track each client receiving data from that particular StoreEntry */
typedef struct _ClientStatusEntry {
    int fd;
    int last_offset;
} ClientStatusEntry;


/* --------------- SPLIT STORE STRUCTURE ----------------- */
/* Split 'StoreEntry' into two structure, when object is purged out from
 * memory, one structure can be freed for saving memory
 */

/* This structure can be freed while object is purged out from memory */
typedef struct _MemObject {
    char *mime_hdr;		/* Mime header info */
    mem_ptr data;

/* These items are mutually exclusive */
    char *e_swap_buf;
    edge *e_pings_first_miss;
    int w_rtt;			/* weighted RTT in msec */
    struct timeval start_ping;

/* These items are also mutually exclusive */
    int e_swap_buf_len;
    unsigned char e_pings_n_pings;
    unsigned char e_pings_n_acks;

    /* move here for alignment of memory */
    unsigned char pending_list_size;

    int e_swap_access;
    char *e_abort_msg;
    log_type abort_code;

    int e_current_len;
    /* The lowest offset that store keep VM copy around
     * use for "delete_behind" mechanism for a big object */
    int e_lowest_offset;
    ClientStatusEntry **client_list;
    int client_list_size;

    u_num32 swap_offset;

    /* use another field to avoid changing the existing code */
    struct pentry **pending;

    short swapin_fd;
    short swapout_fd;
    int fd_of_first_client;
    struct _http_reply *reply;
    request_t *request;
    SIH swapin_complete_handler;
    void *swapin_complete_data;
} MemObject;

enum {
    NOT_IN_MEMORY,
    SWAPPING_IN,
    IN_MEMORY
};

enum {
    PING_WAITING,
    PING_TIMEOUT,
    PING_DONE,
    PING_NONE
};

enum {
    STORE_OK,
    STORE_PENDING,
    STORE_ABORTED
};

enum {
    NO_SWAP,
    SWAPPING_OUT,
    SWAP_OK
};

typedef unsigned int store_status_t;
typedef unsigned int mem_status_t;
typedef unsigned int ping_status_t;
typedef unsigned int swap_status_t;

extern char *memStatusStr[];
extern char *pingStatusStr[];
extern char *storeStatusStr[];
extern char *swapStatusStr[];

/* A cut down structure for store manager */
struct sentry {
    /* first two items must be same as hash_link in hash.h */
    char *key;
    struct sentry *next;
    char *url;

    /* to stru which can be freed while object is purged out from memory */
    MemObject *mem_obj;

    u_num32 flag;
    u_num32 timestamp;
    u_num32 refcount;
    time_t lastref;
    time_t expires;
    time_t lastmod;

    int object_len;
    int swap_file_number;

    mem_status_t mem_status:3;
    ping_status_t ping_status:3;
    store_status_t store_status:3;
    swap_status_t swap_status:3;
    method_t method:4;

    /* WARNING: Explicit assummption that fewer than 256
     * WARNING:  clients all hop onto the same object.  The code
     * WARNING:  doesn't deal with this case.  */
    unsigned char lock_count;

};

/* ----------------------------------------------------------------- */

typedef int (*PIF) (int, StoreEntry *, void *);

typedef struct pentry {
    int fd;
    PIF handler;
    void *data;
} PendingEntry;

extern StoreEntry *storeGet __P((char *));
extern StoreEntry *storeCreateEntry __P((char *, char *, int, method_t));
extern void storeSetPublicKey __P((StoreEntry *));
extern void storeSetPrivateKey __P((StoreEntry *));
extern StoreEntry *storeGetFirst __P((void));
extern StoreEntry *storeGetNext __P((void));
extern StoreEntry *storeLRU __P((void));
extern int storeWalkThrough __P((int (*proc) __P((void)), void *data));
extern int storePurgeOld __P((void));
extern void storeSanityCheck __P((void));
extern void storeComplete __P((StoreEntry *));
extern void storeInit __P((void));
extern int storeReleaseEntry __P((StoreEntry *));
extern int storeClientWaiting __P((StoreEntry *));
extern void storeAbort __P((StoreEntry *, char *));
extern void storeAppend __P((StoreEntry *, char *, int));
extern int storeGetMemSize __P((void));
extern int storeGetSwapSize __P((void));
extern int storeGetSwapSpace __P((int));
extern int storeEntryValidToSend __P((StoreEntry *));
extern int storeEntryValidLength __P((StoreEntry *));
extern int storeEntryLocked __P((StoreEntry *));
extern int storeLockObject __P((StoreEntry *, SIH, void *));
extern int storeOriginalKey __P((StoreEntry *));
extern int storeRelease __P((StoreEntry *));
extern int storeUnlockObject __P((StoreEntry *));
extern int storeUnregister __P((StoreEntry *, int));
extern char *storeGeneratePublicKey __P((char *, method_t));
extern char *storeGeneratePrivateKey __P((char *, method_t, int));
extern char *storeMatchMime __P((StoreEntry *, char *, char *, int));
extern int storeAddSwapDisk __P((char *));
extern char *swappath __P((int));
extern void storeStartDeleteBehind __P((StoreEntry *));
extern int storeClientCopy __P((StoreEntry *, int, int, char *, int *, int));
extern int storePendingNClients __P((StoreEntry * e));
extern char *storeSwapFullPath __P((int, char *));
extern int storeWriteCleanLog __P((void));
extern int storeRegister __P((StoreEntry *, int, PIF, void *));
extern int urlcmp __P((char *, char *));
extern int swapInError __P((int fd, StoreEntry *));
extern int storeMaintainSwapSpace __P((void));
extern void storeExpireNow __P((StoreEntry *));
extern void storeReleaseRequest __P((StoreEntry *));
extern void storeRotateLog __P((void));
extern unsigned int getKeyCounter __P((void));
extern int storeGetLowestReaderOffset __P((StoreEntry *));
extern void storeCloseLog __P((void));
extern void storeConfigure __P((void));
extern void storeNegativeCache __P((StoreEntry *));

#if defined(__STRICT_ANSI__)
extern void storeAppendPrintf __P((StoreEntry *, char *,...));
#else
extern void storeAppendPrintf __P(());
#endif

extern int store_rebuilding;
#define STORE_NOT_REBUILDING 0
#define STORE_REBUILDING_SLOW 1
#define STORE_REBUILDING_FAST 2

#define SWAP_DIRECTORIES_L1	16
#define SWAP_DIRECTORIES_L2	256
extern int ncache_dirs;

#endif
