/*  $Id$ */

#ifndef _STORE_H_
#define _STORE_H_

#define MAX_FILE_NAME_LEN 	256
#define MIN_PENDING 		1
#define MIN_CLIENT 		1

#define BIT_SET(flag, bit) 	((flag) |= (bit))
#define BIT_RESET(flag, bit) 	((flag) &= ~(bit))
#define BIT_TEST(flag, bit) 	((flag) & (bit))

#define REQ_DISPATCHED 		(1<<11)
#define REQ_HTML 		(1<<10)
#define KEY_CHANGE 		(1<<9)
#define KEY_URL    		(1<<8)
#define CACHABLE   		(1<<7)
#define REFRESH_REQUEST   	(1<<6)
#define RELEASE_REQUEST 	(1<<5)
#define ABORT_MSG_PENDING 	(1<<4)
#define DELAY_SENDING 		(1<<3)
#define CLIENT_ABORT_REQUEST 	(1<<2)
#define DELETE_BEHIND   	(1<<1)
#define IP_LOOKUP_PENDING      	(1<<0)

/* type id for REQUEST opcode */
#define REQUEST_OP_GET     	0
#define REQUEST_OP_POST    	1
#define REQUEST_OP_HEAD    	2

extern char *HTTP_OPS[];


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

/* These items are also mutually exclusive */
    int e_swap_buf_len;
    unsigned char e_pings_n_pings;
    unsigned char e_pings_n_acks;

    /* move here for alignment of memory */
    unsigned char pending_list_size;

    int e_swap_access;
    char *e_abort_msg;

    int e_current_len;
    /* The lowest offset that store keep VM copy around
     * use for "delete_behind" mechanism for a big object */
    int e_lowest_offset;
    ClientStatusEntry **client_list;
    int client_list_size;

    u_num32 swap_offset;

    /* use another field to avoid changing the existing code */
    struct pentry **pending;

    unsigned short swap_fd;
    int fd_of_first_client;

} MemObject;

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
    u_num32 lastref;
    u_num32 refcount;
    u_num32 expires;

    int object_len;
    int swap_file_number;

    enum {
	NOT_IN_MEMORY, SWAPPING_IN, IN_MEMORY
    } mem_status:3;
    enum {
	WAITING, TIMEOUT, DONE, NOPING
    } ping_status:3;
    enum {
	STORE_OK, STORE_PENDING, STORE_ABORTED
    } status:3;
    enum {
	NO_SWAP, SWAPPING_OUT, SWAP_OK
    } swap_status:3;
    enum {
	REQ_GET = 0, REQ_POST = 1, REQ_HEAD = 2
    } type_id:3;


    /* WARNING: Explicit assummption that fewer than 256
     * WARNING:  clients all hop onto the same object.  The code
     * WARNING:  doesn't deal with this case.
     */
    unsigned char lock_count;

};

/* ----------------------------------------------------------------- */

typedef int (*PIF) _PARAMS((int, StoreEntry *, caddr_t));

typedef struct pentry {
    short fd;
    PIF handler;
    caddr_t data;
} PendingEntry;

extern int has_mem_obj _PARAMS((StoreEntry *));
extern StoreEntry *storeGet _PARAMS((char *));
extern StoreEntry *storeAdd _PARAMS((char *, char *, char *, int, int, int));
extern StoreEntry *storeGetFirst _PARAMS((void));
extern StoreEntry *storeGetNext _PARAMS((void));
extern StoreEntry *storeLRU _PARAMS((void));
extern int storeWalkThrough _PARAMS((int (*proc) (), caddr_t data));
extern int storePurgeOld _PARAMS((void));
extern void storeChangeKey _PARAMS((StoreEntry *));
extern void storeSanityCheck _PARAMS(());
extern void storeComplete _PARAMS((StoreEntry *));
extern int storeInit _PARAMS(());
extern int storeReleaseEntry _PARAMS((StoreEntry *));
extern int storeClientWaiting _PARAMS((StoreEntry *));
extern int storeAbort _PARAMS((StoreEntry *, char *));
extern int storeAppend _PARAMS((StoreEntry *, char *, int));
extern int storeGetMemSize _PARAMS((void));
extern int storeGetMemSpace _PARAMS((int, int));
extern int storeGetSwapSize _PARAMS((void));
extern int storeGetSwapSpace _PARAMS((int));
extern int storeEntryValidToSend _PARAMS((StoreEntry *));
extern int storeEntryLocked _PARAMS((StoreEntry *));
extern int storeLockObject _PARAMS((StoreEntry *));
extern int storeOriginalKey _PARAMS((StoreEntry *));
extern int storeRelease _PARAMS((StoreEntry *));
extern int storeUnlockObject _PARAMS((StoreEntry *));
extern int storeUnregister _PARAMS((StoreEntry *, int));
extern int storeGrep _PARAMS((StoreEntry *, char *, int));
extern char *storeGenerateKey _PARAMS((char *, int));
extern char *storeMatchMime _PARAMS((StoreEntry *, char *, char *, int));
extern int storeAddSwapDisk _PARAMS((char *));
extern char *swappath _PARAMS((int));
extern void storeStartDeleteBehind _PARAMS((StoreEntry *));
extern int storeClientCopy _PARAMS((StoreEntry *, int, int, char *, int *, int));
extern int storePendingNClients _PARAMS((StoreEntry * e));
extern int storePendingFirstFD _PARAMS((StoreEntry * e));
extern char *storeSwapFullPath _PARAMS((int, char *));
extern int storeWriteCleanLog _PARAMS((void));
extern int storeRegister(StoreEntry *, int, PIF, caddr_t);
extern int urlcmp _PARAMS((char *, char *));
extern int storeSwapInStart _PARAMS((StoreEntry *));
extern int swapInError _PARAMS((int fd, StoreEntry *));
extern int storeCopy _PARAMS((StoreEntry *, int, int, char *, int *));

#endif
