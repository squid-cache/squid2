/*   $Id$ */

#ifndef _HASH_H_
#define _HASH_H_

/*  
 *  Here are some good prime number choices.  It's important not to
 *  choose a prime number that is too close to exact powers of 2.
 */
#if 0
#undef  HASH_SIZE 103		/* prime number < 128 */
#undef  HASH_SIZE 229		/* prime number < 256 */
#undef  HASH_SIZE 467		/* prime number < 512 */
#undef  HASH_SIZE 977		/* prime number < 1024 */
#undef  HASH_SIZE 1979		/* prime number < 2048 */
#undef  HASH_SIZE 4019		/* prime number < 4096 */
#undef  HASH_SIZE 6037		/* prime number < 6144 */
#undef  HASH_SIZE 7951		/* prime number < 8192 */
#undef  HASH_SIZE 12149		/* prime number < 12288 */
#undef  HASH_SIZE 16231		/* prime number < 16384 */
#undef  HASH_SIZE 33493		/* prime number < 32768 */
#undef  HASH_SIZE 65357		/* prime number < 65536 */
#endif

#define  HASH_SIZE 7951		/* prime number < 8192 */

#undef  uhash
#define uhash(x,hid)	((x) % htbl[(hid)].size)	/* for unsigned */
#undef  hash
#define hash(x,hid)	(((x) < 0 ? -(x) : (x)) % htbl[(hid)].size)

typedef struct HASH_LINK {
    char *key;
    struct HASH_LINK *next;
    void *item;
} hash_link;

typedef int HashID;

/* init */
extern void hash_init _PARAMS((int));
extern HashID hash_create _PARAMS((int (*)(char *, char *), int));

/* insert/delete */
extern int hash_insert _PARAMS((HashID, char *, void *));
extern int hash_delete _PARAMS((HashID, char *));
extern int hash_delete_link _PARAMS((HashID, hash_link *));
extern int hash_join _PARAMS((HashID, hash_link *));
extern int hash_remove_link _PARAMS((HashID, hash_link *));

/* searching, accessing */
extern hash_link *hash_lookup _PARAMS((HashID, char *));
extern hash_link *hash_first _PARAMS((HashID));
extern hash_link *hash_next _PARAMS((HashID));
extern hash_link *hash_get_bucket _PARAMS((HashID, unsigned int));

extern int hash_links_allocated;

#endif
