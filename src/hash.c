/*
 * $Id$
 *
 * DEBUG: section 0     Hash Tables
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
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

#include "squid.h"

int hash_links_allocated;

static int default_hash_size = -1;
static int hash_unlink _PARAMS((hash_table *, hash_link *, int));

/*
 *  hash_url() - Returns a well-distributed hash function for URLs.
 *  The best way is to sum up the last half of the string.
 *  Adapted from code written by Mic Bowman.  -Darren
 *  Generates a standard deviation = 15.73
 */
unsigned int
hash_url(const char *s, unsigned int size)
{
    unsigned int i, j, n;
    j = strlen(s);
    for (i = j / 2, n = 0; i < j; i++)
	n ^= 271 * (unsigned) s[i];
    i = n ^ (j * 271);
    return i % size;
}

unsigned int
hash_string(const char *s, unsigned int size)
{
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
	j++;
	n ^= 271 * (unsigned) *s++;
    }
    i = n ^ (j * 271);
    return i % size;
}

/* the following 4 functions were adapted from
 *    usr/src/lib/libc/db/hash_func.c, 4.4 BSD lite */

/*
 * HASH FUNCTIONS
 *
 * Assume that we've already split the bucket to which this key hashes,
 * calculate that bucket, and check that in fact we did already split it.
 *
 * This came from ejb's hsearch.
 */

#define PRIME1		37
#define PRIME2		1048583

#ifdef UNUSED_CODE
unsigned int
hash1(char *keyarg, unsigned int size)
{
    const u_char *key;
    unsigned int h;
    size_t len;

    /* Convert string to integer */
    len = strlen(keyarg);
    for (key = keyarg, h = 0; len--;)
	h = h * PRIME1 ^ (*key++ - ' ');
    h %= PRIME2;
    return h % size;
}

/*
 * Phong's linear congruential hash
 */
#define dcharhash(h, c)	((h) = 0x63c63cd9*(h) + 0x9c39c33d + (c))

unsigned int
hash2(const void *keyarg, unsigned int size)
{
    const u_char *e, *key;
    unsigned int h;
    u_char c;
    size_t len;

    key = keyarg;
    len = strlen(key);
    e = key + len;
    for (h = 0; key != e;) {
	c = *key++;
	if (!c && key > e)
	    break;
	dcharhash(h, c);
    }
    return h % size;
}

/*
 * This is INCREDIBLY ugly, but fast.  We break the string up into 8 byte
 * units.  On the first time through the loop we get the "leftover bytes"
 * (strlen % 8).  On every other iteration, we perform 8 HASHC's so we handle
 * all 8 bytes.  Essentially, this saves us 7 cmp & branch instructions.  If
 * this routine is heavily used enough, it's worth the ugly coding.
 *
 * OZ's original sdbm hash
 */
unsigned int
hash3(const void *keyarg, unsigned int size)
{
    const u_char *key;
    size_t loop;
    unsigned int h;
    size_t len;

#define HASHC   h = *key++ + 65599 * h

    h = 0;
    key = keyarg;
    len = strlen(key);
    if (len > 0) {
	loop = (len + 8 - 1) >> 3;

	switch (len & (8 - 1)) {
	case 0:
	    do {
		HASHC;
		/* FALLTHROUGH */
	case 7:
		HASHC;
		/* FALLTHROUGH */
	case 6:
		HASHC;
		/* FALLTHROUGH */
	case 5:
		HASHC;
		/* FALLTHROUGH */
	case 4:
		HASHC;
		/* FALLTHROUGH */
	case 3:
		HASHC;
		/* FALLTHROUGH */
	case 2:
		HASHC;
		/* FALLTHROUGH */
	case 1:
		HASHC;
	    } while (--loop);
	}
    }
    return h % size;
}
#endif /* UNUSED_CODE */

/* Hash function from Chris Torek. */
unsigned int
hash4(const char *keyarg, unsigned int size)
{
    const char *key;
    size_t loop;
    unsigned int h;
    size_t len;

#define HASH4a   h = (h << 5) - h + *key++;
#define HASH4b   h = (h << 5) + h + *key++;
#define HASH4 HASH4b

    h = 0;
    key = keyarg;
    len = strlen(keyarg);
    if (len > 0) {
	loop = (len + 8 - 1) >> 3;

	switch (len & (8 - 1)) {
	case 0:
	    do {
		HASH4;
		/* FALLTHROUGH */
	case 7:
		HASH4;
		/* FALLTHROUGH */
	case 6:
		HASH4;
		/* FALLTHROUGH */
	case 5:
		HASH4;
		/* FALLTHROUGH */
	case 4:
		HASH4;
		/* FALLTHROUGH */
	case 3:
		HASH4;
		/* FALLTHROUGH */
	case 2:
		HASH4;
		/* FALLTHROUGH */
	case 1:
		HASH4;
	    } while (--loop);
	}
    }
    return h % size;
}

/*
 *  hash_init - initializes the hash library -- must call first.
 *  If hash_sz == 0, then it uses the default hash sizes, otherwise
 *  uses the given hash_sz.  Best performance if hash_sz is a prime number.
 */
void
hash_init(int hash_sz)
{
    default_hash_size = hash_sz > 0 ? hash_sz : HASH_SIZE;
}

/*
 *  hash_create - creates a new hash table, uses the cmp_func
 *  to compare keys.  Returns the identification for the hash table;
 *  otherwise returns a negative number on error.
 */
hash_table *
hash_create(HASHCMP *cmp_func, int hash_sz, HASHHASH *hash_func)
{
    hash_table * hid = xcalloc(1, sizeof(hash_table));
    if (!hash_sz)
	hid->size = (unsigned int) default_hash_size;
    else
	hid->size = (unsigned int) hash_sz;
    /* allocate and null the buckets */
    hid->buckets = xcalloc(hid->size, sizeof(hash_link *));
    hid->cmp = cmp_func;
    hid->hash = hash_func;
    hid->current_ptr = NULL;
    hid->current_slot = 0;
    hid->valid = 1;
    return hid;
}

/*
 *  hash_insert - inserts the given item 'item' under the given key 'k'
 *  into the hash table 'hid'.  Returns non-zero on error; otherwise,
 *  returns 0 and inserts the item.
 *
 *  It does not copy any data into the hash table, only pointers.
 */
int
hash_insert(hash_table * hid, const char *k, void *item)
{
    int i;
    hash_link *new;
    assert(hid->valid);
    assert(k != NULL);
    /* Add to the given hash table 'hid' */
    new = xcalloc(1, sizeof(hash_link));
    new->item = item;
    new->key = (char *) k;
    ++hash_links_allocated;
    i = hid->hash(k, hid->size);
    new->next = hid->buckets[i];
    hid->buckets[i] = new;
    return 0;
}

/*
 *  hash_join - joins a hash_link under its key lnk->key
 *  into the hash table 'hid'.  
 *
 *  It does not copy any data into the hash table, only links pointers.
 */
int
hash_join(hash_table * hid, hash_link * lnk)
{
    int i;
    if (!hid->valid)
	return -1;
    i = hid->hash(lnk->key, hid->size);
    lnk->next = hid->buckets[i];
    hid->buckets[i] = lnk;
    return 0;
}

/*
 *  hash_lookup - locates the item under the key 'k' in the hash table
 *  'hid'.  Returns a pointer to the hash bucket on success; otherwise
 *  returns NULL.
 */
hash_link *
hash_lookup(hash_table * hid, const char *k)
{
    hash_link *walker;
    int b;

    if (!hid->valid)
	return NULL;
    if (k == NULL)
	return NULL;
    b = hid->hash(k, hid->size);
    for (walker = hid->buckets[b]; walker != NULL; walker = walker->next) {
	if ((hid->cmp) (k, walker->key) == 0)
	    return (walker);
	/* XXX this should never happen */
	if (walker == walker->next)
	    break;
    }
    return NULL;
}

hash_link *
hash_lookup_and_move(hash_table * hid, const char *k)
{
    hash_link **walker, *match;
    int b;

    if (!hid->valid)
	return NULL;
    if (k == NULL)
	return NULL;
    b = hid->hash(k, hid->size);
    walker = &hid->buckets[b];
    while ((match = *walker)) {
	if ((hid->cmp) (k, match->key) == 0) {
	    /* found, move to front of list */
	    *walker = match->next;
	    match->next = hid->buckets[b];
	    hid->buckets[b] = match;
	    return (match);
	}
	/* XXX this should not happen */
	if (match == match->next)
	    break;
	walker = &match->next;
    }
    return NULL;
}

/*
 *  hash_first - returns the first item in the hash table 'hid'.
 *  Otherwise, returns NULL on error.
 */
hash_link *
hash_first(hash_table * hid)
{
    int i;
    if (!hid->valid)
	return NULL;

    for (i = 0; i < hid->size; i++) {
	hid->current_slot = i;
	if (hid->buckets[i] != NULL)
	    return (hid->current_ptr = hid->buckets[i]);
    }
    return NULL;
}

/*
 *  hash_next - returns the next item in the hash table 'hid'.
 *  Otherwise, returns NULL on error or end of list.  
 *
 *  MUST call hash_first() before hash_next().
 */
hash_link *
hash_next(hash_table * hid)
{
    int i;

    if (!hid->valid)
	return NULL;

    if (hid->current_ptr != NULL) {
	hid->current_ptr = hid->current_ptr->next;
	if (hid->current_ptr != NULL)
	    return (hid->current_ptr);	/* next item */
    }
    /* find next bucket */
    for (i = hid->current_slot + 1; i < hid->size; i++) {
	hid->current_slot = i;
	if (hid->buckets[i] != NULL)
	    return (hid->current_ptr = hid->buckets[i]);
    }
    return NULL;		/* end of list */
}

int
hash_delete(hash_table * hid, const char *key)
{
    return hash_delete_link(hid, hash_lookup(hid, key));
}

/*
 *  hash_delete_link - deletes the given hash_link node from the 
 *  hash table 'hid'. If FreeLink then free the given hash_link.
 *
 *  On success, it returns 0 and deletes the link; otherwise, 
 *  returns non-zero on error.
 */
static int
hash_unlink(hash_table * hid, hash_link * hl, int FreeLink)
{
    hash_link *walker, *prev;
    int i;
    assert(hid->valid);
    if (hl == NULL)
	return -1;
    i = hid->hash(hl->key, hid->size);
    for (prev = NULL, walker = hid->buckets[i];
	walker != NULL; prev = walker, walker = walker->next) {
	if (walker == hl) {
	    if (prev == NULL) {	/* it's the head */
		hid->buckets[i] = walker->next;
	    } else {
		prev->next = walker->next;	/* skip it */
	    }
	    /* fix walker state if needed */
	    if (walker == hid->current_ptr)
		hid->current_ptr = walker->next;
	    if (FreeLink) {
		safe_free(walker);
		--hash_links_allocated;
	    }
	    return 0;
	}
    }
    return 1;
}

/* take link off and free link node */
int
hash_delete_link(hash_table * hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 1));
}

/* take link off only */
int
hash_remove_link(hash_table * hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 0));
}

/*
 *  hash_get_bucket - returns the head item of the bucket 
 *  in the hash table 'hid'. Otherwise, returns NULL on error.
 */
hash_link *
hash_get_bucket(hash_table * hid, unsigned int bucket)
{
    if (!hid->valid)
	return NULL;
    if (bucket >= hid->size)
	return NULL;
    return (hid->buckets[bucket]);
}


void
hashFreeMemory(hash_table * hid)
{
    safe_free(hid->buckets);
    hid->valid = 0;
}


#ifdef USE_HASH_DRIVER
/*
 *  hash-driver - Run with a big file as stdin to insert each line into the
 *  hash table, then prints the whole hash table, then deletes a random item,
 *  and prints the table again...
 */
int
main(void)
{
    hash_table *hid;
    int i;
    LOCAL_ARRAY(char, buf, BUFSIZ);
    LOCAL_ARRAY(char, todelete, BUFSIZ);
    hash_link *walker = NULL;

    todelete[0] = '\0';
    printf("init\n");
    hash_init(NULL);

    printf("creating hash table\n");
    if ((hid = hash_create(strcmp)) < 0) {
	printf("hash_create error.\n");
	exit(1);
    }
    printf("done creating hash table: %d\n", hid);

    while (fgets(buf, BUFSIZ, stdin)) {
	buf[strlen(buf) - 1] = '\0';
	printf("Inserting '%s' for item %p to hash table: %d\n",
	    buf, buf, hid);
	if (hash_insert(hid, xstrdup(buf), (void *) 0x12345678)) {
	    printf("error inserting!\n");
	    exit(1);
	}
	if (random() % 17 == 0)
	    strcpy(todelete, buf);
    }

    printf("walking hash table...\n");
    for (i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
	printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
	    walker->item);
    }
    printf("done walking hash table...\n");

    if (todelete[0]) {
	printf("deleting %s from %d\n", todelete, hid);
	if (hash_delete(hid, todelete))
	    printf("hash_delete error\n");
    }
    printf("walking hash table...\n");
    for (i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
	printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
	    walker->item);
    }
    printf("done walking hash table...\n");


    printf("driver finished.\n");
    exit(0);
}
#endif
