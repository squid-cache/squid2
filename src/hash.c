/*
 * $Id$
 *
 * DEBUG: section 0     Hash Tables
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

#include "squid.h"

#define MAX_HTABLE 10

int hash_links_allocated;

struct master_table {
    int valid;
    hash_link **buckets;
    int (*cmp) (char *, char *);
    int (*hash) (char *, HashID);
    int size;
    int current_slot;
    hash_link *current_ptr;
};

static int default_hash_size = -1;
struct master_table htbl[MAX_HTABLE];

extern void *xcalloc(int, size_t);

/*
 *  hash_url() - Returns a well-distributed hash function for URLs.
 *  The best way is to sum up the last half of the string.
 *  Adapted from code written by Mic Bowman.  -Darren
 *  Generates a standard deviation = 15.73
 */
int
hash_url(char *s, HashID hid)
{
    unsigned int i, j, n;
    j = strlen(s);
    for (i = j / 2, n = 0; i < j; i++)
	n ^= 271 * (unsigned) s[i];
    i = n ^ (j * 271);
    return (uhash(i, hid));
}

int
hash_string(char *s, HashID hid)
{
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
	j++;
	n ^= 271 * (unsigned) *s++;
    }
    i = n ^ (j * 271);
    return (uhash(i, hid));
}


/*
 *  hash_init - initializes the hash library -- must call first.
 *  If hash_sz == 0, then it uses the default hash sizes, otherwise
 *  uses the given hash_sz.  Best performance if hash_sz is a prime number.
 */
void
hash_init(int hash_sz)
{
    memset(htbl, '\0', sizeof(struct master_table) * MAX_HTABLE);
    default_hash_size = hash_sz > 0 ? hash_sz : HASH_SIZE;
}

/*
 *  hash_create - creates a new hash table, uses the cmp_func
 *  to compare keys.  Returns the identification for the hash table;
 *  otherwise returns a negative number on error.
 */
HashID
hash_create(int (*cmp_func) (char *, char *),
	int hash_sz,
	int (*hash_func) (char *, HashID))
{
    int hid;

    for (hid = 1; hid < MAX_HTABLE; hid++) {
	if (!htbl[hid].valid)
	    break;
    }
    if (hid >= MAX_HTABLE)
	return -1;		/* no room left! */

    if (!hash_sz)
	htbl[hid].size = default_hash_size;
    else
	htbl[hid].size = hash_sz;

    /* allocate and null the buckets */
    htbl[hid].buckets = xcalloc(htbl[hid].size, sizeof(hash_link *));
    htbl[hid].cmp = cmp_func;
    htbl[hid].hash = hash_func;
    htbl[hid].current_ptr = NULL;
    htbl[hid].current_slot = 0;
    htbl[hid].valid = 1;
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
hash_insert(HashID hid, char *k, void *item)
{
    int i;
    hash_link *new;

    if (!htbl[hid].valid)
	return -1;

    /* Add to the given hash table 'hid' */
    new = xcalloc(1, sizeof(hash_link));
    new->item = item;
    new->key = k;

    ++hash_links_allocated;

    i = (htbl[hid].hash) (k, hid);

    if (htbl[hid].buckets[i] == NULL) {		/* first item */
	htbl[hid].buckets[i] = new;
	htbl[hid].buckets[i]->next = NULL;
    } else {			/* prepend to list */
	new->next = htbl[hid].buckets[i];
	htbl[hid].buckets[i] = new;
    }
    return 0;
}

/*
 *  hash_join - joins a hash_link under its key lnk->key
 *  into the hash table 'hid'.  
 *
 *  It does not copy any data into the hash table, only links pointers.
 */
int
hash_join(HashID hid, hash_link * lnk)
{
    int i;

    if (!htbl[hid].valid)
	return -1;

    i = (htbl[hid].hash) (lnk->key, hid);

    if (htbl[hid].buckets[i] == NULL) {		/* first item */
	htbl[hid].buckets[i] = lnk;
	htbl[hid].buckets[i]->next = NULL;
    } else {			/* prepend to list */
	lnk->next = htbl[hid].buckets[i];
	htbl[hid].buckets[i] = lnk;
    }
    return 0;
}

/*
 *  hash_lookup - locates the item under the key 'k' in the hash table
 *  'hid'.  Returns a pointer to the hash bucket on success; otherwise
 *  returns NULL.
 */
hash_link *
hash_lookup(HashID hid, char *k)
{
    static hash_link *walker;
    int b;

    if (!htbl[hid].valid)
	return NULL;
    if (k == NULL)
	return NULL;
    b = (htbl[hid].hash) (k, hid);
    for (walker = htbl[hid].buckets[b]; walker != NULL; walker = walker->next) {
	if ((htbl[hid].cmp) (k, walker->key) == 0)
	    return (walker);
	if (walker == walker->next)
	    break;
    }
    return NULL;
}

/*
 *  hash_first - returns the first item in the hash table 'hid'.
 *  Otherwise, returns NULL on error.
 */
hash_link *
hash_first(HashID hid)
{
    int i;
    if (!htbl[hid].valid)
	return NULL;

    for (i = 0; i < htbl[hid].size; i++) {
	htbl[hid].current_slot = i;
	if (htbl[hid].buckets[i] != NULL) {
	    htbl[hid].current_ptr = htbl[hid].buckets[i];
	    return (htbl[hid].current_ptr);
	}
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
hash_next(HashID hid)
{
    int i;

    if (!htbl[hid].valid)
	return NULL;

    if (htbl[hid].current_ptr != NULL) {
	htbl[hid].current_ptr = htbl[hid].current_ptr->next;
	if (htbl[hid].current_ptr != NULL)
	    return (htbl[hid].current_ptr);	/* next item */
    }
    /* find next bucket */
    for (i = htbl[hid].current_slot + 1; i < htbl[hid].size; i++) {
	htbl[hid].current_slot = i;
	if (htbl[hid].buckets[i] != NULL) {
	    htbl[hid].current_ptr = htbl[hid].buckets[i];
	    return (htbl[hid].current_ptr);
	}
    }
    return NULL;		/* end of list */
}

int
hash_delete(HashID hid, char *key)
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
int
hash_unlink(HashID hid, hash_link * hl, int FreeLink)
{
    hash_link *walker, *prev;
    int i;

    if (!htbl[hid].valid || hl == NULL)
	return 1;

    i = (htbl[hid].hash) (hl->key, hid);
    for (prev = NULL, walker = htbl[hid].buckets[i];
	walker != NULL; prev = walker, walker = walker->next) {
	if (walker == hl) {
	    if (prev == NULL) {	/* it's the head */
		htbl[hid].buckets[i] = walker->next;
	    } else {
		prev->next = walker->next;	/* skip it */
	    }

	    /* fix walker state if needed */
	    if (walker == htbl[hid].current_ptr)
		htbl[hid].current_ptr = walker->next;

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
hash_delete_link(HashID hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 1));
}

/* take link off only */
int
hash_remove_link(HashID hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 0));
}

/*
 *  hash_get_bucket - returns the head item of the bucket 
 *  in the hash table 'hid'. Otherwise, returns NULL on error.
 */
hash_link *
hash_get_bucket(HashID hid, unsigned int bucket)
{
    if (!htbl[hid].valid)
	return NULL;
    if (bucket >= htbl[hid].size)
	return NULL;
    return (htbl[hid].buckets[bucket]);
}


#ifdef USE_HASH_DRIVER
/*
 *  hash-driver - Run with a big file as stdin to insert each line into the
 *  hash table, then prints the whole hash table, then deletes a random item,
 *  and prints the table again...
 */
int
main()
{
    int hid;
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
