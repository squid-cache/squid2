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
extern HashID hash_create _PARAMS((int (*)_PARAMS((char *, char *)),
	int,
	int         (*)_PARAMS((char *, HashID))));

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
extern int hash_url _PARAMS((char *, HashID));
extern int hash_string _PARAMS((char *, HashID));
extern void hashFreeMemory _PARAMS((HashID));

extern int hash_links_allocated;

#endif
