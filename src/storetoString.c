/*
 * $Id$
 *
 * DEBUG: section 0     Store Entry Debugging
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

/* convert store entry content to string. Use for debugging */
/* return pointer to static buffer containing string */
const char *
storeToString(const StoreEntry * e)
{
    MemObject *mem;
    LOCAL_ARRAY(char, stsbuf, 16 << 10);	/* have to make this really big */
    LOCAL_ARRAY(char, tmpbuf, 8 << 10);

    if (!e) {
	sprintf(stsbuf, "\nStoreEntry pointer is NULL.\n");
	return stsbuf;
    }
    sprintf(stsbuf, "\nStoreEntry @: %p\n****************\n", e);
    strcat(stsbuf, tmpbuf);

    sprintf(stsbuf, "Current Time: %d [%s]\n", (int) squid_curtime,
	mkhttpdlogtime(&squid_curtime));
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Key: %s\n", e->key);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "URL: %s\n", e->url);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Next: %p\n", e->next);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Flags: %#x ==> ", e->flag);
    if (BIT_TEST(e->flag, KEY_CHANGE))
	strncat(tmpbuf, " KEYCHANGE", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, ENTRY_CACHABLE))
	strncat(tmpbuf, " CACHABLE", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, REFRESH_REQUEST))
	strncat(tmpbuf, " REFRESH_REQ", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	strncat(tmpbuf, " RELEASE_REQ", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, CLIENT_ABORT_REQUEST))
	strncat(tmpbuf, " CLIENT_ABORT", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, ABORT_MSG_PENDING))
	strncat(tmpbuf, " ABORT_MSG_PENDING", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, DELAY_SENDING))
	strncat(tmpbuf, " DELAY_SENDING", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, DELETE_BEHIND))
	strncat(tmpbuf, " DELETE_BEHIND", sizeof(tmpbuf) - 1);
    if (e->lock_count)
	strncat(tmpbuf, "L", sizeof(tmpbuf) - 1);
    strcat(tmpbuf, "\n");
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Timestamp: %9d [%s]\n",
	(int) e->timestamp,
	mkhttpdlogtime(&e->timestamp));
    strcat(stsbuf, tmpbuf);
    sprintf(tmpbuf, "Lastref  : %9d [%s]\n",
	(int) e->lastref,
	mkhttpdlogtime(&e->lastref));
    strcat(stsbuf, tmpbuf);
    sprintf(tmpbuf, "Expires  : %9d [%s]\n",
	(int) e->expires,
	mkhttpdlogtime(&e->expires));
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "ObjectLen: %d\n", (int) e->object_len);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapFileNumber: %d\n", e->swap_file_number);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "StoreStatus: %s\n", storeStatusStr[e->store_status]);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "MemStatus: %s\n", memStatusStr[e->mem_status]);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "PingStatus: %s\n", pingStatusStr[e->ping_status]);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapStatus: %s\n", swapStatusStr[e->swap_status]);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Method: %s\n", RequestMethodStr[e->method]);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "RefCount: %u\n", e->refcount);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "LockCount: %d\n", e->lock_count);
    strcat(stsbuf, tmpbuf);

    mem = e->mem_obj;
    if (mem == NULL) {
	sprintf(tmpbuf, "MemObject: NULL.\n");
	strcat(stsbuf, tmpbuf);
	return stsbuf;
    }
    sprintf(tmpbuf, "MemObject: %p\n****************\n", mem);
    strcat(stsbuf, tmpbuf);

    if (!mem->mime_hdr) {
	sprintf(tmpbuf, "MimeHdr: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	sprintf(tmpbuf, "MimeHdr:\n-----------\n%s\n-----------\n", mem->mime_hdr);
	strcat(stsbuf, tmpbuf);
    }

    if (!mem->data) {
	sprintf(tmpbuf, "Data: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	sprintf(tmpbuf, "Data: %p\n", mem->data);
	strcat(stsbuf, tmpbuf);
    }


    if (!mem->e_swap_buf)
	sprintf(tmpbuf, "E_swap_buf: NOT SET\n");
    else
	sprintf(tmpbuf, "E_swap_buf: %s\n", mem->e_swap_buf);
    strcat(stsbuf, tmpbuf);
    sprintf(tmpbuf, "First_miss: %p\n", mem->e_pings_first_miss);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "E_swap_buf_len: %d\n", mem->e_swap_buf_len);
    strcat(stsbuf, tmpbuf);
    sprintf(tmpbuf, "[pings]: npings = %d  nacks = %d\n",
	mem->e_pings_n_pings, mem->e_pings_n_acks);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapAccess: %d\n", mem->e_swap_access);
    strcat(stsbuf, tmpbuf);

    if (!mem->e_abort_msg) {
	sprintf(tmpbuf, "AbortMsg: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	sprintf(tmpbuf, "AbortMsg:\n-----------\n%s\n-----------\n", mem->e_abort_msg);
	strcat(stsbuf, tmpbuf);
    }

    sprintf(tmpbuf, "CurrentLen: %d\n", mem->e_current_len);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "LowestOffset: %d\n", mem->e_lowest_offset);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "ClientListSize: %d\n", mem->nclients);
    strcat(stsbuf, tmpbuf);

    if (!mem->clients) {
	sprintf(tmpbuf, "ClientList: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	int i;
	sprintf(tmpbuf, "ClientList: %p\n", mem->clients);
	strcat(stsbuf, tmpbuf);

	for (i = 0; i < mem->nclients; ++i) {
	    struct _store_client *sc = &mem->clients[i];
	    sprintf(tmpbuf, "    Client[%d]: fd = %d\n", i, sc->fd);
	    strcat(stsbuf, tmpbuf);
	    sprintf(tmpbuf, "              : last_offset = %d\n", sc->last_offset);
	    strcat(stsbuf, tmpbuf);
	    sprintf(tmpbuf, "              : callback = %p\n", sc->callback);
	    strcat(stsbuf, tmpbuf);
	    sprintf(tmpbuf, "              : callback_data = %p\n", sc->callback_data);
	    strcat(stsbuf, tmpbuf);
	}
    }

    sprintf(tmpbuf, "SwapOffset: %u\n", mem->swap_offset);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapOutFd: %d\n", mem->swapout_fd);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapInFd: %d\n", mem->swapin_fd);
    strcat(stsbuf, tmpbuf);

    strcat(stsbuf, "\n");

    return stsbuf;
}
