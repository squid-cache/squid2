/*
 * $Id$
 *
 * AUTHOR: Alex Rousskov
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

#ifndef _PACKER_H_
#define _PACKER_H_

/*
    Rationale:
    ----------

    OK, we have to major interfaces comm.c and store.c.

    Store.c has a nice storeAppend[Printf] capability which makes "storing"
    things easy and painless. 

    Comm.c lacks commAppend[Printf] because comm does not handle its own
    buffers (no mem_obj equivalent for comm.c).

    Thus, if one wants to be able to store _and_ comm_write an object, s/he
    has to implement two almost identical functions.

    Packer
    ------

    Packer provides for a more uniform interface to store and comm modules.
    Packer has its own append and printf routines that "know" where to send
    incoming data. In case of store interface, Packer sends data to
    storeAppend.  Otherwise, Packer uses a MemBuf that can be flushed later to
    comm_write.

    Thus, one can write just one function that will either "pack" things for
    comm_write or "append" things to store, depending on actual packer
    supplied.

    It is amasing how much work a tiny object can save. :)

*/

typedef struct _Packer Packer;

typedef void (*append_f)(void *, const char *buf, int size);

#ifdef __STDC__
typedef void (*vprintf_f)(void *, const char *fmt, ...);
#else
typedef void (*vprintf_f)();
#endif


struct _Packer {
    /* protected, use interface functions instead */
    append_f append;
    vprintf_f vprintf;
    void *real_handler; /* first parameter to real append and vprintf */
};


/* init/clean */
/* init with this to forward data to StoreEntry */
extern void packerToStoreInit(Packer *p, StoreEntry *e);
/* init with this to accumulate data in MemBuf */
extern void packerToMemInit(Packer *p, MemBuf *mb);
/* call this when you are done */
extern void packerClean(Packer *p);

/* append/printf */
extern void packerAppend(Packer *p, const char *buf, int size);

#ifdef __STDC__
extern void packerPrintf(Packer *p, const char *fmt, ...);
#else
extern void packerPrintf();
#endif


#endif /* ifndef _PACKER_H_ */
