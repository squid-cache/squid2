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

#ifndef _MEM_BUF_H_
#define _MEM_BUF_H_

/*
    Rationale:
    ----------

    Here is how one would comm_write an object without MemBuffer:

    {
	-- allocate:
	buf = malloc(big_enough);

        -- "pack":
	snprintf object(s) piece-by-piece constantly checking for overflows
	    and maintaining (buf+offset);
	...

	-- write
	comm_write(buf, free, ...);
    }

    The whole "packing" idea is quite messy: We are given a buffer of fixed
    size and we have to check all the time that we still fit. Sounds logical.
    However, what happens if we have more data? If we are lucky to be careful
    to stop before we overrun any buffers, we still may have garbage (e.g.
    half of ETag) in the buffer.

    MemBuffer:
    ----------

    MemBuffer is a memory-resident buffer with printf()-like interface. It
    hides all offest handling and overflow checking. Moreover, it has a
    build-in control that no partial data has been written.

    MemBuffer is designed to handle relatively small data. It starts with a
    small buffer of configurable size to avoid allocating huge buffers all the
    time.  MemBuffer doubles the buffer when needed. It assert()s that it will
    not grow larger than a configurable limit. MemBuffer has virtually no
    overhead (and can even reduce memory consumption) compared to old
    "packing" approach.

    MemBuffer eliminates both "packing" mess and truncated data:

    {
	-- setup
	MemBuf buf;

	-- required init with optional size tuning (see #defines for defaults)
        memBufInit(&buf, initial-size, absolute-maximum);

	-- "pack" (no need to handle offsets or check for overflows)
	memBufPrintf(&buf, ...);
	...

	-- write
	comm_write(buf.buf, memBufFreeFunc(&buf), ...);

	-- *iff* you did not give the buffer away, free it yourself
	-- memBufFree(&buf);
    }
*/

/* default values for buffer sizes, use memBufInit to overwrite */
#define MEM_BUF_INIT_SIZE   (2*1024)
#define MEM_BUF_MAX_SIZE   (16*1024)

typedef size_t mb_size_t; /* in case we want to change it later */

struct _MemBuf {
    /* public, read-only */
    char *buf;
    mb_size_t size;  /* used space */

    /* private, stay away; use interface function instead */
    mb_size_t max_capacity; /* when grows: assert(new_capacity <= max_capacity) */
    mb_size_t capacity;     /* allocated space */
    FREE *freefunc;  /* what to use to free the buffer, NULL after memBufFreeFunc() is called */
};

typedef struct _MemBuf MemBuf;

/* init with specific sizes */
extern void memBufInit(MemBuf *mb, mb_size_t szInit, mb_size_t szMax);

/* init with defaults */
#define memBufDefInit(mb) memBufInit((mb), MEM_BUF_INIT_SIZE, MEM_BUF_MAX_SIZE);

/* cleans the mb; last function to call if you do not give .buf away */
extern void memBufClean(MemBuf *mb);

/* calls memcpy, appends exactly size bytes, extends buffer if needed */
extern void memBufAppend(MemBuf *mb, const char *buf, mb_size_t size);

/* calls snprintf, extends buffer if needed */
#ifdef __STDC__
extern void memBufPrintf(MemBuf *mb, const char *fmt, ...);
#else
extern void memBufPrintf();
#endif

/* vprintf for other printf()'s to use */
extern void memBufVPrintf(MemBuf *mb, const char *fmt, va_list ap);

/*
 * returns free() function to be used.
 * Important:
 *   calling this function "freezes" mb, 
 *   do not _update_ mb after that in any way
 *   (you still can read-access to .buf and .size)
 */
extern FREE *memBufFreeFunc(MemBuf *mb);

/* puts report on MemBuf _module_ usage into mb */
extern void memBufReport(MemBuf *mb);

#endif /* ifndef _MEM_BUF_H_ */
