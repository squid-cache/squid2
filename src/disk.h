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

#ifndef DISK_H
#define DISK_H

#define DISK_OK                   (0)
#define DISK_ERROR               (-1)
#define DISK_EOF                 (-2)
#define DISK_WRT_LOCK_FAIL       (-3)
#define DISK_WRT_WRONG_CODE      (-4)
#define DISK_FILE_NOT_FOUND      (-5)
#define DISK_NO_SPACE_LEFT       (-6)

#define MAX_FILE_NAME_LEN 256

typedef int (*FILE_READ_HD) (int fd, char *buf, int size, int errflag,
    void *data, int offset);

typedef int (*FILE_WALK_HD) (int fd, int errflag, void *data);

typedef int (*FILE_WALK_LHD) (int fd, char *buf, int size, void *line_data);



typedef struct _dwrite_q {
    char *buf;
    int len;
    int cur_offset;
    struct _dwrite_q *next;
    void (*free) (void *);
} dwrite_q;

typedef struct _dread_ctrl {
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int cur_len;
    int end_of_file;
    int (*handler) (int fd, char *buf, int size, int errflag, void *data,
	int offset);
    void *client_data;
} dread_ctrl;

typedef struct _FileEntry {
    char filename[MAX_FILE_NAME_LEN];
    enum {
	NO, YES
    } at_eof;
    enum {
	FILE_NOT_OPEN, FILE_OPEN
    } open_stat;
    enum {
	NOT_REQUEST, REQUEST
    } close_request;
    enum {
	NOT_PRESENT, PRESENT
    } write_daemon;
    enum {
	UNLOCK, LOCK
    } write_lock;
    int access_code;		/* use to verify write lock */
    enum {
	NO_WRT_PENDING, WRT_PENDING
    } write_pending;
    void (*wrt_handle) ();
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
#if USE_ASYNC_IO		/* Data for asynchronous reads */
    struct aiocb aio_cb;	/* Control block */
    int (*aio_handler) (int fd, void *data);
    void *aio_data;		/* state, either FileEntry or ctrl_dat */
#endif
} FileEntry;

extern FileEntry *file_table;

extern int file_open _PARAMS((char *path, int (*handler) _PARAMS((void)), int mode));
extern int file_close _PARAMS((int fd));
extern int file_write _PARAMS((int fd,
	char *buf,
	int len,
	int access_code,
	void       (*handle) _PARAMS((int, int, StoreEntry *)),
	void *handle_data,
	void       (*free) _PARAMS((void *))));
extern int file_write_unlock _PARAMS((int fd, int access_code));
extern int file_read _PARAMS((int fd,
	char *buf,
	int req_len,
	int offset,
	int       (*handler) _PARAMS((int fd,
		char *buf,
		int size,
		int errflag,
		void *data,
		int offset)),
	void *client_data));
extern int file_walk _PARAMS((int fd,
	int       (*handler) _PARAMS((int fd, int errflag, void *data)),
	void *client_data,
	int       (*line_handler) _PARAMS((int fd, char *buf, int size, void *line_data)),
	void *line_data));
extern int file_write_lock _PARAMS((int fd));
extern int disk_init _PARAMS((void));
extern int diskWriteIsComplete _PARAMS((int));
extern void diskFreeMemory _PARAMS((void));

#endif /* DISK_H */
