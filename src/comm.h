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

#ifndef COMM_H
#define COMM_H

#define COMM_OK		  (0)
#define COMM_ERROR	 (-1)
#define COMM_NO_HANDLER	 (-2)
#define COMM_NOMESSAGE	 (-3)
#define COMM_TIMEOUT	 (-4)
#define COMM_SHUTDOWN	 (-5)

#define COMM_NONBLOCKING  (0x1)
#define COMM_DGRAM        (0x4)
#define COMM_NOCLOEXEC	  (0x8)

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)
#define COMM_SELECT_EXCEPT (0x4)
#define COMM_SELECT_TIMEOUT (0x8)
#define COMM_SELECT_LIFETIME (0x10)

typedef int (*PF) _PARAMS((int, void *));

typedef void rw_complete_handler _PARAMS((int fd, char *buf, int size, int errflag, void *data));
typedef struct _RWStateData RWStateData;

#define FD_ASCII_NOTE_SZ 64

struct close_handler {
    PF handler;
    void *data;
    struct close_handler *next;
};

typedef struct fde {
    int openned;		/* Set if we did a comm_connect.  Ignored for ftp_pipes. */
    int sender;			/* Set if this fd is connected to a client */
    u_short local_port;		/* Our TCP port # */
    u_short remote_port;	/* Remote TCP port # */
    char ipaddr[16];		/* dotted decimal address of peer */
    StoreEntry *store_entry;

    /* Select handlers. */
    PF read_handler;		/* Read  select handler. */
    void *read_data;		/* App. data to associate w/ handled conn. */
    PF write_handler;		/* Write select handler. */
    void *write_data;		/* App. data to associate w/ handled conn. */
    PF except_handler;		/* Except select handler. */
    void *except_data;		/* App. data to associate w/ handled conn. */
    PF timeout_handler;		/* Timeout handler. */
    time_t timeout_time;	/* Allow 1-second granularity timeouts */
    time_t timeout_delta;	/* The delta requested */
    void *timeout_data;		/* App. data to associate w/ handled conn. */
    PF lifetime_handler;	/* Lifetime expire handler. */
    void *lifetime_data;	/* App. data to associate w/ handled conn. */
    struct close_handler *close_handler;	/* Linked list of close handlers */
    char ascii_note[FD_ASCII_NOTE_SZ];
    unsigned int comm_type;
    time_t stall_until;		/* don't select for read until this time reached */
    RWStateData *rstate;	/* State data for comm_read */
    RWStateData *wstate;	/* State data for comm_write */
} FD_ENTRY;

extern FD_ENTRY *fd_table;

extern char **getAddressList _PARAMS((char *name));
extern char *fd_note _PARAMS((int fd, char *));
extern int commSetNonBlocking _PARAMS((int fd));
extern int comm_accept _PARAMS((int fd, struct sockaddr_in *, struct sockaddr_in *));
extern int comm_close _PARAMS((int fd));
extern int comm_connect _PARAMS((int sock, char *hst, int prt));
extern int comm_connect_addr _PARAMS((int sock, struct sockaddr_in *));
extern int comm_get_fd_lifetime _PARAMS((int fd));
extern int comm_get_select_handler _PARAMS((int fd, unsigned int type, PF *, void **));
extern int comm_init _PARAMS((void));
extern int comm_listen _PARAMS((int sock));
extern int comm_open _PARAMS((unsigned int io_type, struct in_addr, u_short port, char *note));
extern u_short comm_local_port _PARAMS((int fd));
extern int comm_select _PARAMS((time_t sec, time_t));
extern int comm_set_fd_lifetime _PARAMS((int fd, int lifetime));
extern void comm_set_select_handler _PARAMS((int fd, unsigned int type, PF, void *));
extern void comm_set_select_handler_plus_timeout _PARAMS((int, unsigned int, PF, void *, time_t));
extern void comm_add_close_handler _PARAMS((int fd, PF, void *));
extern void comm_remove_close_handler _PARAMS((int fd, PF, void *));
extern int comm_udp_recv _PARAMS((int, char *, int, struct sockaddr_in *, int *));
extern int comm_udp_send _PARAMS((int fd, char *host, u_short port, char *buf, int len));
extern int comm_udp_sendto _PARAMS((int fd, struct sockaddr_in *, int size, char *buf, int len));
extern int fd_of_first_client _PARAMS((StoreEntry *));
extern struct in_addr *getAddress _PARAMS((char *name));
extern void comm_set_stall _PARAMS((int, int));
extern int comm_get_fd_timeout _PARAMS((int fd));
extern void comm_read _PARAMS((int fd, char *buf, int size, int timeout, int immed, rw_complete_handler * handler, void *handler_data));
extern void comm_write _PARAMS((int fd, char *buf, int size, int timeout, rw_complete_handler * handler, void *handler_data));

extern int RESERVED_FD;

#endif /* COMM_H */
