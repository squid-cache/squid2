/* 
 *  $Id$
 *
 *  File:         comm.h
 *  Description:  Declarations for socket communication  facility.
 *  Commor:       John Noll, USC
 *  Created:      Fri Jun 18 11:55:35 1993
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#ifndef COMM_H
#define COMM_H

#if !defined(__ultrix) || !defined(HOST_NOT_FOUND)	/* not protected */
#include <netdb.h>
#endif
#include <sys/file.h>
#include <sys/types.h>
#ifdef OLD_CODE
#if !defined(_SQUID_LINUX_)
#include <sys/uio.h>
#endif
#endif /* OLD_CODE */

#include <sys/param.h>		/* For MAXHOSTNAMELEN */
#include <netdb.h>		/* For MAXHOSTNAMELEN on Solaris */
#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif

#include <netinet/in.h>
#include "store.h"


#define COMM_OK		  (0)
#define COMM_ERROR	 (-1)
#define COMM_NO_HANDLER	 (-2)
#define COMM_NOMESSAGE	 (-3)
#define COMM_TIMEOUT	 (-4)

#define COMM_BLOCKING	  (0x0)
#define COMM_NONBLOCKING  (0x1)
#define COMM_INTERRUPT    (0x2)
#define COMM_DGRAM        (0x4)

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)
#define COMM_SELECT_EXCEPT (0x4)
#define COMM_SELECT_TIMEOUT (0x8)
#define COMM_SELECT_LIFETIME (0x10)

/* 
 *  CACHED_RETRIEVE_ERROR_MSG args: 
 *      $1 is URL, 
 *      $2 is URL, 
 *      $3 is protocol type string
 *      $4 is error code, 
 *      $5 is error msg, 
 *      $6 is message to user
 *      $7 is cached version
 *      $8 is cached hostname
 */

#define CACHED_RETRIEVE_ERROR_MSG "\
<TITLE>ERROR: The requested URL could not be retrieved</TITLE>\n\
<H2>ERROR: The requested URL could not be retrieved</H2>\n\
<HR>\n\
<P>\n\
While trying to retrieve the URL:\n\
<A HREF=\"%s\">%s</A>\n\
<P>\n\
The following %s error was encountered:\n\
<UL>\n\
<LI><STRONG>ERROR %d -- %s</STRONG>\n\
</UL>\n\
<P>This means that:\n\
<PRE>\n\
    %s\n\
</PRE>\n\
<P> <HR>\n\
<ADDRESS>\n\
Generated by cached/%s@%s\n\
</ADDRESS>\n\
\n"


typedef int (*PF) _PARAMS((int, caddr_t));

#ifdef __cplusplus
extern "C" {
#endif

#define FD_ASCII_NOTE_SZ 64

/* Global variables */
    typedef struct fde {
	int openned;		/* Set if we did a comm_connect.  Ignored for ftp_pipes. */
	int sender;		/* Set if this fd is connected to a client */
	int port;		/* Our tcp port # */
	int (*handler) ();	/* Interrupt handler */
	StoreEntry *store_entry;

	/* Select handlers. */
	caddr_t client_data;	/* App. data to associate w/ handled conn. */
	int (*read_handler) ();	/* Read  select handler. */
	caddr_t read_data;	/* App. data to associate w/ handled conn. */
	int (*write_handler) ();	/* Write select handler. */
	caddr_t write_data;	/* App. data to associate w/ handled conn. */
	int (*except_handler) ();	/* Except select handler. */
	caddr_t except_data;	/* App. data to associate w/ handled conn. */
	int (*timeout_handler) ();	/* Timeout handler. */
	time_t timeout_time;	/* Allow 1-second granularity timeouts */
	time_t timeout_delta;	/* The delta requested */
	caddr_t timeout_data;	/* App. data to associate w/ handled conn. */
	int (*lifetime_handler) ();	/* Lifetime expire handler. */
	caddr_t lifetime_data;	/* App. data to associate w/ handled conn. */
	char ascii_note[FD_ASCII_NOTE_SZ];
	unsigned int comm_type;
	time_t stall_until;	/* don't select for read until this time reached */
    } FD_ENTRY;

    extern FD_ENTRY *fd_table;

    extern int comm_open _PARAMS((unsigned int io_type, int port, PF, char *note));
    extern int comm_accept _PARAMS((int fd, struct sockaddr_in *, struct sockaddr_in *));
    extern char *comm_client _PARAMS((int fd));
    extern int comm_close _PARAMS((int fd));
    extern int comm_connect _PARAMS((int sock, char *hst, int prt));
    extern int comm_connect_addr _PARAMS((int sock, struct sockaddr_in *));
    char *comm_hostname _PARAMS(());
    extern char *comm_hostname_direct _PARAMS(());
    extern int comm_init _PARAMS(());
    extern int comm_listen _PARAMS((int sock));
    extern char *comm_peerhost _PARAMS((int fd));
    extern int comm_peerport _PARAMS((int fd));
    extern int comm_port _PARAMS((int fd));
    extern int comm_read _PARAMS((int fd, char *buf, int size));
    extern int comm_select _PARAMS((long sec, long usec, time_t));
    extern int comm_pending _PARAMS((int fd, long sec, long usec));
    extern int comm_sethandler _PARAMS((int fd, PF, caddr_t));
    extern int comm_set_select_handler_plus_timeout _PARAMS((int fd, unsigned int type, PF, caddr_t, time_t));
    extern int comm_set_select_handler _PARAMS((int fd, unsigned int type, PF, caddr_t));
    extern int comm_get_select_handler _PARAMS((int fd, unsigned int type, PF *, caddr_t *));
    extern int comm_write _PARAMS((int fd, char *buf, int size));
    extern int comm_udp_send _PARAMS((int fd, char *host, int port, char *buf, int len));
    extern int comm_udp_sendto _PARAMS((int fd, struct sockaddr_in *, int size, char *buf, int len));
    extern int comm_udp_recv _PARAMS((int, char *, int, struct sockaddr_in *, int *));
    extern int comm_init();
    extern int comm_set_fd_lifetime _PARAMS((int fd, int lifetime));
    extern int comm_get_fd_lifetime _PARAMS((int fd));
    extern void comm_set_stall _PARAMS((int, int));
    extern char *fd_note _PARAMS((int fd, char *));
    extern int commSetNonBlocking _PARAMS((int fd));
    extern char **getAddressList _PARAMS((char *name));
    extern struct in_addr *getAddress _PARAMS((char *name));
    extern int fd_of_first_client _PARAMS((StoreEntry *));
#ifdef __cplusplus
}

#endif
#endif				/* COMM_H */
