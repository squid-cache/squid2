/*
 * $Id$
 *
 * DEBUG: section 7	File Descriptor Status
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *   Squid is the result of efforts by numerous individuals from the
 *   Internet community.  Development is led by Duane Wessels of the
 *   National Laboratory for Applied Network Research and funded by
 *   the National Science Foundation.
 * 
 */
 
#ifdef HARVEST_COPYRIGHT
Copyright (c) 1994, 1995.  All rights reserved.
 
  The Harvest software was developed by the Internet Research Task
  Force Research Group on Resource Discovery (IRTF-RD):
 
        Mic Bowman of Transarc Corporation.
        Peter Danzig of the University of Southern California.
        Darren R. Hardy of the University of Colorado at Boulder.
        Udi Manber of the University of Arizona.
        Michael F. Schwartz of the University of Colorado at Boulder.
        Duane Wessels of the University of Colorado at Boulder.
 
  This copyright notice applies to software in the Harvest
  ``src/'' directory only.  Users should consult the individual
  copyright notices in the ``components/'' subdirectories for
  copyright information about other software bundled with the
  Harvest source code distribution.
 
TERMS OF USE
  
  The Harvest software may be used and re-distributed without
  charge, provided that the software origin and research team are
  cited in any use of the system.  Most commonly this is
  accomplished by including a link to the Harvest Home Page
  (http://harvest.cs.colorado.edu/) from the query page of any
  Broker you deploy, as well as in the query result pages.  These
  links are generated automatically by the standard Broker
  software distribution.
  
  The Harvest software is provided ``as is'', without express or
  implied warranty, and with no support nor obligation to assist
  in its use, correction, modification or enhancement.  We assume
  no liability with respect to the infringement of copyrights,
  trade secrets, or any patents, and are not responsible for
  consequential damages.  Proper use of the Harvest software is
  entirely the responsibility of the user.
 
DERIVATIVE WORKS
 
  Users may make derivative works from the Harvest software, subject 
  to the following constraints:
 
    - You must include the above copyright notice and these 
      accompanying paragraphs in all forms of derivative works, 
      and any documentation and other materials related to such 
      distribution and use acknowledge that the software was 
      developed at the above institutions.
 
    - You must notify IRTF-RD regarding your distribution of 
      the derivative work.
 
    - You must clearly notify users that your are distributing 
      a modified version and not the original Harvest software.
 
    - Any derivative product is also subject to these copyright 
      and use restrictions.
 
  Note that the Harvest software is NOT in the public domain.  We
  retain copyright, as specified above.
 
HISTORY OF FREE SOFTWARE STATUS
 
  Originally we required sites to license the software in cases
  where they were going to build commercial products/services
  around Harvest.  In June 1995 we changed this policy.  We now
  allow people to use the core Harvest software (the code found in
  the Harvest ``src/'' directory) for free.  We made this change
  in the interest of encouraging the widest possible deployment of
  the technology.  The Harvest software is really a reference
  implementation of a set of protocols and formats, some of which
  we intend to standardize.  We encourage commercial
  re-implementations of code complying to this set of standards.  
#endif


#include "squid.h"

static int Biggest_FD = 0;

typedef enum {
    CLOSE, OPEN
} File_Desc_Status;

typedef struct _FDENTRY {
    File_Desc_Status status;
    File_Desc_Type type;
} FDENTRY;

static FDENTRY *fd_stat_tab = NULL;

static void fdstat_update _PARAMS((int fd, File_Desc_Status status));

File_Desc_Type fdstatGetType(fd)
     int fd;
{
    return fd_stat_tab[fd].type;
}

char *fdfiletype(type)
     File_Desc_Type type;
{
    switch (type) {
    case FD_LOG:
	return ("Log");
	/* NOTREACHED */
    case FD_FILE:
	return ("File");
	/* NOTREACHED */
    case FD_SOCKET:
	return ("Socket");
	/* NOTREACHED */
    case FD_PIPE:
	return ("Pipe");
	/* NOTREACHED */
    case FD_UNKNOWN:
    default:
	break;
    }
    return ("Unknown");
}

/* init fd stat module */
int fdstat_init(preopen)
     int preopen;
{
    int i;

    fd_stat_tab = xcalloc(FD_SETSIZE, sizeof(FDENTRY));
    meta_data.misc += FD_SETSIZE * sizeof(FDENTRY);
    for (i = 0; i < preopen; ++i) {
	fd_stat_tab[i].status = OPEN;
	fd_stat_tab[i].type = FD_FILE;
    }

    for (i = preopen; i < FD_SETSIZE; ++i) {
	fd_stat_tab[i].status = CLOSE;
	fd_stat_tab[i].type = FD_UNKNOWN;
    }

    Biggest_FD = preopen - 1;
    return 0;
}

/* call for updating the current biggest fd */
static void fdstat_update(fd, status)
     int fd;
     File_Desc_Status status;
{
    unsigned int i;

    if (fd >= FD_SETSIZE)
	debug(7, 0, "Running out of file descriptors.\n");

    if (fd < Biggest_FD) {
	/* nothing to do here */
	return;
    }
    if ((fd > Biggest_FD) && (status == OPEN)) {
	/* just update the biggest one */
	Biggest_FD = fd;	/* % FD_SETSIZE; */
	return;
    }
    if ((fd == Biggest_FD) && (status == CLOSE)) {
	/* just scan to Biggest_FD - 1 */
	for (i = Biggest_FD; i > 0; --i) {
	    if (fd_stat_tab[i].status == OPEN)
		break;
	}
	Biggest_FD = i;
	return;
    }
    if ((fd == Biggest_FD) && (status == OPEN)) {
	/* do nothing here */
	/* it could happen since some of fd are out of our control */
	return;
    }
    debug(7, 0, "WARNING: fdstat_update: Internal inconsistency:\n");
    debug(7, 0, "         Biggest_FD = %d, this fd = %d, status = %s\n",
	Biggest_FD, fd, status == OPEN ? "OPEN" : "CLOSE");
    debug(7, 0, "         fd_stat_tab[%d].status == %s\n",
	fd, fd_stat_tab[fd].status == OPEN ? "OPEN" : "CLOSE");
    debug(7, 0, "         fd_stat_tab[%d].type == %s\n", fd,
	fdfiletype(fd_stat_tab[fd].type));

    return;
}


/* call when open fd */
void fdstat_open(fd, type)
     int fd;
     File_Desc_Type type;
{
    fd_stat_tab[fd].status = OPEN;
    fd_stat_tab[fd].type = type;
    fdstat_update(fd, OPEN);
}

int fdstat_isopen(fd)
     int fd;
{
    return (fd_stat_tab[fd].status == OPEN);
}

File_Desc_Type fdstat_type(fd)
     int fd;
{
    return fd_stat_tab[fd].type;
}

/* call when close fd */
void fdstat_close(fd)
     int fd;
{
    fd_stat_tab[fd].status = CLOSE;
    fdstat_update(fd, CLOSE);
}

/* return the biggest fd */
int fdstat_biggest_fd()
{
    return Biggest_FD;
}


int fdstat_are_n_free_fd(n)
     int n;
{
    int fd;
    int n_free_fd = 0;

#if  FD_TEST
    int lowest_avail_fd;

    lowest_avail_fd = dup(0);
    if (lowest_avail_fd >= 0)
	close(lowest_avail_fd);
    else {
	int ln_cnt = 0;
	for (fd = 0; fd < FD_SETSIZE; ++fd) {
	    if (fd_stat_tab[fd].status == CLOSE) {
		if (ln_cnt == 0) {
		    debug(0, 0, "fdstat_are_n_free_fd: Fd-Free: %3d\n", fd);
		    ++ln_cnt;
		} else if (ln_cnt == 20) {
		    debug(0, 0, "fdstat_are_n_free_fd: %3d\n", fd);
		    ln_cnt = 0;
		} else {
		    debug(0, 0, "fdstat_are_n_free_fd: %3d\n", fd);
		    ln_cnt++;
		}
	    }
	}
    }
#endif

    if (n == 0) {
	for (fd = 0; fd < FD_SETSIZE; ++fd)
	    if (fd_stat_tab[fd].status == CLOSE)
		++n;
	return (n);
    }
    if ((FD_SETSIZE - Biggest_FD) > n)
	return 1;
    else {
	for (fd = FD_SETSIZE - 1; ((fd > 0) && (n_free_fd < n)); --fd) {
	    if (fd_stat_tab[fd].status == CLOSE) {
		++n_free_fd;
	    }
	}
	return (n_free_fd >= n);
    }
}
