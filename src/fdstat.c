/*
 * $Id$
 *
 * DEBUG: section 7     File Descriptor Status
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

static int Biggest_FD = 0;

typedef enum {
    FDSTAT_CLOSE,
    FDSTAT_OPEN
} File_Desc_Status;

typedef struct _FDENTRY {
    File_Desc_Status status;
    File_Desc_Type type;
} FDENTRY;

static FDENTRY *fd_stat_tab = NULL;

static void fdstat_update __P((int fd, File_Desc_Status status));

File_Desc_Type
fdstatGetType(int fd)
{
    return fd_stat_tab[fd].type;
}

char *fdstatTypeStr[] =
{
    "None",
    "Log",
    "File",
    "Socket",
    "Pipe",
    "Unknown"
};

/* init fd stat module */
int
fdstat_init(int preopen)
{
    int i;

    fd_stat_tab = xcalloc(FD_SETSIZE, sizeof(FDENTRY));
    meta_data.misc += FD_SETSIZE * sizeof(FDENTRY);
    for (i = 0; i < preopen; ++i) {
	fd_stat_tab[i].status = FDSTAT_OPEN;
	fd_stat_tab[i].type = FD_FILE;
    }

    for (i = preopen; i < FD_SETSIZE; ++i) {
	fd_stat_tab[i].status = FDSTAT_CLOSE;
	fd_stat_tab[i].type = FD_UNKNOWN;
    }

    Biggest_FD = preopen - 1;
    return 0;
}

/* call for updating the current biggest fd */
static void
fdstat_update(int fd, File_Desc_Status status)
{
    unsigned int i;

    if (fd >= FD_SETSIZE)
	debug(7, 0, "Running out of file descriptors.\n");

    if (fd < Biggest_FD) {
	/* nothing to do here */
	return;
    }
    if ((fd > Biggest_FD) && (status == FDSTAT_OPEN)) {
	/* just update the biggest one */
	Biggest_FD = fd;	/* % FD_SETSIZE; */
	return;
    }
    if ((fd == Biggest_FD) && (status == FDSTAT_CLOSE)) {
	/* just scan to Biggest_FD - 1 */
	for (i = Biggest_FD; i > 0; --i) {
	    if (fd_stat_tab[i].status == FDSTAT_OPEN)
		break;
	}
	Biggest_FD = i;
	return;
    }
    if ((fd == Biggest_FD) && (status == FDSTAT_OPEN)) {
	/* do nothing here */
	/* it could happen since some of fd are out of our control */
	return;
    }
    debug(7, 0, "WARNING: fdstat_update: Internal inconsistency:\n");
    debug(7, 0, "         Biggest_FD = %d, this fd = %d, status = %s\n",
	Biggest_FD, fd, status == FDSTAT_OPEN ? "OPEN" : "CLOSE");
    debug(7, 0, "         fd_stat_tab[%d].status == %s\n",
	fd, fd_stat_tab[fd].status == FDSTAT_OPEN ? "OPEN" : "CLOSE");
    debug(7, 0, "         fd_stat_tab[%d].type == %s\n", fd,
	fdstatTypeStr[fd_stat_tab[fd].type]);

    return;
}


/* call when open fd */
void
fdstat_open(int fd, File_Desc_Type type)
{
    fd_stat_tab[fd].status = FDSTAT_OPEN;
    fd_stat_tab[fd].type = type;
    fdstat_update(fd, FDSTAT_OPEN);
}

int
fdstat_isopen(int fd)
{
    return (fd_stat_tab[fd].status == FDSTAT_OPEN);
}

/* call when close fd */
void
fdstat_close(int fd)
{
    fd_stat_tab[fd].status = FDSTAT_CLOSE;
    fdstat_update(fd, FDSTAT_CLOSE);
}

/* return the biggest fd */
int
fdstat_biggest_fd(void)
{
    return Biggest_FD;
}


int
fdstat_are_n_free_fd(int n)
{
    int fd;
    int n_free_fd = 0;

    if (n == 0) {
	for (fd = 0; fd < FD_SETSIZE; ++fd)
	    if (fd_stat_tab[fd].status == FDSTAT_CLOSE)
		++n;
	return (n);
    }
    if ((FD_SETSIZE - Biggest_FD) > n)
	return 1;
    else {
	for (fd = FD_SETSIZE - 1; ((fd > 0) && (n_free_fd < n)); --fd) {
	    if (fd_stat_tab[fd].status == FDSTAT_CLOSE) {
		++n_free_fd;
	    }
	}
	return (n_free_fd >= n);
    }
}
