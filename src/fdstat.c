/*
 * $Id$
 *
 * DEBUG: section 7     File Descriptor Status
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

static void fdstat_update _PARAMS((int fd, unsigned int));

const char *fdstatTypeStr[] =
{
    "None",
    "Log",
    "File",
    "Socket",
    "Pipe",
    "Unknown"
};

/* init fd stat module */
void
fdstat_init(void)
{
    Biggest_FD = -1;
}

/* call for updating the current biggest fd */
static void
fdstat_update(int fd, unsigned int status)
{
    if (fd < Biggest_FD)
	return;
    if (fd >= Squid_MaxFD) {
	debug_trap("Running out of file descriptors.\n");
	return;
    }
    if (fd > Biggest_FD) {
	if (status == FD_OPEN)
	    Biggest_FD = fd;
	else
	    debug_trap("fdstat_update: Biggest_FD inconsistency");
	return;
    }
    /* if we are here, then fd == Biggest_FD */
    if (status == FD_CLOSE) {
	while (fd_table[Biggest_FD].open != FD_OPEN)
	    Biggest_FD--;
    } else {
	debug_trap("fdstat_update: re-opening Biggest_FD?");
    }
}

/* call when open fd */
void
fdstat_open(int fd, unsigned int type)
{
    fd_table[fd].type = type;
    fdstat_update(fd, fd_table[fd].open = FD_OPEN);
}

int
fdstat_isopen(int fd)
{
    return (fd_table[fd].open == FD_OPEN);
}

/* call when close fd */
void
fdstat_close(int fd)
{
    fdstat_update(fd, fd_table[fd].open = FD_CLOSE);
}

int
fdstat_are_n_free_fd(int n)
{
    int fd;
    int n_free_fd = 0;

    if (n == 0) {
	for (fd = 0; fd < Squid_MaxFD; ++fd)
	    if (fd_table[fd].open == FD_CLOSE)
		++n;
	return (n);
    }
    if ((Squid_MaxFD - Biggest_FD) > n)
	return 1;
    else {
	for (fd = Squid_MaxFD - 1; ((fd > 0) && (n_free_fd < n)); --fd) {
	    if (fd_table[fd].open == FD_CLOSE) {
		++n_free_fd;
	    }
	}
	return (n_free_fd >= n);
    }
}
