
/*
 * $Id$
 *
 * AUTHOR: Pete Bentley <pete@demon.net>
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

extern void aioExamine _PARAMS((void));
extern void aioSigHandler _PARAMS((int sig));
extern int aioFileWriteComplete _PARAMS((int ed, void *));
extern int aioFileReadComplete _PARAMS((int fd, void *));
extern int aioFileQueueWrite _PARAMS((int, int (*)(int, void *), FileEntry *));
extern int aioFileQueueRead _PARAMS((int, int (*)(int, void *), dread_ctrl *));
