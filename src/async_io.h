
/*
 * $Id$
 *
 * AUTHOR: Pete Bentley <pete@demon.net>
 * AUTHOR: Stewart Forster <slf@connect.com.au>
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

typedef void AIOCB _PARAMS((void *, int aio_return, int aio_errno));

extern void aioCancel _PARAMS((int));
extern void aioOpen _PARAMS((const char *, int, mode_t, AIOCB *, void *));
extern void aioClose _PARAMS((int));
extern void aioWrite _PARAMS((int, char *, int, AIOCB *, void *));
extern void aioRead _PARAMS((int, char *, int, AIOCB *, void *));
extern void aioStat _PARAMS((char *, struct stat *, AIOCB *, void *));
extern void aioUnlink _PARAMS((const char *, AIOCB *, void *));
extern void aioCheckCallbacks _PARAMS((void));
