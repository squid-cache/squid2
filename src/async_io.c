
/*
 * $Id$
 *
 * DEBUG: section 32    Asynchronous Disk I/O
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

#include "squid.h"

#if USE_ASYNC_IO

#define _AIO_OPEN	0
#define _AIO_READ	1
#define _AIO_WRITE	2
#define _AIO_CLOSE	3
#define _AIO_UNLINK	4
#define _AIO_OPENDIR	5
#define _AIO_STAT	6

typedef struct aio_ctrl_t {
    struct aio_ctrl_t *next;
    int fd;
    int operation;
    AIOCB *done_handler;
    void *done_handler_data;
    aio_result_t result;
    void *tag;
} aio_ctrl_t;


typedef struct aio_unlinkq_t {
    char *path;
    struct aio_unlinkq_t *next;
} aio_unlinkq_t;

static aio_ctrl_t *free_list = NULL;
static aio_ctrl_t *used_list = NULL;
static aio_ctrl_t pool[SQUID_MAXFD];
static int initialised = 0;
static int outunlink = 0;

static void
aioInit()
{
    int i;
    aio_ctrl_t *node;

    if (initialised)
	return;
    for (i = 0; i < SQUID_MAXFD; i++) {
	node = pool + i;
	node->next = free_list;
	free_list = node;
    }
    initialised = 1;
}


void
aioOpen(const char *path, int oflag, mode_t mode, AIOCB * callback, void *callback_data, void *tag)
{
    aio_ctrl_t *ctrlp;
    int ret;

    if (!initialised)
	aioInit();
    if (free_list == NULL) {
	ret = open(path, oflag, mode);
	if (callback)
	    (callback) (callback_data, ret, errno);
	return;
    }
    ctrlp = free_list;
    ctrlp->fd = -2;
    ctrlp->tag = tag;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_OPEN;
    if (aio_open(path, oflag, mode, &(ctrlp->result)) < 0) {
	ret = open(path, oflag, mode);
	if (callback)
	    (callback) (callback_data, ret, errno);
	return;
    }
    free_list = free_list->next;
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}


void
aioClose(int fd)
{
    aio_ctrl_t *ctrlp;

    if (!initialised)
	aioInit();
    aioCancel(fd, NULL);
    if (free_list == NULL) {
	close(fd);
	return;
    }
    ctrlp = free_list;
    ctrlp->fd = fd;
    ctrlp->tag = NULL;
    ctrlp->done_handler = NULL;
    ctrlp->done_handler_data = NULL;
    ctrlp->operation = _AIO_CLOSE;
    if (aio_close(fd, &(ctrlp->result)) < 0) {
	close(fd);		/* Can't create thread - do a normal close */
	return;
    }
    free_list = free_list->next;
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}


void
aioCancel(int fd, void *tag)
{
    aio_ctrl_t *curr;
    aio_ctrl_t *prev;

    if (!initialised)
	aioInit();
    prev = NULL;
    curr = used_list;
    for (;;) {
	while (curr != NULL) {
	    if (curr->fd == fd)
		break;
	    if (tag != NULL && curr->tag == tag)
		break;
	    prev = curr;
	    curr = curr->next;
	}
	if (curr == NULL)
	    break;

	aio_cancel(&(curr->result));

	if (curr->done_handler)
	    (curr->done_handler) (curr->done_handler_data, -2, -2);
	if (curr->operation == _AIO_UNLINK)
	    outunlink--;

	if (prev == NULL)
	    used_list = curr->next;
	else
	    prev->next = curr->next;

	curr->next = free_list;
	free_list = curr;

	if (prev == NULL)
	    curr = used_list;
	else
	    curr = prev->next;
    }
}


void
aioWrite(int fd, char *bufp, int len, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;

    if (!initialised)
	aioInit();
    if (free_list == NULL) {
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    for (ctrlp = used_list; ctrlp != NULL; ctrlp = ctrlp->next)
	if (ctrlp->fd == fd && ctrlp->operation == _AIO_WRITE)
	    break;
    if (ctrlp != NULL) {
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    ctrlp = free_list;
    ctrlp->fd = fd;
    ctrlp->tag = NULL;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_WRITE;
    if (aio_write(fd, bufp, len, 0, SEEK_END, &(ctrlp->result)) < 0) {
	if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
	    errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    free_list = free_list->next;
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}				/* aioWrite */


void
aioRead(int fd, char *bufp, int len, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;

    if (!initialised)
	aioInit();
    if (free_list == NULL) {
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    for (ctrlp = used_list; ctrlp != NULL; ctrlp = ctrlp->next)
	if (ctrlp->fd == fd && ctrlp->operation == _AIO_READ)
	    break;
    if (ctrlp != NULL) {
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    ctrlp = free_list;
    ctrlp->fd = fd;
    ctrlp->tag = NULL;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_READ;
    if (aio_read(fd, bufp, len, 0, SEEK_CUR, &(ctrlp->result)) < 0) {
	if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
	    errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    free_list = free_list->next;
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}				/* aioRead */

void
aioStat(char *path, struct stat *sb, AIOCB * callback, void *callback_data, void *tag)
{
    aio_ctrl_t *ctrlp;

    if (!initialised)
	aioInit();
    if (free_list == NULL) {
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    ctrlp = free_list;
    ctrlp->fd = -2;
    ctrlp->tag = tag;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_STAT;
    if (aio_stat(path, sb, &(ctrlp->result)) < 0) {
	if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
	    errno = EWOULDBLOCK;
	if (callback)
	    (callback) (callback_data, -1, errno);
	return;
    }
    free_list = free_list->next;
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}				/* aioStat */

void
aioUnlink(const char *path, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    static aio_unlinkq_t *uq = NULL;
    aio_unlinkq_t *this;

    if (!initialised)
	aioInit();
    if (path) {
	this = xmalloc(sizeof(aio_unlinkq_t));
	this->path = xstrdup(path);
	this->next = uq;
	uq = this;
    }
    while (uq != NULL) {
	this = uq;
	if (free_list == NULL || outunlink > 10)
	    return;
	ctrlp = free_list;
	ctrlp->fd = -2;
	ctrlp->done_handler = callback;
	ctrlp->done_handler_data = callback_data;
	ctrlp->operation = _AIO_UNLINK;
	if (aio_unlink(this->path, &(ctrlp->result)) < 0) {
	    if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
		return;
	    if (callback)
		(callback) (callback_data, -1, errno);
	    return;
	}
	free_list = free_list->next;
	ctrlp->next = used_list;
	used_list = ctrlp;
	outunlink++;
	uq = this->next;
	xfree(this->path);
	xfree(this);
    }
}				/* aioUnlink */


void
aioCheckCallbacks()
{
    aio_result_t *resultp;
    aio_ctrl_t *ctrlp;
    aio_ctrl_t *prev;
    int callunlink = 0;

    if (!initialised)
	aioInit();
    for (;;) {
	if ((resultp = aio_poll_done()) == NULL)
	    break;
	prev = NULL;
	for (ctrlp = used_list; ctrlp != NULL; prev = ctrlp, ctrlp = ctrlp->next)
	    if (&(ctrlp->result) == resultp)
		break;
	if (ctrlp == NULL)
	    continue;
	if (prev == NULL)
	    used_list = ctrlp->next;
	else
	    prev->next = ctrlp->next;
	if (ctrlp->done_handler)
	    (ctrlp->done_handler) (ctrlp->done_handler_data,
		ctrlp->result.aio_return, ctrlp->result.aio_errno);
	if (ctrlp->operation == _AIO_UNLINK) {
	    outunlink--;
	    callunlink = 1;
	}
	ctrlp->next = free_list;
	free_list = ctrlp;
    }
    if (callunlink)
	aioUnlink(NULL, NULL, NULL);
}

#endif /* USE_ASYNC_IO */
