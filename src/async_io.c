
/*
 * $Id$
 *
 * DEBUG: section 32    Asynchronous Disk I/O
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

#if USE_ASYNC_IO

#include "squid.h"

/*
 * This is a totally bogus signal handler, it only exists so that when doing
 * asynch IO, the kernel will call this function when an asynch operation
 * completes (and causes a SIGIO to be delivered), thus interrupting any system
 * call in progress. In particular, it means we will fall out of the main
 * select() loop if disk IO completes while all the sockets are idle (lower
 * latency, but higher CPU cost --- perhaps it should be configurable)
 */
void
aioSigHandler(int sig)
{
#if !HAVE_SIGACTION
    signal(sig, aioSigHandler);
#endif
}

int
aioFileWriteComplete(int fd, FileEntry * entry)
{
    int rc;
    struct aiocb *aio = &entry->aio_cb;
    dwrite_q *q = NULL;
    int block_complete = 0;

    rc = aio_error(aio);
    entry->aio_data = NULL;	/* prevent duplicate calls */

    if (rc != 0) {
	/* disk i/o failure--flushing all outstanding writes  */
	errno = rc;
	debug(32, 1, "aioFileWriteComplete: FD %d: disk write error: %s\n",
	    fd, xstrerror());
	entry->write_daemon = NOT_PRESENT;
	entry->write_pending = NO_WRT_PENDING;
	/* call finish handler */
	do {
	    q = entry->write_q;
	    entry->write_q = q->next;
	    if (!entry->wrt_handle) {
		safe_free(q->buf);
	    } else {
		/* XXXXXX 
		 * Notice we call the handler multiple times but
		 * the write handler (in page mode) doesn't know
		 * the buf ptr so it'll be hard to deallocate
		 * memory.
		 * XXXXXX */
		entry->wrt_handle(fd,
		    rc == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR,
		    entry->wrt_handle_data);
	    }
	    safe_free(q);
	} while (entry->write_q);
	return DISK_ERROR;
    }
    rc = aio_return(aio);
    debug(32, 4, "AIO write FD %d returned %d\n", fd, rc);

    entry->write_q->cur_offset += rc;
    block_complete = (entry->write_q->cur_offset >= entry->write_q->len);

    if (block_complete && (!entry->write_q->next)) {
	/* No more data */
	if (!entry->wrt_handle)
	    safe_free(entry->write_q->buf);
	safe_free(entry->write_q);
	entry->write_q = entry->write_q_tail = NULL;
	entry->write_pending = NO_WRT_PENDING;
	entry->write_daemon = NOT_PRESENT;
	/* call finish handle */
	if (entry->wrt_handle) {
	    entry->wrt_handle(fd, DISK_OK, entry->wrt_handle_data);
	}
	/* Close it if requested */
	if (file_table[fd].close_request == REQUEST) {
	    file_close(fd);
	}
    } else if ((block_complete) && (entry->write_q->next)) {
	/* Do next block */

	/* XXXXX THESE PRIMITIVES ARE WEIRD XXXXX   
	 * If we have multiple blocks to send, we  
	 * only call the completion handler once, 
	 * so it becomes our job to free buffer space    
	 */
	q = entry->write_q;
	entry->write_q = entry->write_q->next;
	if (!entry->wrt_handle)
	    safe_free(q->buf);
	safe_free(q);
	/* Schedule next write */
	entry->write_daemon = PRESENT;
	return aioFileQueueWrite(fd,
	    aioFileWriteComplete,
	    &file_table[fd]);
    } else {			/* !Block_completed; block incomplete */
	/* reschedule */
	entry->write_daemon = PRESENT;
	return aioFileQueueWrite(fd,
	    aioFileWriteComplete,
	    &file_table[fd]);
    }
    return DISK_OK;
}

int
aioFileReadComplete(int fd, dread_ctrl * ctrl_dat)
{
    int rc;
    FileEntry *entry = &file_table[fd];
    struct aiocb *aio = &entry->aio_cb;

    rc = aio_error(aio);
    entry->aio_data = NULL;	/* prevent multiple calls */

    if (rc != 0) {
	debug(32, 4, "AIO read FD %d returned error %d\n", fd, rc);
	return DISK_ERROR;
    }
    rc = aio_return(aio);
    debug(32, 4, "AIO read FD %d returned %d bytes\n", fd, rc);
    ctrl_dat->cur_len += rc;
    ctrl_dat->offset += rc;
    if ((rc < ctrl_dat->req_len) && (rc != 0)) {
	/* Incomplete read, queue more --- This shouldn't happen! */
	aioFileQueueRead(fd, aioFileReadComplete, ctrl_dat);
    } else {
	int flag = rc ? DISK_OK : DISK_EOF;
	ctrl_dat->handler(fd, ctrl_dat->buf, ctrl_dat->cur_len, flag,
	    ctrl_dat->client_data, ctrl_dat->offset);
	safe_free(ctrl_dat);
    }
    return DISK_OK;
}

int
aioFileQueueWrite(int fd, int (*handler) (int, FileEntry *), FileEntry * entry)
{
    off_t offset;
    struct aiocb *aio;

    /*
     * Asynch. IO either requires O_APPEND to be set or to specify the offset each
     * time.  Too many things call file_write to trust in O_APPEND, so we have
     * to make a system call and get the actual offset.
     * XXX: If squid ever allows multiple writes on the same fd to be in
     * progress, we're hosed
     */
    if ((offset = lseek(fd, 0L, SEEK_END)) == (off_t) - 1)
	return DISK_ERROR;
    file_table[fd].at_eof = YES;

    aio = &file_table[fd].aio_cb;
    memset(aio, 0, sizeof(struct aiocb));
    aio->aio_fildes = fd;
    aio->aio_nbytes = entry->write_q->len - entry->write_q->cur_offset;
    aio->aio_offset = offset;
    aio->aio_buf = entry->write_q->buf + entry->write_q->cur_offset;
    aio->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    aio->aio_sigevent.sigev_signo = SIGIO;

    entry->aio_data = entry;
    entry->aio_handler = (int (*)(int, void *)) handler;
    debug(32, 4, "Queue AIO write, fd: %d, off: %ld, sz: %d\n", fd,
	aio->aio_offset, aio->aio_nbytes);
    if (aio_write(&entry->aio_cb) < 0)
	return DISK_ERROR;
    return DISK_OK;
}

int
aioFileQueueRead(int fd, int (*handler) (int, dread_ctrl *), dread_ctrl * ctrl_dat)
{
    struct aiocb *aio;

    /*
     * XXX: We stash the AIO conrol block for both reads and writes in the
     * appropriate file_table[] slot.  If reads and writes on the same fd
     * are ever scheduled, we're hosed
     */
    aio = &file_table[fd].aio_cb;
    memset(aio, 0, sizeof(struct aiocb));
    aio->aio_fildes = fd;
    aio->aio_nbytes = ctrl_dat->req_len - ctrl_dat->cur_len;
    aio->aio_offset = ctrl_dat->offset;
    aio->aio_buf = ctrl_dat->buf + ctrl_dat->cur_len;
    aio->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    aio->aio_sigevent.sigev_signo = SIGIO;

    file_table[fd].aio_data = ctrl_dat;
    file_table[fd].aio_handler = (int (*)(int, void *)) handler;
    debug(32, 4, "Queue AIO read, fd: %d, off: %ld, sz: %d\n", fd,
	aio->aio_offset, aio->aio_nbytes);
    if (aio_read(aio) < 0)
	return DISK_ERROR;
    return DISK_OK;
}

void
aioExamine(void)
{
    int fd;
    int rc;
    void *data;
    struct aiocb *aio;

    for (fd = 0; fd < FD_SETSIZE; fd++) {	/* XXX: only go up to max used fd */
	if (fdstatGetType(fd) != FD_FILE)
	    continue;
	/* Not in progress */
	if ((data = file_table[fd].aio_data) == NULL)
	    continue;
	aio = &file_table[fd].aio_cb;
	rc = aio_error(aio);
	if (rc == EINPROGRESS)
	    continue;
	debug(32, 4, "Call AIO handler for fd %d\n", fd);
	(file_table[fd].aio_handler) (fd, data);
    }
}

#endif
