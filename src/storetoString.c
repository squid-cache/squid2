/* $Id$ */

#include "squid.h"

/* convert store entry content to string. Use for debugging */
/* return pointer to static buffer containing string */
char *storeToString(e)
     StoreEntry *e;
{
    static char stsbuf[16 << 10];	/* have to make this really big */
    static char tmpbuf[8 << 10];
    time_t t;

    if (!e) {
	sprintf(stsbuf, "\nStoreEntry pointer is NULL.\n");
	return stsbuf;
    }
    sprintf(stsbuf, "\nStoreEntry @: 0x%p\n****************\n", e);
    strcat(stsbuf, tmpbuf);

    sprintf(stsbuf, "Current Time: %d [%s]\n", (int) cached_curtime,
	mkhttpdlogtime(&cached_curtime));
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Key: %s\n", e->key);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "URL: %s\n", e->url);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Next: 0x%p\n", e->next);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Flags: %#x ==> ", e->flag);
#ifdef CACHED1_5
    if (BIT_TEST(e->flag, SAVED))
	strncat(tmpbuf, " SAVED", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, VERIFYING_OBJ))
	strncat(tmpbuf, " VERIFYING", sizeof(tmpbuf) - 1);
#endif
    if (BIT_TEST(e->flag, KEY_CHANGE))
	strncat(tmpbuf, " KEYCHANGE", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, CACHABLE))
	strncat(tmpbuf, " CACHABLE", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, REFRESH_REQUEST))
	strncat(tmpbuf, " REFRESH_REQ", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	strncat(tmpbuf, " RELEASE_REQ", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, CLIENT_ABORT_REQUEST))
	strncat(tmpbuf, " CLIENT_ABORT", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, ABORT_MSG_PENDING))
	strncat(tmpbuf, " ABORT_MSG_PENDING", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, DELAY_SENDING))
	strncat(tmpbuf, " DELAY_SENDING", sizeof(tmpbuf) - 1);
    if (BIT_TEST(e->flag, DELETE_BEHIND))
	strncat(tmpbuf, " DELETE_BEHIND", sizeof(tmpbuf) - 1);
    if (e->lock_count)
	strncat(tmpbuf, "L", sizeof(tmpbuf) - 1);
    strcat(tmpbuf, "\n");
    strcat(stsbuf, tmpbuf);

    t = (time_t) e->timestamp;
    sprintf(tmpbuf, "Timestamp: %9d [%s]\n", (int) e->timestamp,
	mkhttpdlogtime(&t));
    strcat(stsbuf, tmpbuf);

    t = (time_t) e->lastref;
    sprintf(tmpbuf, "Lastref  : %9d [%s]\n", (int) e->lastref,
	mkhttpdlogtime(&t));
    strcat(stsbuf, tmpbuf);

    t = (time_t) e->expires;
    sprintf(tmpbuf, "Expires  : %9d [%s]\n", (int) e->expires,
	mkhttpdlogtime(&t));
    strcat(stsbuf, tmpbuf);

#ifdef CACHED1_5
    t = (time_t) e->lastverify;
    sprintf(tmpbuf, "Lastverify: %9d [%s]\n", (int) e->lastverify,
	mkhttpdlogtime(&t));
    strcat(stsbuf, tmpbuf);

    t = (time_t) e->lastmodified;
    sprintf(tmpbuf, "Lastmodified: %9d [%s]\n", (int) e->lastmodified,
	mkhttpdlogtime(&t));
    strcat(stsbuf, tmpbuf);
#endif

    sprintf(tmpbuf, "ObjectLen: %d\n", e->object_len);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapFileNumber: %d\n", e->swap_file_number);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "Status: ");
    switch (e->status) {

    case STORE_OK:
	strcat(tmpbuf, "STORE_OK\n");
	break;

    case STORE_PENDING:
	strcat(tmpbuf, "STORE_PENDING\n");
	break;

    case STORE_ABORTED:
	strcat(tmpbuf, "STORE_ABORTED\n");
	break;

    default:
	strcat(tmpbuf, "UNKNOWN\n");
	break;
    }
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "MemStatus: ");
    switch (e->mem_status) {

    case NOT_IN_MEMORY:
	strcat(tmpbuf, "NOT_IN_MEMORY\n");
	break;

    case SWAPPING_IN:
	strcat(tmpbuf, "SWAPPING_IN\n");
	break;

    case IN_MEMORY:
	strcat(tmpbuf, "IN_MEMORY\n");
	break;

    default:
	strcat(tmpbuf, "UNKNOWN\n");
	break;
    }
    strcat(stsbuf, tmpbuf);


    sprintf(tmpbuf, "PingStatus: ");
    switch (e->ping_status) {

    case WAITING:
	strcat(tmpbuf, "WAITING\n");
	break;

    case TIMEOUT:
	strcat(tmpbuf, "TIMEOUT\n");
	break;

    case DONE:
	strcat(tmpbuf, "DONE\n");
	break;

    case NOPING:
	strcat(tmpbuf, "NOPING\n");
	break;

    default:
	strcat(tmpbuf, "UNKNOWN\n");
	break;
    }
    strcat(stsbuf, tmpbuf);


    sprintf(tmpbuf, "SwapStatus: ");
    switch (e->swap_status) {

    case NO_SWAP:
	strcat(tmpbuf, "NO_SWAP\n");
	break;

    case SWAPPING_OUT:
	strcat(tmpbuf, "SWAPPING_OUT\n");
	break;

    case SWAP_OK:
	strcat(tmpbuf, "SWAP_OK\n");
	break;

    default:
	strcat(tmpbuf, "UNKNOWN\n");
	break;
    }
    strcat(stsbuf, tmpbuf);


    sprintf(tmpbuf, "TypeId: ");
    switch (e->type_id) {

    case REQ_GET:
	strcat(tmpbuf, "REQ_GET\n");
	break;

    case REQ_POST:
	strcat(tmpbuf, "REQ_POST\n");
	break;

    case REQ_HEAD:
	strcat(tmpbuf, "REQ_POST\n");
	break;

    default:
	strcat(tmpbuf, "UNKNOWN\n");
	break;
    }
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "RefCount: %u\n", e->refcount);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "LockCount: %d\n", e->lock_count);
    strcat(stsbuf, tmpbuf);

    if (!e->mem_obj) {
	sprintf(tmpbuf, "MemObject: NULL.\n");
	strcat(stsbuf, tmpbuf);
	return stsbuf;
    } else {
	sprintf(tmpbuf, "MemObject: 0x%p\n****************\n", e->mem_obj);
	strcat(stsbuf, tmpbuf);
    }

    if (!e->mem_obj->mime_hdr) {
	sprintf(tmpbuf, "MimeHdr: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	sprintf(tmpbuf, "MimeHdr:\n-----------\n%s\n-----------\n", e->mem_obj->mime_hdr);
	strcat(stsbuf, tmpbuf);
    }

    if (!e->mem_obj->data) {
	sprintf(tmpbuf, "Data: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	sprintf(tmpbuf, "Data: 0x%p\n", e->mem_obj->data);
	strcat(stsbuf, tmpbuf);
    }


    sprintf(tmpbuf, "E_swap_buf: %s\n", e->mem_obj->e_swap_buf);
    strcat(stsbuf, tmpbuf);
    sprintf(tmpbuf, "First_miss: 0x%p\n", e->mem_obj->e_pings_first_miss);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "E_swap_buf_len: %d\n", e->mem_obj->e_swap_buf_len);
    strcat(stsbuf, tmpbuf);
    sprintf(tmpbuf, "[pings]: npings = %d  nacks = %d\n",
	e->mem_obj->e_pings_n_pings, e->mem_obj->e_pings_n_acks);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapAccess: %d\n", e->mem_obj->e_swap_access);
    strcat(stsbuf, tmpbuf);

    if (!e->mem_obj->e_abort_msg) {
	sprintf(tmpbuf, "AbortMsg: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	sprintf(tmpbuf, "AbortMsg:\n-----------\n%s\n-----------\n", e->mem_obj->e_abort_msg);
	strcat(stsbuf, tmpbuf);
    }

    sprintf(tmpbuf, "CurrentLen: %d\n", e->mem_obj->e_current_len);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "LowestOffset: %d\n", e->mem_obj->e_lowest_offset);
    strcat(stsbuf, tmpbuf);

#ifdef CACHED1_5
    sprintf(tmpbuf, "FetchStall: %d\n", e->mem_obj->fetch_stall);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "FetchFd: %d\n", e->mem_obj->fetch_fd);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "FetchResumeOffset: %d\n", e->mem_obj->fetch_resume_offset);
    strcat(stsbuf, tmpbuf);
#endif

    sprintf(tmpbuf, "ClientListSize: %d\n", e->mem_obj->client_list_size);
    strcat(stsbuf, tmpbuf);

    if (!e->mem_obj->client_list) {
	sprintf(tmpbuf, "ClientList: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	int i;
	sprintf(tmpbuf, "ClientList: 0x%p\n", e->mem_obj->client_list);
	strcat(stsbuf, tmpbuf);

	for (i = 0; i < e->mem_obj->client_list_size; ++i) {
	    if (e->mem_obj->client_list[i])
		sprintf(tmpbuf, "    Client[%d]: fd == %d  last_offset == %d\n", i,
		    e->mem_obj->client_list[i]->fd, e->mem_obj->client_list[i]->last_offset);
	    else
		sprintf(tmpbuf, "    Client[%d]: NULL.\n", i);
	    strcat(stsbuf, tmpbuf);
	}
    }

    sprintf(tmpbuf, "SwapOffset: %u\n", e->mem_obj->swap_offset);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "SwapFd: %d\n", e->mem_obj->swap_fd);
    strcat(stsbuf, tmpbuf);

    sprintf(tmpbuf, "PendingListSize: %d\n", e->mem_obj->pending_list_size);
    strcat(stsbuf, tmpbuf);

    if (!e->mem_obj->pending) {
	sprintf(tmpbuf, "PendingList: NULL.\n");
	strcat(stsbuf, tmpbuf);
    } else {
	int i;
	sprintf(tmpbuf, "PendingList: 0x%p\n", e->mem_obj->pending);
	strcat(stsbuf, tmpbuf);

	for (i = 0; i < (int) e->mem_obj->pending_list_size; ++i) {
	    if (e->mem_obj->pending[i])
		sprintf(tmpbuf, "    Pending[%d]: fd == %d  handler == 0x%p data == 0x%p\n", i,
		    e->mem_obj->pending[i]->fd,
		    e->mem_obj->pending[i]->handler,
		    e->mem_obj->pending[i]->data);
	    else
		sprintf(tmpbuf, "    Pending[%d]: NULL.\n", i);
	    strcat(stsbuf, tmpbuf);
	}
    }

    strcat(stsbuf, "\n");

    return stsbuf;
}
