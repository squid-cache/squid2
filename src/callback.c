#include "squid.h"

callback_meta *
callbackRegister(void *callback_data, UNREG *unreg_func, void *unreg_data, callback_meta **head)
{
	callback_meta *cbm = xcalloc (1, sizeof(callback_meta));
	cbm->link_count++;
	cbm->callback_data = callback_data;
	cbm->unreg_func = unreg_func;
	cbm->unreg_data = unreg_data;
	if (head) {
		cbm->next = *head;
		*head = cbm;
		cbm->link_count++;
	}
	return cbm;
}

void
callbackUnregister(callback_meta *cbm)
{
	assert(cbm != NULL);
	assert(cbm->link_count >= 0);
	if (cbm->link_count == 0)
		return;
	cbm->link_count--;
	cbm->callback_data = NULL;
	cbm->unreg_func(cbm->unreg_data);
}

void *
callbackCheck(callback_meta *cbm)
{
	if (cbm->link_count == 0)
		return NULL;
	return cbm->callback_data;
	
}

void
callbackUnlink(callback_meta *cbm)
{
	assert(cbm->link_count > 0);
	--cbm->link_count;
	if (cbm->link_count == 0)
		safe_free(cbm);
}

void
callbackUnlinkList(callback_meta *cbm)
{
    callback_meta *c;
    while ((c = cbm)) {
	cbm = c->next;
	callbackUnlink(c);
    }
}
