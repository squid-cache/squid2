/* $Id$ */

#include "squid.h"

/* return 0 for error */
dynamic_array *create_dynamic_array(size, delta)
     int size;
     int delta;
{
    dynamic_array *ary = NULL;

    ary = (dynamic_array *) xcalloc(1, sizeof(dynamic_array));
    ary->collection = (void *) xcalloc(size, sizeof(void *));
    ary->size = size;
    ary->delta = delta;
    ary->index = 0;
    return (ary);
}

int insert_dynamic_array(ary, entry)
     dynamic_array *ary;
     void *entry;
{
    /* if run out of space,then increae array's size
     * by the amount of ary->delta
     */
    if (ary->index >= ary->size) {
	ary->size += ary->delta;
	ary->collection = (void **) xrealloc(ary->collection, ary->size * sizeof(void *));
    }
    ary->collection[(ary->index)++] = entry;
    return (ary->index);
}

/* keep the first new_size items of array */
int cut_dynamic_array(ary, new_size)
     dynamic_array *ary;
     unsigned int new_size;
{
    if (ary->index > new_size)
	ary->index = new_size;
    return (ary->index);
}

void destroy_dynamic_array(ary)
     dynamic_array *ary;
{
    safe_free(ary->collection);
    safe_free(ary);
}
