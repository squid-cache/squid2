
/* $Id$ */

#ifndef _DYNAMIC_ARRAY_H
#define _DYNAMIC_ARRAY_H

typedef struct _dynamic_array {
    void **collection;
    int size;			/* array size */
    int delta;			/* amount to increase while run out of space */
    int index;			/* index for inserting entry into collection */
} dynamic_array;


extern dynamic_array *create_dynamic_array _PARAMS((int size, int delta));
extern int cut_dynamic_array _PARAMS((dynamic_array * ary, unsigned int new_size));
extern int insert_dynamic_array _PARAMS((dynamic_array * ary, void *entry));
extern void destroy_dynamic_array _PARAMS((dynamic_array * ary));

#endif
