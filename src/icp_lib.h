/*  $Id$ */

#ifndef ICP_LIB_H
#define ICP_LIB_H

typedef struct obj {
    icp_common_t header;
    char *url;
    unsigned long ttl;
    unsigned long timestamp;
    unsigned long object_size;
    unsigned long buf_len;
    unsigned long offset;
    char *data;
} icp_object;

#endif
