/* filemap.h,v 1.1.6.1 1995/11/17 08:32:29 duane Exp */

#ifndef _FILEMAP_H_
#define _FILEMAP_H_

typedef struct _fileMap {
    int max_n_files;
    int n_files_in_map;
    int last_file_number_allocated;
    int toggle;
    int nwords;
    unsigned long *file_map;
} fileMap;

extern fileMap *file_map_create _PARAMS((int));
extern int file_map_allocate _PARAMS((int));
extern int file_map_bit_set _PARAMS((int));
extern int file_map_bit_test _PARAMS((int));
extern void file_map_bit_reset _PARAMS((int));

#endif /* _FILEMAP_H_ */
