/* $Id$ */

#ifndef FDSTAT_H
#define FDSTAT_H

#define PREOPEN_FD 3		/* number of preopened fd when process start */

typedef enum {
    LOG,
    File,
    Socket,
    Pipe,
    Unknown
} File_Desc_Type;

extern File_Desc_Type fdstat_type _PARAMS((int fd));
extern char *fd_describe _PARAMS((int fd));
extern int fdstat_biggest_fd _PARAMS((void));
extern int fdstat_init _PARAMS((int preopen));
extern int fdstat_isopen _PARAMS((int fd));
extern void fdstat_close _PARAMS((int fd));
extern void fdstat_open _PARAMS((int fd, File_Desc_Type type));
extern int fdstat_are_n_free_fd _PARAMS((int));
extern File_Desc_Type fdstatGetType _PARAMS((int));


#endif
