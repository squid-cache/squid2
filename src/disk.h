/*  $Id$ */

#ifndef DISK_H
#define DISK_H

#define DISK_OK                   (0)
#define DISK_ERROR               (-1)
#define DISK_EOF                 (-2)
#define DISK_WRT_LOCK_FAIL       (-3)
#define DISK_WRT_WRONG_CODE      (-4)
#define DISK_FILE_NOT_FOUND      (-5)
#define DISK_NO_SPACE_LEFT       (-6)

typedef int (*FILE_READ_HD) _PARAMS((int fd, char *buf, int size, int errflag,
	void *data, int offset));

typedef int (*FILE_WALK_HD) _PARAMS((int fd, int errflag, void *data));

typedef int (*FILE_WALK_LHD) _PARAMS((int fd, char *buf, int size, void *line_data));



extern int file_open _PARAMS((char *path, int (*handler) (), int mode));
extern int file_close _PARAMS((int fd));
extern int file_write _PARAMS((int fd, char *buf, int len, int access_code,
	void       (*handle) (), void *handle_data));
extern int file_write_unlock _PARAMS((int fd, int access_code));
extern int file_read _PARAMS((int fd, char *buf, int req_len, int offset,
	int       (*handler) (int fd, char *buf, int size,
	    int errflag, void *data, int offset),
	void *client_data));
extern int file_walk _PARAMS((int fd,
	int       (*handler) (int fd, int errflag, void *data),
	void *client_data,
	int       (*line_handler)
	          (int fd, char *buf, int size, void *line_data),
	void *line_data));
extern int file_update_open _PARAMS((int fd, char *path));
extern int file_write_lock _PARAMS((int fd));
extern int disk_init _PARAMS((void));

#endif /* DISK_H */
