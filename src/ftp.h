#ifndef FTP_H
#define FTP_H

typedef struct _ftpget_thread {
    pid_t pid;
    int state;
    int status;
    int wait_retval;
    int fd;
    struct _ftpget_thread *next;
} ftpget_thread;

#define FTPGET_THREAD_RUNNING  0
#define FTPGET_THREAD_WAITED   1

#endif
