#ifndef AIOPS_H
#define AIOPS_H

typedef struct aio_result_t {
    int aio_return;
    int aio_errno;
} aio_result_t;

extern int aio_cancel _PARAMS((aio_result_t *));
extern int aio_open _PARAMS((const char *, int, mode_t, aio_result_t *));
extern int aio_read _PARAMS((int, char *, int, off_t, int, aio_result_t *));
extern int aio_write _PARAMS((int, char *, int, off_t, int, aio_result_t *));
extern int aio_close _PARAMS((int, aio_result_t *));
extern int aio_stat _PARAMS((const char *, struct stat *, aio_result_t *));
extern int aio_unlink _PARAMS((const char *, aio_result_t *));
extern int aio_opendir _PARAMS((void));
extern aio_result_t *aio_poll_done();

#endif /* AIOPS_H */
