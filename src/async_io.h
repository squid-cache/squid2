

extern void aioExamine _PARAMS((void));
extern void aioSigHandler _PARAMS((int sig));
extern int aioFileWriteComplete _PARAMS((int ed, FileEntry *entry));
extern int aioFileReadComplete _PARAMS((int fd, dread_ctrl *ctrl_dat));

