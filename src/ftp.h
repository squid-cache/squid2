
/* $Id$ */

extern int ftpStart _PARAMS((int unusedfd, char *url, request_t * req, StoreEntry * entry));
extern int ftpInitialize _PARAMS((void));
extern int ftpCachable _PARAMS((char *));
extern void ftpServerClose _PARAMS((void));
