
extern void cbdataInit _PARAMS((void));
extern void cbdataAdd _PARAMS((void *p));
extern void cbdataFree _PARAMS((void *p));
extern void cbdataLock _PARAMS((void *p));
extern void cbdataUnlock _PARAMS((void *p));
extern int cbdataValid _PARAMS((void *p));
extern void cbdataDump _PARAMS((StoreEntry *));
