extern char *getMyHostname _PARAMS((void));
extern void fatal _PARAMS((char *message));
extern void fatal_dump _PARAMS((char *message));
extern int getMaxFD _PARAMS((void));
extern void death _PARAMS((void));
extern int safeunlink _PARAMS((char *path, int quiet));

extern int do_mallinfo;
