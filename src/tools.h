
/* $Id$ */

extern char *getMyHostname _PARAMS((void));
extern int getMaxFD _PARAMS((void));
extern int safeunlink _PARAMS((char *path, int quiet));
extern void death _PARAMS((int sig));
extern void fatal _PARAMS((char *message));
extern void fatal_dump _PARAMS((char *message));
extern void rotate_logs _PARAMS((int sig));
extern void shut_down _PARAMS((int sig));
extern void sig_child _PARAMS((int sig));
extern void check_suid _PARAMS((void));
extern void get_suid _PARAMS((void));
extern void no_suid _PARAMS((void));
extern void writePidFile _PARAMS((void));
extern void setMaxFD _PARAMS((void));
extern time_t getCurrentTime _PARAMS((void));
extern void normal_shutdown _PARAMS((void));
extern void reconfigure _PARAMS((int sig));
extern int tvSubMsec _PARAMS((struct timeval, struct timeval));

extern int do_mallinfo;
extern time_t squid_curtime;
extern struct timeval current_time;
