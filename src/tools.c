
/* $Id$ */

/*
 * DEBUG: Section 21          tools
 */

#include "squid.h"

int do_mallinfo = 0;		/* don't do mallinfo() unless this gets set */
time_t squid_curtime;
struct timeval current_time;

extern void serverConnectionsClose _PARAMS((void));

#define DEAD_MSG "\
The Squid Cache (version %s) died.\n\
\n\
You've encountered a fatal error in the Squid Cache version %s.\n\
If a core file was created (possibly in the swap directory),\n\
please execute 'gdb squid core' or 'dbx squid core', then type 'where',\n\
and report the trace back to squid-bugs@nlanr.net.\n\
\n\
Thanks!\n"

static char *dead_msg()
{
    static char msg[1024];
    sprintf(msg, DEAD_MSG, version_string, version_string);
    return msg;
}

void mail_warranty()
{
    FILE *fp = NULL;
    static char filename[256];
    static char command[256];

    sprintf(filename, "/tmp/mailin%d", (int) getpid());
    fp = fopen(filename, "w");
    if (fp != NULL) {
	fprintf(fp, "From: %s\n", appname);
	fprintf(fp, "To: %s\n", getAdminEmail());
	fprintf(fp, "Subject: %s\n", dead_msg());
	fclose(fp);
	sprintf(command, "mail %s < %s", getAdminEmail(), filename);
	system(command);	/* XXX should avoid system(3) */
	unlink(filename);
    }
}

void print_warranty()
{
    if (getAdminEmail())
	mail_warranty();
    else
	puts(dead_msg());
}


static void dumpMallocStats(f)
     FILE *f;
{
#if HAVE_MALLINFO
    struct mallinfo mp;

    if (!do_mallinfo)
	return;

    mp = mallinfo();

    fprintf(f, "Malloc Instrumentation via mallinfo(): \n");
    fprintf(f, "   total space in arena  %d\n", mp.arena);
    fprintf(f, "   number of ordinary blocks  %d\n", mp.ordblks);
    fprintf(f, "   number of small blocks  %d\n", mp.smblks);
    fprintf(f, "   number of holding blocks  %d\n", mp.hblks);
    fprintf(f, "   space in holding block headers  %d\n", mp.hblkhd);
    fprintf(f, "   space in small blocks in use  %d\n", mp.usmblks);
    fprintf(f, "   space in free blocks  %d\n", mp.fsmblks);
    fprintf(f, "   space in ordinary blocks in use  %d\n", mp.uordblks);
    fprintf(f, "   space in free ordinary blocks  %d\n", mp.fordblks);
    fprintf(f, "   cost of enabling keep option  %d\n", mp.keepcost);
#if HAVE_EXT_MALLINFO
    fprintf(f, "   max size of small blocks  %d\n", mp.mxfast);
    fprintf(f, "   number of small blocks in a holding block  %d\n",
	mp.nlblks);
    fprintf(f, "   small block rounding factor  %d\n", mp.grain);
    fprintf(f, "   space (including overhead) allocated in ord. blks  %d\n",
	mp.uordbytes);
    fprintf(f, "   number of ordinary blocks allocated  %d\n",
	mp.allocated);
    fprintf(f, "   bytes used in maintaining the free tree  %d\n",
	mp.treeoverhead);
#endif /* HAVE_EXT_MALLINFO */

#if PRINT_MMAP
    mallocmap();
#endif /* PRINT_MMAP */
#endif /* HAVE_MALLINFO */
}
static int PrintRusage(f, lf)
     void (*f) ();
     FILE *lf;
{
#if HAVE_GETRUSAGE && defined(RUSAGE_SELF)
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    fprintf(lf, "CPU Usage: user %d sys %d\n",
	(int) rusage.ru_utime.tv_sec, (int) rusage.ru_stime.tv_sec);
    fprintf(lf, "Memory Usage: rss %ld KB\n",
	rusage.ru_maxrss * getpagesize() / 1000);
    fprintf(lf, "Page faults with physical i/o: %ld\n",
	rusage.ru_majflt);
#endif
    dumpMallocStats(lf);
    if (f)
	f(0);
    return 0;
}

void death(sig)
     int sig;
{
    if (sig == SIGSEGV)
	fprintf(debug_log, "FATAL: Received Segment Violation...dying.\n");
    else if (sig == SIGBUS)
	fprintf(debug_log, "FATAL: Received bus error...dying.\n");
    else
	fprintf(debug_log, "FATAL: Received signal %d...dying.\n", sig);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(sig, SIG_DFL);
    storeWriteCleanLog();
    PrintRusage(NULL, debug_log);
    print_warranty();
    abort();
}


void rotate_logs(sig)
     int sig;
{
    debug(21, 1, "rotate_logs: SIGUSR1 received.\n");

    storeWriteCleanLog();
    storeRotateLog();
    neighbors_rotate_log();
    stat_rotate_log();
    _db_rotate_log();
    signal(sig, rotate_logs);
}

void setSocketShutdownLifetimes()
{
    FD_ENTRY *f = NULL;
    int lft = getShutdownLifetime();
    int cur;
    int i;
    for (i = fdstat_biggest_fd(); i >= 0; i--) {
	f = &fd_table[i];
	if (!f->read_handler && !f->write_handler && !f->except_handler)
	    continue;
	if (fdstatGetType(i) != Socket)
	    continue;
	cur = comm_get_fd_lifetime(i);
	if (cur > 0 && (cur - squid_curtime) <= lft)
	    continue;
	comm_set_fd_lifetime(i, lft);
    }
}

void normal_shutdown()
{
    debug(21, 1, "Shutting down...\n");
    if (getPidFilename()) {
	enter_suid();
	safeunlink(getPidFilename(), 0);
	leave_suid();
    }
    storeWriteCleanLog();
    PrintRusage(NULL, debug_log);
    debug(21, 0, "Squid Cache (Version %s): Exiting normally.\n",
	version_string);
    exit(0);
}
void shut_down(sig)
     int sig;
{
    debug(21, 1, "Preparing for shutdown after %d connections\n",
	ntcpconn + nudpconn);
    serverConnectionsClose();
    ipcacheShutdownServers();
    ftpServerClose();
    setSocketShutdownLifetimes();
    shutdown_pending = 1;
    /* reinstall signal handler? */
}

void fatal_common(message)
     char *message;
{
#if HAVE_SYSLOG
    if (syslog_enable)
	syslog(LOG_ALERT, message);
#endif
    fprintf(debug_log, "FATAL: %s\n", message);
    fprintf(debug_log, "Squid Cache (Version %s): Terminated abnormally.\n",
	version_string);
    fflush(debug_log);
    PrintRusage(NULL, debug_log);
}

/* fatal */
void fatal(message)
     char *message;
{
    fatal_common(message);
    exit(1);
}

/* fatal with dumping core */
void fatal_dump(message)
     char *message;
{
    if (message)
	fatal_common(message);
    if (catch_signals)
	storeWriteCleanLog();
    abort();
}

void sig_child(sig)
     int sig;
{
#ifdef _SQUID_NEXT_
    union wait status;
#else
    int status;
#endif
    int pid;

    do {
#ifdef _SQUID_NEXT_
        pid = wait3(&status, WNOHANG, NULL);
#else
        pid = waitpid(-1, &status, WNOHANG);
#endif
	debug(21, 3, "sig_child: Ate pid %d\n", pid);
    } while (pid > 0 || (pid < 0 && errno == EINTR));
    signal(sig, sig_child);
}

char *getMyHostname()
{
    static char host[SQUIDHOSTNAMELEN + 1];
    static int present = 0;
    struct hostent *h = NULL;
    char *t = NULL;

    if ((t = getVisibleHostname()))
	return t;

    /* Get the host name and store it in host to return */
    if (!present) {
	host[0] = '\0';
	if (gethostname(host, SQUIDHOSTNAMELEN) == -1) {
	    debug(21, 1, "getMyHostname: gethostname failed: %s\n",
		xstrerror());
	    return NULL;
	} else {
	    if ((h = ipcache_gethostbyname(host)) != NULL) {
		/* DNS lookup successful */
		/* use the official name from DNS lookup */
		strcpy(host, h->h_name);
	    }
	    present = 1;
	}
    }
    return host;
}

int safeunlink(s, quiet)
     char *s;
     int quiet;
{
    int err;
    if ((err = unlink(s)) < 0)
	if (!quiet)
	    debug(21, 1, "safeunlink: Couldn't delete %s. %s\n", s, xstrerror());
    return (err);
}

/* leave a privilegied section. (Give up any privilegies)
 * Routines that need privilegies can rap themselves in enter_suid()
 * and leave_suid()
 * To give upp all posibilites to gain privilegies use no_suid()
 */
void leave_suid()
{
    struct passwd *pwd = NULL;
    struct group *grp = NULL;
    if (geteuid() != 0)
	return;
    /* Started as a root, check suid option */
    if (getEffectiveUser() == NULL)
	return;
    if ((pwd = getpwnam(getEffectiveUser())) == NULL)
	return;
    if (getEffectiveGroup() && (grp = getgrnam(getEffectiveGroup()))) {
	setgid(grp->gr_gid);
    } else {
	setgid(pwd->pw_gid);
    }
#if HAVE_SETRESUID
    setresuid(pwd->pw_uid, pwd->pw_uid, 0);
#elif HAVE_SETEUID
    seteuid(pwd->pw_uid);
#else
    setuid(pwd->pw_uid);
#endif
}

/* Enter a privilegied section */
void enter_suid()
{
#if HAVE_SETRESUID
    setresuid(-1, 0, -1);
#else
    setuid(0);
#endif
}

/* Give up the posibility to gain privilegies.
 * this should be used before starting a sub process
 */
void no_suid()
{
    uid_t uid;
    leave_suid();
    uid = geteuid();
#if HAVE_SETRESUID
    setresuid(uid, uid, uid);
#else
    setuid(0);
    setuid(uid);
#endif
}

void writePidFile()
{
    FILE *pid_fp = NULL;
    char *f = NULL;

    if ((f = getPidFilename()) == NULL)
	return;
    enter_suid();
    pid_fp = fopen(f, "w");
    leave_suid();
    if (pid_fp != NULL) {
        fprintf(pid_fp, "%d\n", (int) getpid());
        fclose(pid_fp);
    } else {
	debug(21, 0, "WARNING: Could not write pid file\n");
	debug(21, 0, "         %s: %s\n", f, xstrerror());
    }
}


void setMaxFD()
{
#if HAVE_SETRLIMIT
    /* try to use as many file descriptors as possible */
    /* System V uses RLIMIT_NOFILE and BSD uses RLIMIT_OFILE */
    struct rlimit rl;
#if defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
	debug(21, 0, "setrlimit: RLIMIT_NOFILE: %s", xstrerror());
    } else {
	rl.rlim_cur = FD_SETSIZE;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_NOFILE: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, &rl) < 0) {
	debug(21, 0, "setrlimit: RLIMIT_NOFILE: %s", xstrerror());
    } else {
	rl.rlim_cur = FD_SETSIZE;
	if (setrlimit(RLIMIT_OFILE, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_OFILE: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif
#else /* HAVE_SETRLIMIT */
    debug(21, 1, "setMaxFD: Cannot increase: setrlimit() not supported on this system");
#endif /* HAVE_SETRLIMIT */

#if HAVE_SETRLIMIT && defined(RLIMIT_DATA)
    if (getrlimit(RLIMIT_DATA, &rl) < 0) {
	debug(21, 0, "getrlimit: RLIMIT_DATA: %s", xstrerror());
    } else {
	rl.rlim_cur = rl.rlim_max;	/* set it to the max */
	if (setrlimit(RLIMIT_DATA, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_DATA: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif /* RLIMIT_DATA */
}

time_t getCurrentTime()
{
    gettimeofday(&current_time, NULL);
    return squid_curtime = current_time.tv_sec;
}


void reconfigure(sig)
     int sig;
{
    debug(21, 1, "reconfigure: SIGHUP received.\n");
    serverConnectionsClose();
    ipcacheShutdownServers();
    ftpServerClose();
    reread_pending = 1;
    setSocketShutdownLifetimes();
    signal(sig, reconfigure);
}

int tvSubMsec(t1, t2)
     struct timeval t1;
     struct timeval t2;
{
    return (t2.tv_sec - t1.tv_sec) * 1000 +
	(t2.tv_usec - t1.tv_usec) / 1000;
}
