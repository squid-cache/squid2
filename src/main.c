/* $Id$ */

/* DEBUG: Section 1             main: startup and main loop */

#include "squid.h"

time_t squid_starttime = 0;
time_t next_cleaning = 0;
int theHttpConnection = -1;
int theInIcpConnection = -1;
int theOutIcpConnection = -1;
int do_reuse = 1;
int opt_unlink_on_reload = 0;
int opt_reload_hit_only = 0;	/* only UDP_HIT during store relaod */
int catch_signals = 1;
int do_dns_test = 1;
int vhost_mode = 0;
int unbuffered_logs = 1;	/* debug and hierarhcy unbuffered by default */
int shutdown_pending = 0;	/* set by SIGTERM handler (shut_down()) */
int reread_pending = 0;		/* set by SIGHUP handler */
char version_string[] = SQUID_VERSION;
char appname[] = "squid";
char localhost[] = "127.0.0.1";
struct in_addr local_addr;

/* for error reporting from xmalloc and friends */
extern void (*failure_notify) _PARAMS((char *));

static int httpPortNumOverride = 1;
static int icpPortNumOverride = 1;	/* Want to detect "-u 0" */
#if MALLOC_DBG
static int malloc_debug_level = 0;
#endif

static void usage()
{
    fprintf(stderr, "\
Usage: %s [-hsvzCDRUVY] [-f config-file] [-[au] port]\n\
       -a port   Specify ASCII port number (default: %d).\n\
       -f file   Use given config-file instead of\n\
                 %s\n\
       -h        Print help message.\n\
       -s        Enable logging to syslog.\n\
       -u port   Specify UDP port number (default: %d), disable with 0.\n\
       -v        Print version.\n\
       -z        Zap disk storage -- deletes all objects in disk cache.\n\
       -C        Do not catch fatal signals.\n\
       -D        Disable initial DNS tests.\n\
       -R        Do not set REUSEADDR on port.\n\
       -U        Unlink expired objects on reload.\n\
       -V        Virtual host httpd-accelerator.\n\
       -Y        Only return UDP_HIT or UDP_DENIED during fast store reload.\n",
	appname, CACHE_HTTP_PORT, DefaultConfigFile, CACHE_ICP_PORT);
    exit(1);
}

static void mainParseOptions(argc, argv)
     int argc;
     char *argv[];
{
    extern char *optarg;
    int c;

    while ((c = getopt(argc, argv, "CDRUVYa:bf:hm:su:vz?")) != -1) {
	switch (c) {
	case 'C':
	    catch_signals = 0;
	    break;
	case 'D':
	    do_dns_test = 0;
	    break;
	case 'R':
	    do_reuse = 0;
	    break;
	case 'U':
	    opt_unlink_on_reload = 1;
	    break;
	case 'V':
	    vhost_mode = 1;
	    break;
	case 'Y':
	    opt_reload_hit_only = 1;
	    break;
	case 'a':
	    httpPortNumOverride = atoi(optarg);
	    break;
	case 'b':
	    unbuffered_logs = 0;
	    break;
	case 'f':
	    xfree(ConfigFile);
	    ConfigFile = xstrdup(optarg);
	    break;
	case 'h':
	    usage();
	    break;
	case 'm':
#if MALLOC_DBG
	    malloc_debug_level = atoi(optarg);
	    break;
#else
	    fatal("Need to add -DMALLOC_DBG when compiling to use -m option");
#endif
	case 's':
	    syslog_enable = 0;
	    break;
	case 'u':
	    icpPortNumOverride = atoi(optarg);
	    if (icpPortNumOverride < 0)
		icpPortNumOverride = 0;
	    break;
	case 'v':
	    printf("Squid Cache: Version %s\n", version_string);
	    exit(0);
	    /* NOTREACHED */
	case 'z':
	    zap_disk_store = 1;
	    break;
	case '?':
	default:
	    usage();
	    break;
	}
    }
}

void serverConnectionsOpen()
{
    struct in_addr addr;
    u_short port;
    /* Get our real priviliges */

    /* Open server ports */
    enter_suid();
    theHttpConnection = comm_open(COMM_NONBLOCKING,
	getTcpIncomingAddr(),
	getHttpPortNum(),
	"HTTP Port");
    leave_suid();
    if (theHttpConnection < 0) {
	fatal("Cannot open HTTP Port");
    }
    fd_note(theHttpConnection, "HTTP socket");
    comm_listen(theHttpConnection);
    comm_set_select_handler(theHttpConnection,
	COMM_SELECT_READ,
	asciiHandleConn,
	0);
    debug(1, 1, "Accepting HTTP connections on FD %d.\n",
	theHttpConnection);

    if (!httpd_accel_mode || getAccelWithProxy()) {
	if ((port = getIcpPortNum()) > 0) {
	    theInIcpConnection = comm_open(COMM_NONBLOCKING | COMM_DGRAM,
		getUdpIncomingAddr(),
		port,
		"ICP Port");
	    if (theInIcpConnection < 0)
		fatal("Cannot open ICP Port");
	    fd_note(theInIcpConnection, "ICP socket");
	    comm_set_select_handler(theInIcpConnection,
		COMM_SELECT_READ,
		icpHandleUdp,
		0);
	    debug(1, 1, "Accepting ICP connections on FD %d.\n",
		theInIcpConnection);

	    if ((addr = getUdpOutgoingAddr()).s_addr != INADDR_NONE) {
		theOutIcpConnection = comm_open(COMM_NONBLOCKING | COMM_DGRAM,
		    addr,
		    port,
		    "ICP Port");
		if (theOutIcpConnection < 0)
		    fatal("Cannot open Outgoing ICP Port");
		comm_set_select_handler(theOutIcpConnection,
		    COMM_SELECT_READ,
		    icpHandleUdp,
		    0);
		debug(1, 1, "Accepting ICP connections on FD %d.\n",
		    theOutIcpConnection);
		fd_note(theOutIcpConnection, "Outgoing ICP socket");
		fd_note(theInIcpConnection, "Incoming ICP socket");
	    } else {
		theOutIcpConnection = theInIcpConnection;
	    }
	}
    }
}

void serverConnectionsClose()
{
    if (theHttpConnection >= 0) {
	debug(21, 1, "FD %d Closing HTTP connection\n",
	    theHttpConnection);
	comm_close(theHttpConnection);
	comm_set_select_handler(theHttpConnection,
	    COMM_SELECT_READ,
	    NULL,
	    0);
	theHttpConnection = -1;
    }
    if (theInIcpConnection >= 0) {
	/* NOTE, don't close outgoing ICP connection, we need to write to
	 * it during shutdown */
	debug(21, 1, "FD %d Closing ICP connection\n",
	    theInIcpConnection);
	if (theInIcpConnection != theOutIcpConnection)
	    comm_close(theInIcpConnection);
	comm_set_select_handler(theInIcpConnection,
	    COMM_SELECT_READ,
	    NULL,
	    0);
	if (theInIcpConnection != theOutIcpConnection)
	    comm_set_select_handler(theOutIcpConnection,
		COMM_SELECT_READ,
		NULL,
		0);
	theInIcpConnection = -1;
    }
}

static void mainReinitialize()
{
    debug(1, 0, "Restarting Squid Cache (version %s)...\n", version_string);
    /* Already called serverConnectionsClose and ipcacheShutdownServers() */
    neighborsDestroy();

    parseConfigFile(ConfigFile);
    _db_init(getCacheLogFile(), getDebugOptions());
    neighbors_init();
    ipcacheOpenServers();
    serverConnectionsOpen();
    (void) ftpInitialize();
    if (theOutIcpConnection >= 0 && (!httpd_accel_mode || getAccelWithProxy()))
	neighbors_open(theOutIcpConnection);
    debug(1, 0, "Ready to serve requests.\n");
}

static void mainInitialize()
{
    static int first_time = 1;


    if (catch_signals) {
	signal(SIGSEGV, death);
	signal(SIGBUS, death);
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, sig_child);

    if (ConfigFile == NULL)
	ConfigFile = xstrdup(DefaultConfigFile);
    parseConfigFile(ConfigFile);

    leave_suid();		/* Run as non privilegied user */

    if (httpPortNumOverride != 1)
	setHttpPortNum((u_short) httpPortNumOverride);
    if (icpPortNumOverride != 1)
	setIcpPortNum((u_short) icpPortNumOverride);

    _db_init(getCacheLogFile(), getDebugOptions());
    fdstat_open(fileno(debug_log), LOG);
    fd_note(fileno(debug_log), getCacheLogFile());

    debug(1, 0, "Starting Squid Cache version %s for %s...\n",
	version_string,
	CONFIG_HOST_TYPE);
    debug(1, 1, "With %d file descriptors available\n", FD_SETSIZE);

    if (first_time) {
	disk_init();		/* disk_init must go before ipcache_init() */
	writePidFile();		/* write PID file */
    }
    ipcache_init();
    neighbors_init();
    (void) ftpInitialize();

#if MALLOC_DBG
    malloc_debug(0, malloc_debug_level);
#endif

    if (first_time) {
	first_time = 0;
	/* module initialization */
	urlInitialize();
	stat_init(&CacheInfo, getAccessLogFile());
	storeInit();
	stmemInit();

	if (getEffectiveUser()) {
	    /* we were probably started as root, so cd to a swap
	     * directory in case we dump core */
	    if (chdir(swappath(0)) < 0) {
		debug(1, 0, "%s: %s\n", swappath(0), xstrerror());
		fatal_dump("Cannot cd to swap directory?");
	    }
	}
	/* after this point we want to see the mallinfo() output */
	do_mallinfo = 1;
    }
    serverConnectionsOpen();
    if (theOutIcpConnection >= 0 && (!httpd_accel_mode || getAccelWithProxy()))
	neighbors_open(theOutIcpConnection);

    signal(SIGUSR1, rotate_logs);
    signal(SIGUSR2, sigusr2_handle);
    signal(SIGHUP, reconfigure);
    signal(SIGTERM, shut_down);
    signal(SIGINT, shut_down);

    debug(1, 0, "Ready to serve requests.\n");
}


int main(argc, argv)
     int argc;
     char **argv;
{
    int errcount = 0;
    int n;			/* # of GC'd objects */
    time_t last_maintain = 0;
    time_t last_announce = 0;
    time_t loop_delay;

    memset(&local_addr, '\0', sizeof(struct in_addr));
    local_addr.s_addr = inet_addr(localhost);

    errorInitialize();

    squid_starttime = getCurrentTime();
    failure_notify = fatal_dump;

    mainParseOptions(argc, argv);

    setMaxFD();

    for (n = FD_SETSIZE; n > 2; n--)
	close(n);

#if HAVE_MALLOPT
#ifdef M_GRAIN
    /* set malloc option */
    /* use small block algorithm for faster allocation */
    /* grain of small block */
    mallopt(M_GRAIN, 16);
#endif
#ifdef M_MXFAST
    /* biggest size that is considered a small block */
    mallopt(M_MXFAST, 512);
#endif
#ifdef M_NBLKS
    /* number of block in each chunk */
    mallopt(M_NLBLKS, 100);
#endif
#endif /* HAVE_MALLOPT */

    /*init comm module */
    comm_init();

    /* we have to init fdstat here. */
    fdstat_init(PREOPEN_FD);
    fdstat_open(0, LOG);
    fdstat_open(1, LOG);
    fdstat_open(2, LOG);
    fd_note(0, "STDIN");
    fd_note(1, "STDOUT");
    fd_note(2, "STDERR");

    /* enable syslog by default */
    syslog_enable = 0;

    /* preinit for debug module */
    debug_log = stderr;
    hash_init(0);

    mainInitialize();

    /* main loop */
    if (getCleanRate() > 0)
	next_cleaning = time(NULL) + getCleanRate();
    for (;;) {
	loop_delay = (time_t) 60;
	/* maintain cache storage */
	if (squid_curtime > last_maintain) {
	    storeMaintainSwapSpace();
	    last_maintain = squid_curtime;
	}
	/* do background processing */
	if (doBackgroundProcessing())
	    loop_delay = (time_t) 0;
	switch (comm_select(loop_delay, next_cleaning)) {
	case COMM_OK:
	    errcount = 0;	/* reset if successful */
	    break;
	case COMM_ERROR:
	    errcount++;
	    debug(1, 0, "Select loop Error. Retry %d\n", errcount);
	    if (errcount == 10)
		fatal_dump("Select Loop failed!");
	    break;
	case COMM_TIMEOUT:
	    /* this happens after 1 minute of idle time, or
	     * when next_cleaning has arrived */
	    /* garbage collection */
	    if (getCleanRate() > 0 && squid_curtime >= next_cleaning) {
		debug(1, 1, "Performing a garbage collection...\n");
		n = storePurgeOld();
		debug(1, 1, "Garbage collection done, %d objects removed\n", n);
		next_cleaning = squid_curtime + getCleanRate();
	    }
	    if ((n = getAnnounceRate()) > 0) {
		if (squid_curtime > last_announce + n)
		    send_announce();
		last_announce = squid_curtime;
	    }
	    /* house keeping */
	    break;
	case COMM_SHUTDOWN:
	    /* delayed close so we can transmit while shutdown pending */
	    if (theOutIcpConnection > 0) {
		comm_close(theOutIcpConnection);
		theOutIcpConnection = -1;
	    }
	    if (shutdown_pending) {
		normal_shutdown();
		exit(0);
	    } else if (reread_pending) {
		mainReinitialize();
		reread_pending = 0;	/* reset */
	    } else {
		fatal_dump("MAIN: SHUTDOWN from comm_select, but nothing pending.");
	    }
	    break;
	default:
	    fatal_dump("MAIN: Internal error -- this should never happen.");
	    break;
	}
    }
    /* NOTREACHED */
    exit(0);
    return 0;
}
