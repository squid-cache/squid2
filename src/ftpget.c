/*
 * $Id$
 *
 * DEBUG: section 38    FTP Retrieval
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

/*
 *    NOTES
 *      
 *      Directories vs. Files
 *      ---------------------
 *      
 *      Given 'ftp://foo/dir/bar' how do we know if 'bar' is a file or
 *      directory?  We can't assume anything from the URL, because people
 *      often leave trailing slashes off of directory URLs.  
 *      What we do here is try it one way first, and then try it the
 *      other way.
 *      
 *      Initially we tried CWD first, and RETR second.  This seemed to
 *      work pretty well.  If the last pathname component didn't exist
 *      at all (ie both CWD and RETR fail) then we got back a "No such
 *      file or directory" message from the ftpd.
 *      
 *      Then we tried ftp.microsoft.com (a Windows/NT) server.  On this
 *      "ftpd" you could successfully CWD to a file.  eg:
 *      
 *              ftp -d ftp.microsoft.com
 *              ...
 *              ftp> cd index.txt
 *              ---> CWD index.txt
 *              250 CWD command successful.
 *      
 *      So then we tried RETR before CWD.  Gets around the Microsoft bug,
 *      but this can cause incorrect error messages when a file is not
 *      readable.  Something like this happens:
 *      
 *              --> RETR passwd
 *              <-- 550 passwd: Permission denied.
 *              --> CWD passwd
 *              <-- 550 passwd: Not a directory.
 *      
 *      And the user ends up viewing the "Not a directory." message
 *      which is misleading and confusing.  Sigh.  The CERN httpd
 *      does this too.
 *      
 *      
 *      PASV vs. PORT
 *      -------------
 *      
 *      As of v1.4 pl1 we try to use PASV to make the data connection
 *      before using PORT.  PASV is more firewall-friendly.  At least
 *      one ftpd has been found which does not support PASV:
 *      ftp.isoc.org.  Because we fall back to PORT, users behind 
 *      firewalls may be confused as to why that site would fail.
 *      
 *      Use of HTML BASE tag
 *      --------------------
 *      
 *      Sometimes we have to use the HTML BASE tag to "force" the
 *      current URL to be a directory.  [[ we could do like httpd's
 *      do.  When they get requests for directories w/o the trailing
 *      slash, they return redirects with the slash so the browser
 *      can properly grok relative URLs. ]]  This is especially a
 *      problem for us with symbolic links.  We assume symbolic
 *      links point to files, not directories, so when a symlink
 *      really points to a directory, the URL we generate
 *      will be wrong.
 *      
 *      We insert the BASE tag when we know its a directory, but
 *      the given url-path didn't end with a slash.
 *      
 */

#include "squid.h"
#include "mime_table.h"

char *proxy_host = NULL;

#ifndef HAVE_GETOPT_H
extern int optind;
#endif

/* Junk so we can link with debug.o */
int opt_syslog_enable = 0;
volatile int unbuffered_logs = 1;
const char *const w_space = " \t\n\r";
const char *const appname = "ftpget";
struct timeval current_time;
time_t squid_curtime;
struct SquidConfig Config;

#define FTP_PORT 21
/* #define DEFAULT_MIME_TYPE "text/plain" */
#define DEFAULT_MIME_TYPE "application/octet-stream"
#define READ_TIMEOUT -2

#define MAGIC_MARKER	"\004\004\004"
#define MAGIC_MARKER_SZ	3

#define F_HTTPIFY	0x01
#define F_HDRSENT	0x02
#define F_ISDIR		0x04
#define F_NOERRS	0x08
#define F_TRYDIR	0x10
#define F_NEEDACCEPT	0x20
#define F_USEBASE	0x40
#define F_BASEDIR	0x80

#if !defined(SUN_LEN)
#define SUN_LEN(su) \
        (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

typedef enum {
    BEGIN,
    PARSE_OK,
    CONNECTED,
    FAIL_CONNECT,
    SERVICE_READY,
    NEED_PASSWD,
    LOGGED_IN,
    FAIL_LOGIN,
    TYPE_OK,
    MDTM_OK,
    SIZE_OK,
    PORT_OK,
    PASV_OK,
    PASV_FAIL,
    CWD_OK,
#ifdef TRY_CWD_FIRST
    CWD_FAIL,
#else
    RETR_FAIL,
#endif
    REST_OK,
    TRANSFER_BEGIN,
    DATA_TRANSFER,
    TRANSFER_DONE,
    DONE,
    FAIL_TIMEOUT,
    FAIL_SOFT,			/* don't cache these */
    FAIL_HARD			/* do cache these */
} state_t;

typedef struct _ftp_request {
    char *host;
    u_short port;
    char *path;
    char *type;
    char *user;
    char *pass;
    char *url_escaped;
    char *title_url;
    char *url;
    int cfd;
    int sfd;
    int dfd;
    int conn_att;
    int login_att;
    state_t state;
    int rc;
    char *errmsg;
    time_t mdtm;
    int size;
    int flags;
    char *mime_type;
    char *mime_enc;
    char *html_icon;
    FILE *readme_fp;
    struct _list_t *cmd_msg;
    int rest_offset;
    int rest_att;
    int rest_implemented;
    struct in_addr host_addr;
    int bytes_written;
} ftp_request_t;

typedef struct _parts {
    char type;
    int size;
    char *date;
    char *name;
    char *showname;
    char *link;
} parts_t;

typedef struct _list_t {
    char *ptr;
    struct _list_t *next;
} list_t;

/* OPTIONS */
static int o_conn_ret = 1;	/* connect retries */
static int o_login_ret = 1;	/* login retries */
static int o_rest_ret = 1;	/* restart retries */
static int o_conn_del = 3;	/* connect retry delay */
static int o_login_del = 30;	/* login retry delay */
static int o_rest_del = 3;	/* restart retry delay */
static int o_readme = 1;	/* get README ? */
static int o_timeout = XFER_TIMEOUT;	/* data/command timeout, from config.h */
static int o_neg_ttl = 300;	/* negative TTL, default 5 min */
static int o_httpify = 0;	/* convert to HTTP */
static int o_showpass = 1;	/* Show password in generated URLs */
static int o_showlogin = 1;	/* Show login info in generated URLs */
static const char *o_iconprefix = "internal-";	/* URL prefix for icons */
static const char *o_iconsuffix = "";	/* URL suffix for icons */
static int o_list_width = 32;	/* size of filenames in directory list */
static int o_list_wrap = 0;	/* wrap long directory names ? */
static u_short o_conn_min = 0x4000;	/* min. port number to use */
static u_short o_conn_max = 0x3fff + 0x4000;	/* max. port number to use */
static const char *socket_pathname = NULL;
static int o_max_bps = 0;	/* max bytes/sec */
static int o_skip_whitespace = 0;	/* skip whitespace in listings */
static struct timeval starttime;
static struct timeval currenttime;
unsigned int inaddr_none;

char *rfc1738_escape _PARAMS((const char *));
void rfc1738_unescape _PARAMS((char *));
static const char *dots_fill _PARAMS((size_t));
static const char *http_time _PARAMS((time_t));
static const char *html_trailer _PARAMS((void));
static char *htmlize_list_entry _PARAMS((const char *, ftp_request_t *));
static char *mime_get_icon _PARAMS((const char *));
static int accept_with_timeout _PARAMS((int, struct sockaddr *, int *));
static int check_data_rate _PARAMS((int));
static int connect_with_timeout _PARAMS((int, struct sockaddr_in *, int));
static int connect_with_timeout2 _PARAMS((int, struct sockaddr_in *, int));
static int ftpget_srv_mode _PARAMS((char *));
static int is_dfd_open _PARAMS((ftp_request_t *));
static int is_month _PARAMS((const char *));
static int read_with_timeout _PARAMS((int, char *, int));
static int read_reply _PARAMS((int));
static int readline_with_timeout _PARAMS((int, char *, int));
static int send_cmd _PARAMS((int, const char *));
static parts_t *parse_entry _PARAMS((const char *));
static state_t do_accept _PARAMS((ftp_request_t *));
static state_t do_connect _PARAMS((ftp_request_t *));
static state_t do_cwd _PARAMS((ftp_request_t *));
static state_t do_list _PARAMS((ftp_request_t *));
static state_t do_mdtm _PARAMS((ftp_request_t *));
static state_t do_passwd _PARAMS((ftp_request_t *));
static state_t do_pasv _PARAMS((ftp_request_t *));
static state_t do_port _PARAMS((ftp_request_t *));
static state_t do_rest _PARAMS((ftp_request_t *));
static state_t do_retr _PARAMS((ftp_request_t *));
static state_t do_size _PARAMS((ftp_request_t *));
static state_t do_type _PARAMS((ftp_request_t *));
static state_t do_user _PARAMS((ftp_request_t *));
static state_t htmlify_listing _PARAMS((ftp_request_t *));
static state_t parse_request _PARAMS((ftp_request_t *));
static state_t read_data _PARAMS((ftp_request_t *));
static state_t read_welcome _PARAMS((ftp_request_t *));
static state_t ftp_request_timeout _PARAMS((ftp_request_t *));
static time_t parse_iso3307_time _PARAMS((const char *));
static void cleanup_path _PARAMS((ftp_request_t *));
static void close_dfd _PARAMS((ftp_request_t *));
static void fail _PARAMS((ftp_request_t *));
static void generic_sig_handler _PARAMS((int));
static void mime_get_type _PARAMS((ftp_request_t * r));
static void send_success_hdr _PARAMS((ftp_request_t *));
static void sigchld_handler _PARAMS((int));
static void try_readme _PARAMS((ftp_request_t *));
static void usage _PARAMS((int));

#define SMALLBUFSIZ 1024
#define MIDBUFSIZ 2048
#define BIGBUFSIZ 8192


/*
 *  GLOBALS
 */
const char *progname = NULL;
static const char *fullprogname = NULL;
static char cbuf[SMALLBUFSIZ];	/* send command buffer */
static char htmlbuf[BIGBUFSIZ];
static char *server_reply_msg = NULL;
static struct sockaddr_in ifc_addr;
static time_t last_alarm_set = 0;
static ftp_request_t *MainRequest = NULL;
static char visible_hostname[SMALLBUFSIZ];
static struct in_addr outgoingTcpAddr;

/* This linked list holds the "continuation" lines before the final
 * reply code line is sent for a FTP command */
static list_t *cmd_msg = NULL;

static int process_request _PARAMS((ftp_request_t *));
static int write_with_timeout _PARAMS((int fd, char *buf, int len));

static const char *state_str[] =
{
    "BEGIN",
    "PARSE_OK",
    "CONNECTED",
    "FAIL_CONNECT",
    "SERVICE_READY",
    "NEED_PASSWD",
    "LOGGED_IN",
    "FAIL_LOGIN",
    "TYPE_OK",
    "MDTM_OK",
    "SIZE_OK",
    "PORT_OK",
    "PASV_OK",
    "PASV_FAIL",
    "CWD_OK",
#ifdef TRY_CWD_FIRST
    "CWD_FAIL",
#else
    "RETR_FAIL",
#endif
    "REST_OK",
    "TRANSFER_BEGIN",
    "DATA_TRANSFER",
    "TRANSFER_DONE",
    "DONE",
    "FAIL_TIMEOUT",
    "FAIL_SOFT",
    "FAIL_HARD"
};

/* 
 *  CACHED_RETRIEVE_ERROR_MSG args: 
 *      $1 is URL, 
 *      $2 is URL, 
 *      $3 is protocol type string
 *      $4 is error code, 
 *      $5 is error msg, 
 *      $6 is message to user
 *      $7 is time string
 *      $8 is cached version
 *      $9 is cached hostname
 */

#define CACHED_RETRIEVE_ERROR_MSG "\
<HTML><HEAD>\n\
<TITLE>ERROR: The requested URL could not be retrieved</TITLE>\n\
</HEAD><BODY><H1>ERROR</H1>\n\
<H2>The requested URL could not be retrieved</H2>\n\
<HR>\n\
<P>\n\
While trying to retrieve the URL:\n\
<A HREF=\"%s\">%s</A>\n\
<P>\n\
The following FTP error was encountered:\n\
<UL>\n\
<LI><STRONG>%s</STRONG>\n\
</UL>\n\
<P>This means that:\n\
<PRE>\n\
    %s\n\
</PRE>\n\
<P>\n\
\n"

static const char *
html_trailer(void)
{
    static char buf[SMALLBUFSIZ];

    sprintf(buf, "<HR><ADDRESS>\nGenerated %s, by squid-ftpget/%s@%s\n</ADDRESS>\n</BODY></HTML>\n", http_time((time_t) NULL), SQUID_VERSION, visible_hostname);
    return buf;
}

static void
fail(ftp_request_t * r)
{
    FILE *fp = NULL;
    char *longmsg = NULL;
    time_t expire_time;
    list_t *l = NULL;

    if (r->flags & F_NOERRS)
	return;

    switch (r->rc) {
    case 0:
	longmsg = "Success!  Huh?";
	break;
    case 2:
	longmsg = "A local socket error occurred.  Please try again.";
	break;
    case 3:
	longmsg = "A network socket error occurred.  Please try again.";
	break;
    case 4:
	longmsg = "A network read or write error occurred.  Please try again.";
	break;
    case 5:
	longmsg = "An FTP protocol error occurred.  Please try again.";
	break;
    case 6:
	longmsg = "A fatal signal was received.  Please try again.";
	break;
    case 7:
	longmsg = "A timeout occurred.  Please try again.";
	break;
    case 10:
	longmsg = "The given URL does not exist, or is not readable.";
	break;
    default:
	break;
    }

    if ((r->flags & F_HTTPIFY)) {
	if ((fp = fdopen(dup(r->cfd), "w")) == NULL) {
	    debug(38, 0, "fdopen: %s\n", xstrerror());
	    exit(1);
	}
	if (r->errmsg == NULL)
	    r->errmsg = xstrdup(xstrerror());	/* safety net */
	setbuf(fp, NULL);
	htmlbuf[0] = '\0';
	sprintf(htmlbuf, CACHED_RETRIEVE_ERROR_MSG,
	    r->title_url,
	    r->title_url,
	    r->errmsg,
	    longmsg);
	if (!(r->flags & F_HDRSENT)) {
	    debug(38, 3, "Preparing HTML error message\n");
	    expire_time = time(NULL) + o_neg_ttl;
	    fprintf(fp, "HTTP/1.0 500 Proxy Error\r\n");
	    fprintf(fp, "Date: %s\r\n", http_time(time(NULL)));
	    fprintf(fp, "Expires: %s\r\n", http_time(expire_time));
	    fprintf(fp, "MIME-Version: 1.0\r\n");
	    fprintf(fp, "Server: Squid %s\r\n", SQUID_VERSION);
	    fprintf(fp, "Content-Type: text/html\r\n");
	    /*fprintf(fp, "Content-Length: %d\r\n", (int) strlen(htmlbuf)); */
	    fprintf(fp, "\r\n");
	}
	fputs(htmlbuf, fp);
	if (r->conn_att > 1 || r->login_att > 1 || r->rest_att > 0) {
	    fprintf(fp, "<H4>Retry Attempts:</H4>\n<P>\n");
	    fprintf(fp, "Connect: %d<BR>\n", r->conn_att - 1);
	    fprintf(fp, "Login: %d<BR>\n", r->login_att - 1);
	    fprintf(fp, "Reget: %d<BR>\n", r->rest_att);
	}
	if (cmd_msg) {
	    fprintf(fp, "<HR><H4>Remote server replied with:</H4>\n");
	    fprintf(fp, "<PRE>\n");
	    for (l = cmd_msg; l; l = l->next)
		fputs(l->ptr, fp);
	    fprintf(fp, "</PRE>\n");
	}
	fputs(html_trailer(), fp);
	fclose(fp);
	if (r->flags & F_HTTPIFY) {
	    debug(38, 7, "Writing Marker to FD %d\n", r->cfd);
	    write_with_timeout(r->cfd, MAGIC_MARKER, MAGIC_MARKER_SZ);
	}
    } else if (r->errmsg) {
	debug(38, 0, "ftpget: %s\n", r->errmsg);
	debug(38, 0, "ftpget: '%s'\n", r->url);
    }
    xfree(r->errmsg);
}

static void
generic_sig_handler(int sig)
{
    static char buf[SMALLBUFSIZ];

    if (socket_pathname)
	unlink(socket_pathname);
    sprintf(buf, "Received signal %d, exiting.\n", sig);
    debug(38, 0, "ftpget: %s", buf);
    if (MainRequest == NULL)
	exit(1);
    MainRequest->rc = 6;
    MainRequest->errmsg = xstrdup(buf);
    fail(MainRequest);
    exit(MainRequest->rc);
}

static state_t
ftp_request_timeout(ftp_request_t * r)
{
    time_t now;
    static char buf[SMALLBUFSIZ];
    now = time(NULL);
    sprintf(buf, "Timeout after %d seconds.\n",
	(int) (now - last_alarm_set));
    debug(38, 0, "ftpget: %s", buf);
    r->errmsg = xstrdup(buf);
    r->rc = 7;
    return FAIL_TIMEOUT;
}

static void
sigchld_handler(int sig)
{
#if defined(_SQUID_NEXT_) && !defined(_POSIX_SOURCE)
    union wait status;
#else
    int status;
#endif
    pid_t pid;

#if defined(_SQUID_NEXT_) && !defined(_POSIX_SOURCE)
    if ((pid = wait4(0, &status, WNOHANG, NULL)) > 0)
#else
    if ((pid = waitpid(0, &status, WNOHANG)) > 0)
#endif
	debug(38, 5, "sigchld_handler: Ate pid %d\n", pid);
    signal(sig, sigchld_handler);
}

static int
write_with_timeout(int fd, char *buf, int sz)
{
    int x;
    fd_set R;
    fd_set W;
    struct timeval tv;
    int nwritten = 0;

    while (sz > 0) {
	tv.tv_sec = o_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&R);
	FD_ZERO(&W);
	FD_SET(fd, &W);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	debug(38, 7, "write_with_timeout: FD %d, %d seconds\n", fd, tv.tv_sec);
	x = select(fd + 1, &R, &W, NULL, &tv);
	debug(38, 7, "write_with_timeout: select returned %d\n", x);
	if (x < 0) {
	    if (errno == EWOULDBLOCK)
		continue;
	    if (errno == EAGAIN)
		continue;
	    /* anything else, fail */
	    return x;
	}
	if (x == 0)		/* timeout */
	    return READ_TIMEOUT;
	if (FD_ISSET(0, &R))
	    exit(1);		/* XXX very ungraceful! */
	x = write(fd, buf, sz);
	debug(38, 7, "write_with_timeout: write returned %d\n", x);
	if (x < 0) {
	    debug(38, 0, "write_with_timeout: %s\n", xstrerror());
	    return x;
	}
	if (x == 0)
	    continue;
	nwritten += x;
	sz -= x;
	buf += x;
    }
    return nwritten;
}

static int
read_with_timeout(int fd, char *buf, int sz)
{
    int x;
    fd_set R;
    struct timeval tv;
    for (;;) {
	tv.tv_sec = o_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&R);
	FD_SET(fd, &R);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	debug(38, 3, "read_with_timeout: FD %d, %d seconds\n", fd, tv.tv_sec);
	x = select(fd + 1, &R, NULL, NULL, &tv);
	if (x < 0) {
	    if (errno == EWOULDBLOCK)
		continue;
	    if (errno == EAGAIN)
		continue;
	    /* anything else, fail */
	    return x;
	}
	if (x == 0)		/* timeout */
	    return READ_TIMEOUT;
	if (FD_ISSET(0, &R))
	    exit(1);		/* XXX very ungraceful! */
	return read(fd, buf, sz);
    }
}

/* read until newline, sz, or timeout */
static int
readline_with_timeout(int fd, char *buf, int sz)
{
    int x;
    fd_set R;
    struct timeval tv;
    int nread = 0;
    char c = '@';

    while (nread < sz - 1) {
	tv.tv_sec = o_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&R);
	FD_SET(fd, &R);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	x = select(fd + 1, &R, NULL, NULL, &tv);
	if (x < 0) {
	    if (errno == EWOULDBLOCK)
		continue;
	    if (errno == EAGAIN)
		continue;
	    /* anything else, fail */
	    return x;
	}
	if (x == 0)		/* timeout */
	    return READ_TIMEOUT;
	if (FD_ISSET(0, &R))
	    exit(1);		/* XXX very ungraceful! */
	x = read(fd, &c, 1);
	debug(38, 9, "readline: x=%d  c='%c'\n", x, c);
	if (x < 0)
	    return x;
	if (x == 0)
	    break;
	buf[nread++] = c;
	if (c == '\n')
	    break;
    }
    buf[nread] = '\0';
    return nread;
}

static int
connect_with_timeout2(int fd, struct sockaddr_in *S, int len)
{
    int x;
    int y;
    fd_set W;
    fd_set R;
    struct timeval tv;
    int cerrno;
    debug(38, 7, "connect_with_timeout2: starting...\n");

    for (;;) {
	debug(38, 5, "Connecting FD %d to: %s, port %d, len = %d\n", fd,
	    inet_ntoa(S->sin_addr),
	    (int) ntohs(S->sin_port),
	    len);
	y = connect(fd, (struct sockaddr *) S, len);
	cerrno = errno;
	if (y < 0)
	    debug(38, 7, "connect: %s\n", xstrerror());
	if (y >= 0)
	    return y;
	if (cerrno == EISCONN)
	    return 0;
	if (cerrno == EINVAL) {
	    len = sizeof(x);
	    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &x, &len) >= 0)
		cerrno = x;
	}
	if (cerrno != EINPROGRESS && cerrno != EAGAIN)
	    return y;

	/* if we get here, y<0 and cerrno==EINPROGRESS|EAGAIN */

	tv.tv_sec = o_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&W);
	FD_ZERO(&R);
	FD_SET(fd, &W);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	debug(38, 7, "connect_with_timeout2: selecting on FD %d\n", fd);
	x = select(fd + 1, &R, &W, NULL, &tv);
	cerrno = errno;
	debug(38, 7, "select returned: %d\n", x);
	if (x == 0)
	    return READ_TIMEOUT;
	if (x < 0) {
	    if (cerrno == EWOULDBLOCK)
		continue;
	    if (cerrno == EAGAIN)
		continue;
	    /* anything else, fail */
	    return x;
	}
	if (FD_ISSET(0, &R))
	    exit(1);
    }
}

/* stupid wrapper for so we can set and clear O_NDELAY */
static int
connect_with_timeout(int fd, struct sockaddr_in *S, int len)
{
    int orig_flags;
    int rc;
    struct sockaddr_in L;
    if (outgoingTcpAddr.s_addr) {
	memset(&L, '\0', sizeof(struct sockaddr_in));
	L.sin_family = AF_INET;
	L.sin_addr = outgoingTcpAddr;
	L.sin_port = 0;
	if (bind(fd, (struct sockaddr *) &L, sizeof(struct sockaddr_in)) < 0) {
	    debug(38, 0, "bind: %s\n", xstrerror());
	}
    }
    orig_flags = fcntl(fd, F_GETFL, 0);
    debug(38, 7, "orig_flags = %x\n", orig_flags);
#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
    if (fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK) < 0)
	debug(38, 0, "fcntl O_NONBLOCK: %s\n", xstrerror());
#else
    if (fcntl(fd, F_SETFL, orig_flags | O_NDELAY) < 0)
	debug(38, 0, "fcntl O_NDELAY: %s\n", xstrerror());
#endif
    rc = connect_with_timeout2(fd, S, len);
    if (fcntl(fd, F_SETFL, orig_flags) < 0)
	debug(38, 0, "fcntl orig: %s\n", xstrerror());
    return rc;
}

static int
accept_with_timeout(int fd, struct sockaddr *S, int *len)
{
    int x;
    fd_set R;
    struct timeval tv;
    for (;;) {
	tv.tv_sec = o_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&R);
	FD_SET(fd, &R);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	debug(38, 7, "accept_with_timeout: selecting on FD %d\n", fd);
	x = select(fd + 1, &R, NULL, NULL, &tv);
	debug(38, 7, "select returned: %d\n", x);
	if (x == 0)
	    return READ_TIMEOUT;
	if (x < 0) {
	    if (errno == EWOULDBLOCK)
		continue;
	    if (errno == EAGAIN)
		continue;
	    return x;
	}
	if (FD_ISSET(0, &R))
	    exit(1);
	return accept(fd, S, len);
    }
    /* NOTREACHED */
}



/*
 *  If there are two extensions and both are listed in the types table
 *  then return the leftmost extention type.  The rightmost extention
 *  type becomes the content encoding (eg .gz)
 */
static void
mime_get_type(ftp_request_t * r)
{
    char *filename = NULL;
    char *ext = NULL;
    char *t = NULL;
    const char *type = NULL;
    const char *enc = NULL;
    int i;

    if (r->flags & F_ISDIR) {
	r->mime_type = xstrdup("text/html");
	return;
    }
    type = DEFAULT_MIME_TYPE;

    if ((t = strrchr(r->path, '/')))
	filename = xstrdup(t + 1);
    else
	filename = xstrdup(r->path);

    if (!(t = strrchr(filename, '.')))
	goto mime_get_type_done;
    ext = xstrdup(t + 1);
    for (i = 0; i < EXT_TABLE_LEN; i++) {
	if (!strcmp(ext, ext_mime_table[i].name)) {
	    type = ext_mime_table[i].mime_type;
	    enc = ext_mime_table[i].mime_encoding;
	    break;
	}
    }
    if (i == EXT_TABLE_LEN) {
	for (i = 0; i < EXT_TABLE_LEN; i++) {
	    if (!strcasecmp(ext, ext_mime_table[i].name)) {
		type = ext_mime_table[i].mime_type;
		enc = ext_mime_table[i].mime_encoding;
		break;
	    }
	}
    }
    /* now check for another extension */

    *t = '\0';
    if (!(t = strrchr(filename, '.')))
	goto mime_get_type_done;
    xfree(ext);
    ext = xstrdup(t + 1);
    for (i = 0; i < EXT_TABLE_LEN; i++) {
	if (!strcmp(ext, ext_mime_table[i].name)) {
	    type = ext_mime_table[i].mime_type;
	    break;
	}
    }
    if (i == EXT_TABLE_LEN) {
	for (i = 0; i < EXT_TABLE_LEN; i++) {
	    if (!strcasecmp(ext, ext_mime_table[i].name)) {
		type = ext_mime_table[i].mime_type;
		break;
	    }
	}
    }
  mime_get_type_done:
    xfree(filename);
    xfree(ext);
    r->mime_type = xstrdup(type);
    if (enc)
	r->mime_enc = xstrdup(enc);
}

static char *
mime_get_icon(const char *name)
{
    char *ext = NULL;
    const char *t = NULL;
    int i = 0;

    if (name == NULL)
	return xstrdup("unknown");
    if (!(t = strrchr(name, '.')))
	return xstrdup("unknown");
    ext = xstrdup(t + 1);
    debug(38, 3, "mime_get_icon: ext = '%s'\n", ext);
    for (i = 0; i < EXT_TABLE_LEN; i++) {
	if (!strcmp(ext, ext_mime_table[i].name)) {
	    debug(38, 3, "mime_get_icon: matched entry #%d\n", i);
	    debug(38, 3, "mime_get_icon: returning '%s'\n",
		ext_mime_table[i].icon);
	    xfree(ext);
	    return xstrdup(ext_mime_table[i].icon);
	    /* NOTREACHED */
	}
    }
    if (i == EXT_TABLE_LEN) {
	for (i = 0; i < EXT_TABLE_LEN; i++) {
	    if (!strcasecmp(ext, ext_mime_table[i].name)) {
		debug(38, 3, "mime_get_icon: matched entry #%d\n", i);
		debug(38, 3, "mime_get_icon: returning '%s'\n",
		    ext_mime_table[i].icon);
		xfree(ext);
		return xstrdup(ext_mime_table[i].icon);
		/* NOTREACHED */
	    }
	}
    }
    return xstrdup("unknown");
}

static const char *
http_time(time_t t)
{
    struct tm *gmt;
    time_t when;
    static char tbuf[128];

    when = t ? t : time(NULL);
    gmt = gmtime(&when);
    strftime(tbuf, 128, "%A, %d-%b-%y %H:%M:%S GMT", gmt);
    return tbuf;
}

static void
send_success_hdr(ftp_request_t * r)
{
    FILE *fp = NULL;

    if (r->flags & F_HDRSENT)
	return;

    r->flags |= F_HDRSENT;

    mime_get_type(r);

    if ((fp = fdopen(dup(r->cfd), "w")) == NULL) {
	debug(38, 0, "fdopen: %s\n", xstrerror());
	exit(1);
    }
    setbuf(fp, NULL);
    fprintf(fp, "HTTP/1.0 200 Gatewaying\r\n");
    fprintf(fp, "Date: %s\r\n", http_time(time(NULL)));
    fprintf(fp, "MIME-Version: 1.0\r\n");
    fprintf(fp, "Server: Squid %s\r\n", SQUID_VERSION);
    if (r->mime_type)
	fprintf(fp, "Content-Type: %s\r\n", r->mime_type);
    if (r->size > 0)
	fprintf(fp, "Content-Length: %d\r\n", r->size);
    if (r->mime_enc)
	fprintf(fp, "Content-Encoding: %s\r\n", r->mime_enc);
    if (r->mdtm > 0)
	fprintf(fp, "Last-Modified: %s\r\n", http_time(r->mdtm));
    fprintf(fp, "\r\n");
    fclose(fp);
}

/*
 *  read_reply()
 *  Read reply strings from an FTP server.
 * 
 *  Returns the reply code.
 */
static int
read_reply(int fd)
{
    static char buf[SMALLBUFSIZ];
    int quit = 0;
    char *t = NULL;
    int code;
    list_t **Tail = NULL;
    list_t *l = NULL;
    list_t *next = NULL;
    int n;

    for (l = cmd_msg; l; l = next) {
	next = l->next;
	xfree(l->ptr);
	xfree(l);
    }
    cmd_msg = NULL;
    Tail = &cmd_msg;

    while (!quit) {
	n = readline_with_timeout(fd, buf, SMALLBUFSIZ);
	debug(38, 9, "read_reply: readline returned %d\n", n);
	if (n < 0) {
	    xfree(server_reply_msg);
	    server_reply_msg = xstrdup(xstrerror());
	    return n;
	}
	if (n == 0)
	    quit = 1;
	else
	    quit = (buf[2] >= '0' && buf[2] <= '9' && buf[3] == ' ');
	if (!quit) {
	    l = xmalloc(sizeof(list_t));
	    if (sscanf(buf, "%3d-", &n) == 1)
		l->ptr = xstrdup(&buf[4]);
	    else
		l->ptr = xstrdup(&buf[strspn(buf, w_space)]);
	    l->next = NULL;
	    *Tail = l;
	    Tail = &(l->next);
	}
	if ((t = strchr(buf, '\r')))
	    *t = 0;
	if ((t = strchr(buf, '\n')))
	    *t = 0;
	debug(38, 3, "read_reply: %s\n", buf);
    }
    code = atoi(buf);
    xfree(server_reply_msg);
    server_reply_msg = xstrdup(&buf[4]);
    return code;
}

/*
 *  send_cmd()
 *  Write a command string
 * 
 *  Returns # bytes written
 */
static int
send_cmd(int fd, const char *buf)
{
    char *xbuf = NULL;
    size_t len;
    int x;

    len = strlen(buf) + 2;
    xbuf = xmalloc(len + 1);
    sprintf(xbuf, "%s\r\n", buf);
    debug(38, 3, "send_cmd: %s\n", buf);
    x = write_with_timeout(fd, xbuf, len);
    xfree(xbuf);
    return x;
}


#define ASCII_DIGIT(c) ((c)-48)
static time_t
parse_iso3307_time(const char *buf)
{
/* buf is an ISO 3307 style time: YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx */
    struct tm tms;
    time_t t;

    while (*buf == ' ' || *buf == '\t')
	buf++;
    if ((int) strlen(buf) < 14)
	return 0;
    memset(&tms, '\0', sizeof(struct tm));
    tms.tm_year = (ASCII_DIGIT(buf[2]) * 10) + ASCII_DIGIT(buf[3]);
    tms.tm_mon = (ASCII_DIGIT(buf[4]) * 10) + ASCII_DIGIT(buf[5]) - 1;
    tms.tm_mday = (ASCII_DIGIT(buf[6]) * 10) + ASCII_DIGIT(buf[7]);
    tms.tm_hour = (ASCII_DIGIT(buf[8]) * 10) + ASCII_DIGIT(buf[9]);
    tms.tm_min = (ASCII_DIGIT(buf[10]) * 10) + ASCII_DIGIT(buf[11]);
    tms.tm_sec = (ASCII_DIGIT(buf[12]) * 10) + ASCII_DIGIT(buf[13]);

#if HAVE_TIMEGM
    t = timegm(&tms);
#elif HAVE_MKTIME
    t = mktime(&tms);
#else
    t = (time_t) 0;
#endif

    debug(38, 3, "parse_iso3307_time: %d\n", t);
    return t;
}
#undef ASCII_DIGIT

#define SEND_CBUF \
        if (send_cmd(r->sfd, cbuf) < 0) { \
                r->errmsg = xmalloc (SMALLBUFSIZ); \
                sprintf(r->errmsg, "Failed to send '%s'", cbuf); \
                r->rc = 4; \
                return FAIL_SOFT; \
        }

/*
 *  close_dfd()
 *  Close any open data channel
 */
static void
close_dfd(ftp_request_t * r)
{
    if (r->dfd >= 0)
	close(r->dfd);
    r->flags &= ~F_NEEDACCEPT;
    r->dfd = -1;
}

/*
 *  is_dfd_open()
 *  Check if a data channel is already open
 */
static int
is_dfd_open(ftp_request_t * r)
{
    if (r->dfd >= 0 && !(r->flags & F_NEEDACCEPT)) {
	fd_set R;
	struct timeval tv;
	FD_ZERO(&R);
	FD_SET(r->dfd, &R);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	if (select(r->dfd + 1, &R, NULL, NULL, &tv) == 0) {
	    debug(38, 3, "Data channel already connected (FD=%d)\n", r->dfd);
	    return 1;
	} else {
	    debug(38, 2, "Data channel closed by server (%s)\n", xstrerror());
	}
    } else if (r->dfd >= 0) {
	debug(38, 2, "Data socket not connected, closing\n");
    }
    close_dfd(r);
    return 0;
}

/*
 *  parse_request()
 *  Perform validity checks on request parameters.
 *    - lookup hostname
 * 
 *  Returns states:
 *    FAIL_HARD
 *    PARSE_OK
 */
static state_t
parse_request(ftp_request_t * r)
{
    const struct hostent *hp;
    char *host = proxy_host ? proxy_host : r->host;
    debug(38, 3, "parse_request: looking up '%s'\n", host);
    r->host_addr.s_addr = inet_addr(host);	/* try numeric */
    if (r->host_addr.s_addr != inaddr_none)
	return PARSE_OK;
    hp = gethostbyname(host);
    if (hp == NULL) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "Unknown host: %s", host);
	r->rc = 10;
	return FAIL_HARD;
    }
    xmemcpy(&r->host_addr.s_addr, *hp->h_addr_list, 4);
    return PARSE_OK;
}

/*
 *  do_connect()
 *  Connect to the FTP server r->host on r->port.
 * 
 *  Returns states:
 *    CONNECTED
 *    FAIL_CONNECT
 */
static state_t
do_connect(ftp_request_t * r)
{
    int sock;
    struct sockaddr_in S;
    int len;
    int x;

    r->conn_att++;
    debug(38, 3, "do_connect: connect attempt #%d to '%s'\n",
	r->conn_att, r->host);
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "socket: %s", xstrerror());
	r->rc = 2;
	return FAIL_CONNECT;
    }
    memset(&S, '\0', sizeof(struct sockaddr_in));
    S.sin_addr = r->host_addr;
    S.sin_family = AF_INET;
    S.sin_port = htons(r->port);

    x = connect_with_timeout(sock, &S, sizeof(S));
    if (x == READ_TIMEOUT) {
	(void) ftp_request_timeout(r);
	return FAIL_CONNECT;
    }
    if (x < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "%s (port %d): %s",
	    r->host, r->port, xstrerror());
	r->rc = 3;
	return FAIL_CONNECT;
    }
    r->sfd = sock;

    /* get the address of whatever interface we're using so we know */
    /* what to use in the PORT command.                             */
    len = sizeof(ifc_addr);
    if (getsockname(sock, (struct sockaddr *) &ifc_addr, &len) < 0) {
	debug(38, 0, "getsockname: %s\n", xstrerror());
	exit(1);
    }
    if (outgoingTcpAddr.s_addr)
	ifc_addr.sin_addr = outgoingTcpAddr;
    return CONNECTED;
}

/*
 *  read_welcome()
 *  Parse the ``welcome'' message from the FTP server
 * 
 *  Returns states:
 *    SERVICE_READY
 *    FAIL_CONNECT
 */
static state_t
read_welcome(ftp_request_t * r)
{
    int code;
    char *p = NULL;
#ifdef PASVONLY
    r->login_att++;
#endif /* PASVONLY */
    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 220) {
	    p = cmd_msg ? cmd_msg->ptr : server_reply_msg;
	    if (p)
		if (strstr(p, "NetWare"))
		    o_skip_whitespace = 1;
	    return SERVICE_READY;
	}
    }
    close(r->sfd);
    r->sfd = -1;
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_CONNECT;
}

/*
 *  do_user()
 *  Send the USER command to the FTP server
 * 
 *  Returns states:
 *    LOGGED_IN
 *    NEED_PASSWD
 *    FAIL_LOGIN
 */
static state_t
do_user(ftp_request_t * r)
{
    int code;

#ifndef PASVONLY
    r->login_att++;
#endif /* PASVONLY */

    if (proxy_host != NULL) {
	sprintf(cbuf, "USER %s@%s", r->user, r->host);
	SEND_CBUF;
    } else {
	sprintf(cbuf, "USER %s", r->user);
	SEND_CBUF;
    }
    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 230)
	    return LOGGED_IN;
	if (code == 331)
	    return NEED_PASSWD;
    }
    close(r->sfd);
    r->sfd = -1;
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_LOGIN;
}

/*
 *  do_passwd()
 *  Send the USER command to the FTP server
 * 
 *  Returns states:
 *    LOGGED_IN
 *    FAIL_LOGIN
 */
static state_t
do_passwd(ftp_request_t * r)
{
    int code;

    sprintf(cbuf, "PASS %s", r->pass);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 230)
	    return LOGGED_IN;
    }
    close(r->sfd);
    r->sfd = -1;
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_LOGIN;
}

static state_t
do_type(ftp_request_t * r)
{
    int code;

    sprintf(cbuf, "TYPE %c", *(r->type));
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 200)
	    return TYPE_OK;
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static state_t
do_mdtm(ftp_request_t * r)
{
    int code;

    sprintf(cbuf, "MDTM %s", r->path);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 213)
	    r->mdtm = parse_iso3307_time(server_reply_msg);
    }
    if (code < 0) {
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 4;
	return FAIL_SOFT;
    }
    return MDTM_OK;
}

static state_t
do_size(ftp_request_t * r)
{
    int code;

    sprintf(cbuf, "SIZE %s", r->path);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 213)
	    r->size = atoi(server_reply_msg);
    }
    if (code < 0) {
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 4;
	return FAIL_SOFT;
    }
    return SIZE_OK;
}

static state_t
do_port(ftp_request_t * r)
{
    int code;
    int sock;
    struct sockaddr_in S;
    unsigned int naddr;
    int tries = 0;
    u_short port = 0;
    static int init = 0;

    if (is_dfd_open(r))
	return PORT_OK;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "socket: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    S = ifc_addr;
    S.sin_family = AF_INET;

#if !defined(PASVONLY)

    if (!init) {
	init = 1;
#if HAVE_SRAND48
	srand48(time(NULL));
#else
	srand(time(NULL));
#endif
    }
    for (;;) {
#if HAVE_LRAND48
	port = (u_short) (lrand48() % (o_conn_max - o_conn_min)) + o_conn_min;
#else
	port = (u_short) (rand() % (o_conn_max - o_conn_min)) + o_conn_min;
#endif
	S.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *) &S, sizeof(S)) >= 0)
	    break;
	if (++tries < 10)
	    continue;
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "bind: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
#else
    {
	port = 0;
	S.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *) &S, sizeof(S)) < 0) {
	    r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	    sprintf(r->errmsg, "bind: %s", xstrerror());
	    r->rc = 2;
	    return FAIL_SOFT;
	}
	port = ntohs(S.sin_port);
    }
#endif /* PASVONLY */


    if (listen(sock, 1) < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "listen: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    debug(38, 3, "listening on FD %d\n", sock);
    naddr = ntohl(ifc_addr.sin_addr.s_addr);
    sprintf(cbuf, "PORT %d,%d,%d,%d,%d,%d",
	(naddr >> 24) & 0xFF,
	(naddr >> 16) & 0xFF,
	(naddr >> 8) & 0xFF,
	naddr & 0xFF,
	((int) port >> 8) & 0xFF,
	port & 0xFF);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 200) {
	    r->dfd = sock;
	    r->flags |= F_NEEDACCEPT;
	    return PORT_OK;
	}
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static state_t
do_pasv(ftp_request_t * r)
{
    int code;
    int sock;
    struct sockaddr_in S;
    u_short port = 0;
    int n;
    int h1, h2, h3, h4;
    int p1, p2;
    static char junk[SMALLBUFSIZ];
    static int pasv_supported = 1;

    /* if PASV previously failed, don't even try it again.  Just return
     * PASV_FAIL and let the state machine fall back to using PORT */
    if (!pasv_supported)
	return PASV_FAIL;

    /* If there already are a open data connection, use that */
    if (is_dfd_open(r))
	return PORT_OK;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "socket: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    S = ifc_addr;
    S.sin_family = AF_INET;

    sprintf(cbuf, "PASV");
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) != 227) {
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = code < 0 ? 4 : 5;
	pasv_supported = 0;
	return PASV_FAIL;
    }
    /*  227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).  */
    /*  ANSI sez [^0-9] is undefined, it breaks on Watcom cc */
    n = sscanf(server_reply_msg, "%[^0123456789]%d,%d,%d,%d,%d,%d",
	junk, &h1, &h2, &h3, &h4, &p1, &p2);
    if (n != 7 || p1 < 0 || p2 < 0) {
	/* note RISC/os sends negative numbers in PASV reply */
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 5;
	pasv_supported = 0;
	return PASV_FAIL;
    }
    sprintf(junk, "%d.%d.%d.%d", h1, h2, h3, h4);
    S.sin_addr.s_addr = inet_addr(junk);
    S.sin_port = htons(port = ((p1 << 8) + p2));

    if (connect_with_timeout(sock, &S, sizeof(S)) < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "%s, port %d: %s", junk, port, xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    r->dfd = sock;
    return PORT_OK;
}

static state_t
do_cwd(ftp_request_t * r)
{
    int code;

    debug(38, 9, "do_cwd: \"%s\"\n", r->path);

    if (r->flags & F_BASEDIR)
	return CWD_OK;

    sprintf(cbuf, "CWD %s", r->path);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code >= 200 && code < 300)
	    return CWD_OK;
#ifdef TRY_CWD_FIRST
	if (!(r->flags & F_ISDIR))
	    return CWD_FAIL;
#endif
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 10;
	return FAIL_HARD;
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static state_t
do_rest(ftp_request_t * r)
{
    int code;

    if (!r->rest_implemented && r->rest_offset == 0)
	return REST_OK;

    sprintf(cbuf, "REST %d", r->rest_offset);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 350)
	    return REST_OK;
	r->rest_implemented = 0;
	if (r->rest_offset == 0)
	    return REST_OK;
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}


static state_t
do_retr(ftp_request_t * r)
{
    int code;

    sprintf(cbuf, "RETR %s", r->path);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code >= 100 && code < 200)
	    return TRANSFER_BEGIN;
#ifdef TRY_CWD_FIRST
	if (code == 550) {
	    r->errmsg = xstrdup(server_reply_msg);
	    r->rc = 10;
	    return FAIL_HARD;
	}
#else
	if (r->flags & F_TRYDIR)
	    return RETR_FAIL;
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 10;
	return FAIL_HARD;
#endif
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static state_t
do_list(ftp_request_t * r)
{
    int code;

    sprintf(cbuf, "LIST");
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 125)
	    return TRANSFER_BEGIN;
	if (code == 150)
	    return TRANSFER_BEGIN;
	if (code == 450) {
	    r->errmsg = xstrdup(server_reply_msg);
	    r->rc = 10;
	    return FAIL_HARD;
	}
    }
    sprintf(cbuf, "NLST");
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 125)
	    return TRANSFER_BEGIN;
	if (code == 150)
	    return TRANSFER_BEGIN;
	if (code == 450) {
	    r->errmsg = xstrdup(server_reply_msg);
	    r->rc = 10;
	    return FAIL_HARD;
	}
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static state_t
do_accept(ftp_request_t * r)
{
    int sock;
    struct sockaddr S;
    int len;

    len = sizeof(S);
    memset(&S, '\0', len);
    sock = accept_with_timeout(r->dfd, &S, &len);
    if (sock == READ_TIMEOUT)
	return ftp_request_timeout(r);
    if (sock < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "accept: %s", xstrerror());
	r->rc = 3;
	return FAIL_SOFT;
    }
    close_dfd(r);
    r->dfd = sock;
    return DATA_TRANSFER;
}

static state_t
read_data(ftp_request_t * r)
{
    int code;
    int n;
    static char buf[SQUID_TCP_SO_RCVBUF];
    int x;
    int read_sz = SQUID_TCP_SO_RCVBUF;

    while (check_data_rate(r->bytes_written))
	sleep(1);
    if (0 < o_max_bps && o_max_bps < read_sz)
	read_sz = o_max_bps;
    n = read_with_timeout(r->dfd, buf, read_sz);
    if (n == READ_TIMEOUT) {
	return ftp_request_timeout(r);
    } else if (n < 0) {
	close_dfd(r);
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "read: %s", xstrerror());
	r->rc = 4;
	return FAIL_SOFT;
    } else if (n == 0) {
	close_dfd(r);
	if ((code = read_reply(r->sfd)) > 0) {
	    if (code == 226)
		return TRANSFER_DONE;
	}
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = code < 0 ? 4 : 5;
	return FAIL_SOFT;
    }
    x = write_with_timeout(r->cfd, buf, n);
    if (x == READ_TIMEOUT)
	return ftp_request_timeout(r);
    if (x < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "write cfd: %s", xstrerror());
	r->rc = 4;
	return FAIL_SOFT;
    }
    r->bytes_written += x;
    r->rest_offset += n;
    return r->state;
}

static const char *Month[] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static int
is_month(const char *buf)
{
    int i;

    for (i = 0; i < 12; i++)
	if (!strcasecmp(buf, Month[i]))
	    return 1;
    return 0;
}

#define MAX_TOKENS 64

static parts_t *
parse_entry(const char *buf)
{
    parts_t *p = NULL;
    char *t = NULL;
    const char *ct = NULL;
    char *tokens[MAX_TOKENS];
    int i;
    int n_tokens;
    const char *const WS = " \t\n";
    static char sbuf[128];
    char *xbuf = NULL;

    if (buf == NULL)
	return NULL;

    if (*buf == '\0')
	return NULL;

    p = xcalloc(1, sizeof(parts_t));

    n_tokens = 0;
    for (i = 0; i < MAX_TOKENS; i++)
	tokens[i] = (char *) NULL;

    xbuf = xstrdup(buf);
    for (t = strtok(xbuf, WS); t && n_tokens < MAX_TOKENS; t = strtok(NULL, WS))
	tokens[n_tokens++] = xstrdup(t);
    xfree(xbuf);

    /* locate the Month field */
    for (i = 3; i < n_tokens - 3; i++) {
	if (!is_month(tokens[i]))	/* Month */
	    continue;
	if (!sscanf(tokens[i - 1], "%[0-9]", sbuf))	/* Size */
	    continue;
	if (!sscanf(tokens[i + 1], "%[0-9]", sbuf))	/* Day */
	    continue;
	if (!sscanf(tokens[i + 2], "%[0-9:]", sbuf))	/* Yr | hh:mm */
	    continue;
	p->type = *tokens[0];
	p->size = atoi(tokens[i - 1]);
	sprintf(sbuf, "%s %2s %5s",
	    tokens[i], tokens[i + 1], tokens[i + 2]);
	if (!strstr(buf, sbuf))
	    sprintf(sbuf, "%s %2s %-5s",
		tokens[i], tokens[i + 1], tokens[i + 2]);
	if ((t = strstr(buf, sbuf))) {
	    p->date = xstrdup(sbuf);
	    if (o_skip_whitespace) {
		t += strlen(sbuf);
		while (strchr(WS, *t))
		    t++;
	    } else {
		/* XXX assumes a single space between date and filename
		 * suggested by:  Nathan.Bailey@cc.monash.edu.au and
		 * Mike Battersby <mike@starbug.bofh.asn.au> */
		t += strlen(sbuf) + 1;
	    }
	    p->name = xstrdup(t);
	    if ((t = strstr(p->name, " -> "))) {
		*t = '\0';
		p->link = xstrdup(t + 4);
	    }
	}
	break;
    }

    /* try it as a DOS listing */
    if (n_tokens > 3 && p->name == NULL &&
	sscanf(tokens[0], "%[0-9]-%[0-9]-%[0-9]", sbuf, sbuf, sbuf) == 3 &&
    /* 04-05-70 */
	sscanf(tokens[1], "%[0-9]:%[0-9]%[AaPp]%[Mm]", sbuf, sbuf, sbuf, sbuf) == 4) {
	/* 09:33PM */
	if (!strcasecmp(tokens[2], "<dir>")) {
	    p->type = 'd';
	} else {
	    p->type = '-';
	    p->size = atoi(tokens[2]);
	}
	sprintf(sbuf, "%s %s", tokens[0], tokens[1]);
	p->date = xstrdup(sbuf);
	p->name = xstrdup(tokens[3]);
    }
    /* Try EPLF format; carson@lehman.com */
    if (p->name == NULL && buf[0] == '+') {
	ct = buf + 1;
	p->type = 0;
	while (ct && *ct) {
	    switch (*ct) {
	    case '\t':
		sscanf(ct + 1, "%[^,]", sbuf);
		p->name = xstrdup(sbuf);
		break;
	    case 's':
		sscanf(ct + 1, "%d", &(p->size));
		break;
	    case 'm':
		sscanf(ct + 1, "%d", &i);
		p->date = xstrdup(ctime((time_t *) & i));
		*(strstr(p->date, "\n")) = '\0';
		break;
	    case '/':
		p->type = 'd';
		break;
	    case 'r':
		p->type = '-';
		break;
	    case 'i':
		break;
	    default:
		break;
	    }
	    ct = strstr(ct, ",");
	    if (ct) {
		ct++;
	    }
	}
	if (p->type == 0) {
	    p->type = '-';
	}
    }
    for (i = 0; i < n_tokens; i++)
	xfree(tokens[i]);
    if (p->name == NULL) {
	xfree(p->date);
	xfree(p);
	p = NULL;
    }
    return p;
}

static const char *
dots_fill(size_t len)
{
    static char buf[256];
    int i = 0;

    if ((int) len > o_list_width) {
	memset(buf, ' ', 256);
	buf[0] = '\n';
	buf[o_list_width + 4] = '\0';
	return buf;
    }
    for (i = (int) len; i < o_list_width; i++)
	buf[i - len] = (i % 2) ? '.' : ' ';
    buf[i - len] = '\0';
    return buf;
}

static char *
htmlize_list_entry(const char *line, ftp_request_t * r)
{
    char *link = NULL;
    char *icon = NULL;
    char *html = NULL;
    char *ename = NULL;
    parts_t *parts = NULL;

    link = xmalloc(MIDBUFSIZ);
    icon = xmalloc(MIDBUFSIZ);
    html = xmalloc(BIGBUFSIZ);

    /* check .. as special case */
    if (!strcmp(line, "..")) {
	sprintf(icon, "<IMG BORDER=0 SRC=\"%s%s%s\" ALT=\"%-6s\">",
	    o_iconprefix, "gopher-menu", o_iconsuffix, "[DIR]");
	sprintf(link, "<A HREF=\"%s\">%s</A>",
	    "../",
	    "Parent Directory");
	sprintf(html, "%s %s\n", icon, link);
	xfree(icon);
	xfree(link);
	return (html);
    }
    if ((parts = parse_entry(line)) == NULL) {
	sprintf(html, "%s\n", line);
	return html;
    }
    if (!strcmp(parts->name, ".") || !strcmp(parts->name, "..")) {
	/* sprintf(html, "<!-- %s -->\n", line); */
	*html = '\0';
	return html;
    }
    parts->size += 1023;
    parts->size >>= 10;
    parts->showname = xstrdup(parts->name);
    if ((int) strlen(parts->showname) > o_list_width - 1 && !o_list_wrap) {
	*(parts->showname + o_list_width - 1) = '>';
	*(parts->showname + o_list_width - 0) = '\0';
    }
    ename = xstrdup(rfc1738_escape(parts->name));
    switch (parts->type) {
    case 'd':
	sprintf(icon, "<IMG SRC=\"%sgopher-%s%s\" ALT=\"%-6s\">",
	    o_iconprefix, "menu", o_iconsuffix, "[DIR]");
	sprintf(link, "<A HREF=\"%s/\">%s</A>%s",
	    ename,
	    parts->showname,
	    dots_fill(strlen(parts->showname)));
	sprintf(html, "%s %s  [%s]\n",
	    icon,
	    link,
	    parts->date);
	break;
    case 'l':
	sprintf(icon, "<IMG SRC=\"%sgopher-%s%s\" ALT=\"%-6s\">",
	    o_iconprefix, mime_get_icon(parts->link), o_iconsuffix, "[LINK]");
	sprintf(link, "<A HREF=\"%s\">%s</A>%s",
	    ename,
	    parts->showname,
	    dots_fill(strlen(parts->showname)));
	sprintf(html, "%s %s  [%s]\n",
	    icon,
	    link,
	    parts->date);
	break;
    case '-':
    default:
	sprintf(icon, "<IMG SRC=\"%sgopher-%s%s\" ALT=\"%-6s\">",
	    o_iconprefix, mime_get_icon(parts->name), o_iconsuffix, "[FILE]");
	sprintf(link, "<A HREF=\"%s\">%s</A>%s",
	    ename,
	    parts->showname,
	    dots_fill(strlen(parts->showname)));
	sprintf(html, "%s %s  [%s] %6dk\n",
	    icon,
	    link,
	    parts->date,
	    parts->size);
	break;
    }

    xfree(parts->name);
    xfree(parts->showname);
    xfree(parts->date);
    xfree(parts->link);
    xfree(parts);
    xfree(ename);
    xfree(icon);
    xfree(link);
    return html;		/* html should be freed by caller */
}

static void
try_readme(ftp_request_t * r)
{
    char *t = NULL;
    char *tfname = NULL;
    ftp_request_t *readme = NULL;
    int fd = -1;
    struct stat sb;
    FILE *fp = NULL;

    if ((t = tempnam(NULL, progname)) == NULL)
	return;

    tfname = xstrdup(t);

    if ((fd = open(tfname, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
	xfree(tfname);
	return;
    }
    readme = xcalloc(1, sizeof(ftp_request_t));
    readme->path = xstrdup("README");
    readme->cfd = fd;
    readme->sfd = r->sfd;
    if (is_dfd_open(r)) {
	readme->dfd = r->dfd;
	r->dfd = -1;
    } else {
	readme->dfd = -1;
    }
#ifdef TRY_CWD_FIRST
    readme->state = CWD_FAIL;
#else
    readme->state = SIZE_OK;
#endif
    readme->flags = F_NOERRS;

    process_request(readme);
    if (readme->cfd >= 0) {
	close(readme->cfd);
	readme->cfd = -1;
    }
    if (is_dfd_open(readme)) {
	close_dfd(r);
	r->dfd = readme->dfd;
	readme->dfd = -1;
    }
    fp = fopen(tfname, "r");
    unlink(tfname);

    if (fp) {
	if (fstat(fileno(fp), &sb) < 0 || sb.st_size == 0) {
	    fclose(fp);
	    fp = NULL;
	}
    }
    r->readme_fp = fp;
    xfree(tfname);
    xfree(readme->path);
    xfree(readme);
}



static state_t
htmlify_listing(ftp_request_t * r)
{
    int code;
    static char buf[BIGBUFSIZ];
    char *t = NULL;
    FILE *wfp = NULL;
    time_t stamp;
    int n;
    int x;

    wfp = fdopen(dup(r->cfd), "w");
    setbuf(wfp, NULL);

    stamp = time(NULL);
    fprintf(wfp, "<!-- HTML listing generated by Squid %s -->\n",
	SQUID_VERSION);
    fprintf(wfp, "<!-- %s -->\n", http_time(stamp));
    fprintf(wfp, "<HTML><HEAD><TITLE>\n");
    fprintf(wfp, "FTP Directory: %s\n", r->title_url);
    fprintf(wfp, "</TITLE>\n");
    if (r->flags & F_USEBASE)
	fprintf(wfp, "<BASE HREF=\"%s\">\n", r->url_escaped);
    fprintf(wfp, "</HEAD><BODY>\n");

    if (r->cmd_msg) {		/* There was a message sent with the CWD cmd */
	list_t *l;
	fprintf(wfp, "<PRE>\n");
	for (l = r->cmd_msg; l; l = l->next) {
	    x = write_with_timeout(r->cfd, l->ptr, strlen(l->ptr));
	    r->bytes_written += x;
	}
	fprintf(wfp, "</PRE>\n");
	fprintf(wfp, "<HR>\n");
    } else if (r->readme_fp && r->flags & F_BASEDIR) {
	fprintf(wfp, "<H4>README file from %s</H4>\n", r->title_url);
	fprintf(wfp, "<PRE>\n");
	while (fgets(buf, SMALLBUFSIZ, r->readme_fp))
	    fputs(buf, wfp);
	fclose(r->readme_fp);
	r->readme_fp = NULL;
	fprintf(wfp, "</PRE>\n");
	fprintf(wfp, "<HR>\n");
    }
    fprintf(wfp, "<H2>\n");
    fprintf(wfp, "FTP Directory: %s\n", r->title_url);
    fprintf(wfp, "</H2>\n");
    fprintf(wfp, "<PRE>\n");
    if ((t = htmlize_list_entry("..", r))) {
	fputs(t, wfp);
	xfree(t);
    }
    while ((n = readline_with_timeout(r->dfd, buf, BIGBUFSIZ)) > 0) {
	debug(38, 3, "Input: %s", buf);
	if ((t = strchr(buf, '\r')))
	    *t = '\0';
	if ((t = strchr(buf, '\n')))
	    *t = '\0';
	if (!strncmp(buf, "total", 5))
	    continue;
	if ((t = htmlize_list_entry(buf, r))) {
	    fputs(t, wfp);
	    xfree(t);
	}
    }
    close_dfd(r);
    if (n == READ_TIMEOUT) {
	return ftp_request_timeout(r);
    } else if (n < 0) {
	r->errmsg = xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "read: %s", xstrerror());
	r->rc = 4;
	return FAIL_SOFT;
    }
    fprintf(wfp, "</PRE>\n");
    fprintf(wfp, "<HR>\n");
    if (r->readme_fp) {
	fprintf(wfp, "<H4>README file from %s</H4>\n", r->title_url);
	fprintf(wfp, "<PRE>\n");
	while (fgets(buf, SMALLBUFSIZ, r->readme_fp))
	    fputs(buf, wfp);
	fclose(r->readme_fp);
	fprintf(wfp, "</PRE>\n");
	fprintf(wfp, "<HR>\n");
    }
    fprintf(wfp, "<ADDRESS>\n");
    fprintf(wfp, "Generated %s, by %s/%s@%s\n",
	http_time(stamp), progname, SQUID_VERSION, visible_hostname);
    fprintf(wfp, "</ADDRESS></BODY></HTML>\n");
    fclose(wfp);

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 226)
	    return TRANSFER_DONE;
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static int
process_request(ftp_request_t * r)
{
    if (r == NULL)
	return 1;

    for (;;) {
	debug(38, 3, "process_request: in state %s\n",
	    state_str[r->state]);
	switch (r->state) {
	case BEGIN:
	    r->state = parse_request(r);
	    break;
	case PARSE_OK:
	    r->state = do_connect(r);
	    break;
	case CONNECTED:
	    r->state = read_welcome(r);
	    if ((r->flags & F_HTTPIFY) && (r->flags & F_BASEDIR) && cmd_msg) {
		list_t *t = r->cmd_msg;
		r->cmd_msg = cmd_msg;
		cmd_msg = t;
	    }
	    break;
	case FAIL_CONNECT:
	    r->state = FAIL_SOFT;
	    if (r->conn_att < o_conn_ret) {
		sleep(o_conn_del);
		r->state = PARSE_OK;
	    }
	    break;
	case SERVICE_READY:
	    r->state = do_user(r);
	    break;
	case NEED_PASSWD:
	    r->state = do_passwd(r);
	    break;
	case LOGGED_IN:
	    if ((r->flags & F_HTTPIFY) && (r->flags & F_BASEDIR) && cmd_msg) {
		list_t *t = r->cmd_msg;
		r->cmd_msg = cmd_msg;
		cmd_msg = t;
	    }
	    r->state = do_type(r);
	    break;
	case FAIL_LOGIN:
	    r->state = FAIL_SOFT;
	    if (r->login_att < o_login_ret) {
		sleep(o_login_del);
		r->state = PARSE_OK;
	    }
	    break;
	case TYPE_OK:
	    if (r->flags & F_ISDIR)
		r->state = do_cwd(r);
	    else
		r->state = do_mdtm(r);
	    break;
	case MDTM_OK:
	    r->state = do_size(r);
	    break;
	case SIZE_OK:
#ifdef TRY_CWD_FIRST
	    r->state = do_cwd(r);
#else
	    r->state = do_pasv(r);
#endif
	    break;
	case CWD_OK:
	    if (!(r->flags & F_ISDIR))
		r->flags |= F_USEBASE;
	    r->flags |= F_ISDIR;
	    if (!(r->flags & F_BASEDIR)) {
		/* tack on the trailing slash now that we know its a dir */
		strcat(r->url, "/");
		strcat(r->title_url, "/");
		strcat(r->url_escaped, "/");
	    }
	    if (r->flags & F_HTTPIFY) {
		if (!(r->flags & F_BASEDIR) || cmd_msg) {
		    list_t *t = r->cmd_msg;
		    r->cmd_msg = cmd_msg;
		    cmd_msg = t;
		}
		if (o_readme)
		    try_readme(r);
	    }
	    r->state = do_pasv(r);
	    break;
#ifdef TRY_CWD_FIRST
	case CWD_FAIL:
	    r->state = do_pasv(r);
	    break;
#else
	case RETR_FAIL:
	    r->state = do_cwd(r);
	    break;
#endif
	case PASV_FAIL:
	    /* fallback to PORT */
	    r->state = do_port(r);
	    break;
	case PORT_OK:
	case PASV_OK:
	    r->state = r->flags & F_ISDIR ? do_list(r) : do_rest(r);
	    break;
	case REST_OK:
	    r->state = do_retr(r);
	    break;
	case TRANSFER_BEGIN:
	    if (r->flags & F_HTTPIFY)
		send_success_hdr(r);
	    if (r->flags & F_NEEDACCEPT)
		r->state = do_accept(r);
	    else
		r->state = DATA_TRANSFER;
	    break;
	case DATA_TRANSFER:
	    if ((r->flags & F_HTTPIFY) && (r->flags & F_ISDIR))
		r->state = htmlify_listing(r);
	    else
		r->state = read_data(r);
	    break;
	case TRANSFER_DONE:
	    r->state = DONE;
	    break;
	case DONE:
	    if (r->flags & F_HTTPIFY) {
		debug(38, 7, "Writing Marker to FD %d\n", r->cfd);
		write_with_timeout(r->cfd, MAGIC_MARKER, MAGIC_MARKER_SZ);
	    }
	    return 0;
	    /* NOTREACHED */
	case FAIL_TIMEOUT:
	    r->state = FAIL_SOFT;
	    if (r->rest_att < o_rest_ret && r->rest_implemented) {
		sleep(o_rest_del);
		r->state = PARSE_OK;
	    }
	    break;
	case FAIL_SOFT:
	case FAIL_HARD:
	    fail(r);
	    return (r->rc);
	    /* NOTREACHED */
	default:
	    debug(38, 0, "Nothing to do with state %s\n",
		state_str[r->state]);
	    return (1);
	    /* NOTREACHED */
	}
    }
}

static void
cleanup_path(ftp_request_t * r)
{
    int again;
    int l;
    char *t = NULL;
    char *s = NULL;

    do {
	again = 0;
	l = strlen(r->path);
	/* check for null path */
	if (*r->path == '\0') {
	    t = r->path;
	    r->path = xstrdup(".");
	    r->flags |= F_BASEDIR;
	    xfree(t);
	    again = 1;
	} else if ((l >= 1) && (*(r->path + l - 1) == '/')) {
	    /* remove any trailing slashes from path */
	    *(r->path + l - 1) = '\0';
	    r->flags |= F_ISDIR;
	    r->flags &= ~F_USEBASE;
	    again = 1;
	} else if ((l >= 2) && (!strcmp(r->path + l - 2, "/."))) {
	    /* remove trailing /. */
	    *(r->path + l - 2) = '\0';
	    r->flags |= F_ISDIR;
	    r->flags &= ~F_USEBASE;
	    again = 1;
	} else if (*r->path == '/') {
	    /* remove any leading slashes from path */
	    t = r->path;
	    r->path = xstrdup(t + 1);
	    xfree(t);
	    again = 1;
	} else if (!strncmp(r->path, "./", 2)) {
	    /* remove leading ./ */
	    t = r->path;
	    r->path = xstrdup(t + 2);
	    xfree(t);
	    again = 1;
	} else if ((t = strstr(r->path, "/./"))) {
	    /* remove /./ */
	    s = xstrdup(t + 2);
	    strcpy(t, s);
	    xfree(s);
	    again = 1;
	} else if ((t = strstr(r->path, "//"))) {
	    /* remove // */
	    s = xstrdup(t + 1);
	    strcpy(t, s);
	    xfree(s);
	    again = 1;
	}
    } while (again);
}

#define MAX_ARGS 64
static int
ftpget_srv_mode(char *arg)
{
    /* Accept connections on localhost:port.  For each request,
     * parse into args and exec ftpget. */
    int sock;
    int c;
    fd_set R;
    char *args[MAX_ARGS];
    char *t = NULL;
    int i;
    int n;
    static char buf[BUFSIZ];
    int buflen;
    int flags;

#if HAVE_SETSID
    setsid();			/* become session leader */
#elif HAVE_SETPGRP
    setpgrp(getpid(), 0);
#endif
    sock = 3;
    memset(&R, '\0', sizeof(R));
    for (;;) {
	FD_ZERO(&R);
	FD_SET(0, &R);
	FD_SET(sock, &R);
	if (select(sock + 1, &R, NULL, NULL, NULL) < 0) {
	    if (errno == EWOULDBLOCK)
		continue;
	    if (errno == EAGAIN)
		continue;
	    if (errno == EINTR)
		continue;
	    debug(38, 0, "select: %s\n", xstrerror());
	    return 1;
	}
	if (FD_ISSET(0, &R)) {
	    /* exit server mode if any activity on stdin */
	    close(sock);
	    if (socket_pathname)
		unlink(socket_pathname);
	    return 0;
	}
	if (!FD_ISSET(sock, &R))
	    continue;
	if ((c = accept(sock, NULL, 0)) < 0) {
	    debug(38, 0, "accept: %s\n", xstrerror());
	    if (socket_pathname)
		unlink(socket_pathname);
	    exit(1);
	}
	if (fork()) {
	    /* parent */
	    close(c);
	    continue;
	}
	if ((flags = fcntl(c, F_GETFL, 0)) < 0)
	    debug(38, 0, "fcntl F_GETFL: %s\n", xstrerror());
#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
	flags &= ~O_NONBLOCK;
#else
	flags &= ~O_NDELAY;
#endif
	if (fcntl(c, F_SETFL, flags) < 0)
	    debug(38, 0, "fcntl F_SETFL: %s\n", xstrerror());
	buflen = 0;
	memset(buf, '\0', BUFSIZ);
	do {
	    if ((n = read(c, &buf[buflen], BUFSIZ - buflen - 1)) <= 0) {
		if (n < 0)
		    debug(38, 0, "read: %s\n", xstrerror());
		close(c);
		_exit(1);
	    }
	    buflen += n;
	} while (!strchr(buf, '\n'));
	i = 0;
	t = strtok(buf, w_space);
	while (t && i < MAX_ARGS - 1) {
	    if (strcmp(t, "\"\"") == 0)
		t = "";
	    args[i] = xstrdup(t);
	    /* we used to call rfc1738_escape(args[i]) here */
	    debug(38, 5, "args[%d] = %s\n", i, args[i]);
	    t = strtok(NULL, w_space);
	    i++;
	}
	args[i] = NULL;

	dup2(c, 1);
	close(c);
	execvp(fullprogname, args);
	debug(38, 0, "%s: %s\n", fullprogname, xstrerror());
	_exit(1);
    }
    /* NOTREACHED */
}

static void
usage(int argcount)
{
    fprintf(stderr, "usage: %s options filename host path A,I user pass\n",
	progname);
    if (argcount != 0)
	return;
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-c num[:delay]  Max connect attempts and retry delay\n");
    fprintf(stderr, "\t-l num[:delay]  Max login attempts and retry delay\n");
    fprintf(stderr, "\t-r num[:delay]  Max restart attempts and retry delay\n");
    fprintf(stderr, "\t-t seconds      Idle timeout\n");
    fprintf(stderr, "\t-n seconds      Negative TTL\n");
    fprintf(stderr, "\t-p path         Icon URL prefix\n");
    fprintf(stderr, "\t-s .ext         Icon URL suffix\n");
    fprintf(stderr, "\t-h              Convert to HTTP\n");
    fprintf(stderr, "\t-a              Do not show password in generated URLs\n");
    fprintf(stderr, "\t-A              Do not show login information in generated URLs\n");
    fprintf(stderr, "\t-H hostname     Visible hostname\n");
    fprintf(stderr, "\t-R              DON'T get README file\n");
    fprintf(stderr, "\t-w chars        Filename width in directory listing\n");
    fprintf(stderr, "\t-W              Wrap long filenames\n");
    fprintf(stderr, "\t-C min:max      Min and max port numbers to used for data\n");
    fprintf(stderr, "\t-D dbg          Debug options\n");
    fprintf(stderr, "\t-P port         FTP Port number\n");
    fprintf(stderr, "\t-b              Maximum bytes/sec rate\n");
    fprintf(stderr, "\t-v              Version\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "usage: %s -S\n", progname);
    exit(1);
}

/* return 1 if exceeding our max data rate */

static int
check_data_rate(int size)
{
    double dt;
    int rate;
    if (o_max_bps == 0)
	return 0;
#if GETTIMEOFDAY_NO_TZP
    gettimeofday(&currenttime);
#else
    gettimeofday(&currenttime, NULL);
#endif
    dt = (double) (currenttime.tv_sec - starttime.tv_sec)
	+ (double) (currenttime.tv_usec - starttime.tv_usec) / 1000000;
    rate = (int) ((double) size / dt);
    return rate > o_max_bps ? 1 : 0;
}

time_t
getCurrentTime(void)
{
#if GETTIMEOFDAY_NO_TZP
    gettimeofday(&current_time);
#else
    gettimeofday(&current_time, NULL);
#endif
    return squid_curtime = current_time.tv_sec;
}


int
main(int argc, char *argv[])
{
    ftp_request_t *r = NULL;
    char *t = NULL;
    int rc;
    int i;
    int len;
    int j, k;
    u_short port = FTP_PORT;
    const char *debug_args = "ALL,1";
    extern char *optarg;
    unsigned long ip;
    const struct hostent *hp = NULL;
    int c;

    inaddr_none = inet_addr("255.255.255.255");
    fullprogname = xstrdup(argv[0]);
    if ((t = strrchr(argv[0], '/'))) {
	progname = xstrdup(t + 1);
    } else
	progname = xstrdup(argv[0]);
    if ((t = getenv("SQUID_DEBUG")))
	debug_args = xstrdup(t);
    getCurrentTime();
    starttime = current_time;
    _db_init(NULL, debug_args);


#ifdef NSIG
    for (i = 1; i < NSIG; i++) {
#else
    for (i = 1; i < _sys_nsig; i++) {
#endif
	switch (i) {
	case SIGALRM:
	case SIGINT:
	case SIGHUP:
	case SIGTERM:
	case SIGQUIT:
	    signal(i, generic_sig_handler);
	    break;
	case SIGSEGV:
	case SIGBUS:
	    break;
	case SIGCHLD:
	    signal(i, sigchld_handler);
	    break;
	default:
	    signal(i, SIG_IGN);
	    break;
	}
    }

    strcpy(visible_hostname, getfullhostname());

    while ((c = getopt(argc, argv, "AC:D:G:H:P:RS:Wab:c:hl:n:o:p:r:s:t:vw:")) != -1) {
	switch (c) {
	case 'A':
	    o_showlogin = 0;
	    break;
	case 'C':
	    j = k = 0;
	    sscanf(optarg, "%d:%d", &j, &k);
	    if (j)
		o_conn_min = j;
	    if (k)
		o_conn_max = k;
	    break;
	case 'D':
	    _db_init(NULL, optarg);
	    break;
	case 'G':
	    proxy_host = xstrdup(optarg);
	    break;
	case 'H':
	    strcpy(visible_hostname, optarg);
	    break;
	case 'P':
	    port = atoi(optarg);
	    break;
	case 'R':
	    o_readme = 0;
	    break;
	case 'S':
	    return (ftpget_srv_mode(optarg));
	    /* NOTREACHED */
	case 'W':
	    o_list_wrap = 1;
	    break;
	case 'a':
	    o_showpass = 0;
	    break;
	case 'b':
	    o_max_bps = atoi(optarg);
	    break;
	case 'c':
	    j = k = 0;
	    sscanf(optarg, "%d:%d", &j, &k);
	    if (j)
		o_conn_ret = j;
	    if (k)
		o_conn_del = k;
	    break;
	case 'h':
	    o_httpify = 1;
	    break;
	case 'l':
	    j = k = 0;
	    sscanf(optarg, "%d:%d", &j, &k);
	    if (j)
		o_login_ret = j;
	    if (k)
		o_login_del = k;
	    break;
	case 'n':
	    o_neg_ttl = atoi(optarg);
	    break;
	case 'o':
	    if ((ip = inet_addr(optarg)) != inaddr_none)
		outgoingTcpAddr.s_addr = ip;
	    else if ((hp = gethostbyname(optarg)) != NULL)
		outgoingTcpAddr = *(struct in_addr *) (void *) (hp->h_addr_list[0]);
	    else {
		debug(38, 0, "%s: bad outbound tcp address %s\n", progname, optarg);
		exit(1);
	    }
	    break;
	case 'p':
	    o_iconprefix = xstrdup(optarg);
	    break;
	case 's':
	    o_iconsuffix = xstrdup(optarg);
	    break;
	case 't':
	    o_timeout = atoi(optarg);
	    break;
	case 'r':
	    j = k = 0;
	    sscanf(optarg, "%d:%d", &j, &k);
	    if (j)
		o_rest_ret = j;
	    if (k)
		o_rest_del = k;
	    break;
	case 'v':
	    printf("%s version %s\n", progname, SQUID_VERSION);
	    exit(0);
	case 'w':
	    o_list_width = atoi(optarg);
	    break;
	default:
	    usage(argc);
	    exit(1);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc != 6) {
	fprintf(stderr, "Wrong number of arguments left (%d)\n", argc);
	usage(argc);
    }
    r = xcalloc(1, sizeof(ftp_request_t));

    if (strcmp(argv[0], "-") == 0) {
	r->cfd = 1;
    } else if ((r->cfd = open(argv[0], O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
	perror(argv[0]);
	exit(1);
    }
    r->host = xstrdup(argv[1]);
    r->path = xstrdup(argv[2]);
    r->type = xstrdup(argv[3]);
    r->user = xstrdup(argv[4]);
    r->pass = xstrdup(argv[5]);
    r->port = port;
    r->sfd = -1;
    r->dfd = -1;
    r->size = -1;
    r->state = BEGIN;
    r->flags |= o_httpify ? F_HTTPIFY : 0;
    r->flags |= F_TRYDIR;
    r->flags |= F_USEBASE;
    r->rest_implemented = 1;

    if (*(r->type) != 'A' && *(r->type) != 'I') {
	debug(38, 0, "ftpget: Invalid transfer type: %s\n", r->type);
	usage(argc);
    }
    cleanup_path(r);
    rfc1738_unescape(r->host);
    rfc1738_unescape(r->path);
    rfc1738_unescape(r->user);
    rfc1738_unescape(r->pass);

    len = 15 + strlen(r->user) + strlen(r->pass) + strlen(r->host)
	+ strlen(r->path);
    r->url = xmalloc(len);
    r->title_url = xmalloc(len);

    *r->url = '\0';
    strcat(r->url, "ftp://");
    if (strcmp(r->user, "anonymous")) {
	if (o_showlogin) {
	    strcat(r->url, r->user);
	    if (o_showpass) {
		strcat(r->url, ":");
		strcat(r->url, r->pass);
	    }
	}
	strcat(r->url, "@");
    }
    strcat(r->url, r->host);
    if (r->port != FTP_PORT)
	sprintf(&r->url[strlen(r->url)], ":%d", r->port);
    strcat(r->url, "/");
    if (!(r->flags & F_BASEDIR))
	strcat(r->url, r->path);

    *r->title_url = '\0';
    strcat(r->title_url, "ftp://");
    if (strcmp(r->user, "anonymous")) {
	strcat(r->title_url, r->user);
	strcat(r->title_url, "@");
    }
    strcat(r->title_url, r->host);
    if (r->port != FTP_PORT)
	sprintf(&r->title_url[strlen(r->title_url)], ":%d", r->port);
    strcat(r->title_url, "/");
    if (!(r->flags & F_BASEDIR))
	strcat(r->title_url, r->path);

    /* Make a copy of the escaped URL with some room to grow at the end */
    t = rfc1738_escape(r->url);
    r->url_escaped = xmalloc(strlen(t) + 10);
    strcpy(r->url_escaped, t);

    rc = process_request(MainRequest = r);
    if (r->sfd >= 0)
	send_cmd(r->sfd, "QUIT");
    if (r->sfd >= 0)
	close(r->sfd);
    if (r->cfd >= 0)
	close(r->cfd);
    close_dfd(r);
    close(0);
    close(1);
    exit(rc);
    /* NOTREACHED */
}
