/* $Id$ */

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


#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>		/* for select(2) */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if HAVE_BSTRING_H
#include <bstring.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "util.h"


char *rfc1738_escape();
char *http_time();

typedef struct _ext_table_entry {
    char *name;
    char *mime_type;
    char *mime_encoding;
    char *icon;
} ext_table_entry;

#include "mime_table.h"

#define FTP_PORT 21
#define DEFAULT_MIME_TYPE "text/plain"
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

typedef struct _request {
    char *host;
    int port;
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
} request_t;

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
int o_conn_ret = 1;		/* connect retries */
int o_login_ret = 1;		/* login retries */
int o_rest_ret = 1;		/* restart retries */
int o_conn_del = 3;		/* connect retry delay */
int o_login_del = 30;		/* login retry delay */
int o_rest_del = 3;		/* restart retry delay */
int o_readme = 1;		/* get README ? */
int o_timeout = XFER_TIMEOUT;	/* data/command timeout, from config.h */
int o_neg_ttl = 300;		/* negative TTL, default 5 min */
int o_httpify = 0;		/* convert to HTTP */
char *o_iconprefix = "internal-";	/* URL prefix for icons */
char *o_iconsuffix = "";	/* URL suffix for icons */
int o_list_width = 32;		/* size of filenames in directory list */
int o_list_wrap = 0;		/* wrap long directory names ? */
int o_conn_min = 0x4000;	/* min. port number to use */
int o_conn_max = 0x3fff + 0x4000;	/* max. port number to use */

#define SMALLBUFSIZ 1024
#define MIDBUFSIZ 2048
#define BIGBUFSIZ 8192
#define READBUFSIZ SMALLBUFSIZ


/*
 *  GLOBALS
 */
char *progname = NULL;
char *fullprogname = NULL;
static char cbuf[SMALLBUFSIZ];	/* send command buffer */
static char htmlbuf[BIGBUFSIZ];
char *server_reply_msg = NULL;
struct sockaddr_in ifc_addr;
static time_t last_alarm_set = 0;
request_t *MainRequest = NULL;

/* This linked list holds the "continuation" lines before the final
 * reply code line is sent for a FTP command */
list_t *cmd_msg = NULL;

static int process_request _PARAMS((request_t *));
static int write_with_timeout _PARAMS((int fd, char *buf, int len));

static char *state_str[] =
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
</HEAD><BODY>\n\
<H2>ERROR: The requested URL could not be retrieved</H2>\n\
<HR>\n\
<P>\n\
While trying to retrieve the URL:\n\
<A HREF=\"%s\">%s</A>\n\
<P>\n\
The following %s error was encountered:\n\
<UL>\n\
<LI><STRONG>%s</STRONG>\n\
</UL>\n\
<P>This means that:\n\
<PRE>\n\
    %s\n\
</PRE>\n\
<P>\n\
\n"

char *html_trailer()
{
    static char buf[SMALLBUFSIZ];

    sprintf(buf, "<HR><ADDRESS>\nGenerated %s, by squid-ftpget/%s@%s\n</ADDRESS>\n </BODY></HTML>\n", http_time((time_t) NULL), SQUID_VERSION, getfullhostname());
    return buf;
}

void fail(r)
     request_t *r;
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
	    log_errno2(__FILE__, __LINE__, "fdopen");
	    exit(1);
	}
	setbuf(fp, NULL);
	htmlbuf[0] = '\0';
	sprintf(htmlbuf, CACHED_RETRIEVE_ERROR_MSG,
	    r->title_url,
	    r->title_url,
	    "FTP",
	    r->errmsg,
	    longmsg);
	if (!(r->flags & F_HDRSENT)) {
	    Debug(26, 1, ("Preparing HTML error message\n"));
	    expire_time = time(NULL) + o_neg_ttl;
	    fprintf(fp, "HTTP/1.0 500 Proxy Error\r\n");
	    fprintf(fp, "Expires: %s\r\n", mkrfc850(&expire_time));
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
	    Debug(26, 9, ("Writing Marker to FD %d\n", r->cfd));
	    write_with_timeout(r->cfd, MAGIC_MARKER, MAGIC_MARKER_SZ);
	}
    } else if (r->errmsg) {
	errorlog("%s\n\t<URL:%s>\n", r->errmsg, r->url);
    }
    xfree(r->errmsg);
}

void generic_sig_handler(sig)
     int sig;
{
    static char buf[SMALLBUFSIZ];

    sprintf(buf, "Received signal %d, exiting.\n", sig);
    errorlog(buf);
    if (MainRequest == NULL)
	exit(1);
    MainRequest->rc = 6;
    MainRequest->errmsg = xstrdup(buf);
    fail(MainRequest);
    exit(MainRequest->rc);
}

state_t request_timeout(r)
     request_t *r;
{
    time_t now;
    static char buf[SMALLBUFSIZ];
    now = time(NULL);
    sprintf(buf, "Timeout after %d seconds.\n",
	(int) (now - last_alarm_set));
    errorlog(buf);
    r->errmsg = xstrdup(buf);
    r->rc = 7;
    return FAIL_TIMEOUT;
}

void sigchld_handler(sig)
     int sig;
{
    int status;
    int pid;

    if ((pid = waitpid(0, &status, WNOHANG)) > 0)
	Debug(26, 5, ("sigchld_handler: Ate pid %d\n", pid));
#if RESET_SIGNAL_HANDLER
    signal(sig, sigchld_handler);
#endif
}

int write_with_timeout(fd, buf, sz)
     int fd;
     char *buf;
     int sz;
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
	FD_SET(fd, &W);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	x = select(fd + 1, &R, &W, NULL, &tv);
	Debug(26, 9, ("write_with_timeout: select returned %d\n", x));
	if (x < 0)
	    return x;
	if (x == 0)		/* timeout */
	    return READ_TIMEOUT;
	if (FD_ISSET(0, &R))
	    exit(1);		/* XXX very ungraceful! */
	x = write(fd, buf, sz);
	Debug(26, 9, ("write_with_timeout: write returned %d\n", x));
	if (x < 0) {
	    log_errno2(__FILE__, __LINE__, "write");
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

int read_with_timeout(fd, buf, sz)
     int fd;
     char *buf;
     int sz;
{
    int x;
    fd_set R;
    struct timeval tv;
    tv.tv_sec = o_timeout;
    tv.tv_usec = 0;
    FD_ZERO(&R);
    FD_SET(fd, &R);
    FD_SET(0, &R);
    last_alarm_set = time(NULL);
    x = select(fd + 1, &R, NULL, NULL, &tv);
    if (x < 0)
	return x;
    if (x == 0)			/* timeout */
	return READ_TIMEOUT;
    if (FD_ISSET(0, &R))
	exit(1);		/* XXX very ungraceful! */
    return read(fd, buf, sz);
}

/* read until newline, sz, or timeout */
int readline_with_timeout(fd, buf, sz)
     int fd;
     char *buf;
     int sz;
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
	if (x < 0)
	    return x;
	if (x == 0)		/* timeout */
	    return READ_TIMEOUT;
	if (FD_ISSET(0, &R))
	    exit(1);		/* XXX very ungraceful! */
	x = read(fd, &c, 1);
	Debug(26, 9, ("readline: x=%d  c='%c'\n", x, c));
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

int connect_with_timeout2(fd, S, len)
     int fd;
     struct sockaddr *S;
     int len;
{
    int x;
    int y;
    fd_set W;
    fd_set R;
    struct timeval tv;
    Debug(26, 9, ("connect_with_timeout2: starting...\n"));
    while (1) {

	y = connect(fd, S, len);
	Debug(26, 9, ("connect returned %d\n", y));
	if (y < 0)
	    Debug(26, 9, ("connect: %s\n", xstrerror()));
	if (y >= 0)
	    return y;
	if (errno == EISCONN)
	    return 0;
	if (errno != EINPROGRESS && errno != EAGAIN)
	    return y;

	/* if we get here, y<0 and errno==EINPROGRESS|EAGAIN */

	tv.tv_sec = o_timeout;
	tv.tv_usec = 0;
	FD_ZERO(&W);
	FD_ZERO(&R);
	FD_SET(fd, &W);
	FD_SET(0, &R);
	last_alarm_set = time(NULL);
	Debug(26, 9, ("selecting on FD %d\n", fd));
	x = select(fd + 1, &R, &W, NULL, &tv);
	Debug(26, 9, ("select returned: %d\n", x));
	if (x == 0)
	    return READ_TIMEOUT;
	if (x < 0)
	    return x;
	if (FD_ISSET(0, &R))
	    exit(1);
    }
}

/* stupid wrapper for so we can set and clear O_NDELAY */
int connect_with_timeout(fd, S, len)
     int fd;
     struct sockaddr *S;
     int len;
{
    int orig_flags;
    int rc;

    orig_flags = fcntl(fd, F_GETFL, 0);
    Debug(26, 9, ("orig_flags = %x\n", orig_flags));
    if (fcntl(fd, F_SETFL, O_NDELAY) < 0)
	log_errno2(__FILE__, __LINE__, "fcntl O_NDELAY");
    rc = connect_with_timeout2(fd, S, len);
    if (fcntl(fd, F_SETFL, orig_flags) < 0)
	log_errno2(__FILE__, __LINE__, "fcntl orig");
    return rc;
}

int accept_with_timeout(fd, S, len)
     int fd;
     struct sockaddr *S;
     int *len;
{
    int x;
    fd_set R;
    struct timeval tv;
    tv.tv_sec = o_timeout;
    tv.tv_usec = 0;
    FD_ZERO(&R);
    FD_SET(fd, &R);
    FD_SET(0, &R);
    last_alarm_set = time(NULL);
    Debug(26, 9, ("selecting on FD %d\n", fd));
    x = select(fd + 1, &R, NULL, NULL, &tv);
    Debug(26, 9, ("select returned: %d\n", x));
    if (x == 0)
	return READ_TIMEOUT;
    if (x < 0)
	return x;
    if (FD_ISSET(0, &R))
	exit(1);
    return accept(fd, S, len);
}



/*
 *  If there are two extensions and both are listed in the types table
 *  then return the leftmost extention type.  The rightmost extention
 *  type becomes the content encoding (eg .gz)
 */
void mime_get_type(r)
     request_t *r;
{
    char *filename = NULL;
    char *ext = NULL;
    char *t = NULL;
    char *type = NULL;
    char *enc = NULL;
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

char *mime_get_icon(name)
     char *name;
{
    char *ext = NULL;
    char *t = NULL;
    int i = 0;

    if (!(t = strrchr(name, '.')))
	return xstrdup("unknown");
    ext = xstrdup(t + 1);
    Debug(26, 1, ("mime_get_icon: ext = '%s'\n", ext));
    for (i = 0; i < EXT_TABLE_LEN; i++) {
	if (!strcmp(ext, ext_mime_table[i].name)) {
	    Debug(26, 1, ("mime_get_icon: matched entry #%d\n", i));
	    Debug(26, 1, ("mime_get_icon: returning '%s'\n",
		    ext_mime_table[i].icon));
	    xfree(ext);
	    return xstrdup(ext_mime_table[i].icon);
	    /* NOTREACHED */
	}
    }
    if (i == EXT_TABLE_LEN) {
	for (i = 0; i < EXT_TABLE_LEN; i++) {
	    if (!strcasecmp(ext, ext_mime_table[i].name)) {
		Debug(26, 1, ("mime_get_icon: matched entry #%d\n", i));
		Debug(26, 1, ("mime_get_icon: returning '%s'\n",
			ext_mime_table[i].icon));
		xfree(ext);
		return xstrdup(ext_mime_table[i].icon);
		/* NOTREACHED */
	    }
	}
    }
    return xstrdup("unknown");
}

char *http_time(t)
     time_t t;
{
    struct tm *gmt;
    time_t when;
    static char tbuf[128];

    when = t ? t : time(NULL);
    gmt = gmtime(&when);
    strftime(tbuf, 128, "%A, %d-%b-%y %H:%M:%S GMT", gmt);
    return tbuf;
}

void send_success_hdr(r)
     request_t *r;
{
    FILE *fp = NULL;

    if (r->flags & F_HDRSENT)
	return;

    r->flags |= F_HDRSENT;

    mime_get_type(r);

    if ((fp = fdopen(dup(r->cfd), "w")) == NULL) {
	log_errno2(__FILE__, __LINE__, "fdopen");
	exit(1);
    }
    setbuf(fp, NULL);
    fprintf(fp, "HTTP/1.0 200 Gatewaying\r\n");
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
int read_reply(fd)
     int fd;
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
	Debug(26, 1, ("read_reply: readline returned %d\n", n));
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
	    l = (list_t *) xmalloc(sizeof(list_t));
	    l->ptr = xstrdup(&buf[4]);
	    l->next = NULL;
	    *Tail = l;
	    Tail = &(l->next);
	}
	if ((t = strchr(buf, '\r')))
	    *t = 0;
	if ((t = strchr(buf, '\n')))
	    *t = 0;
	Debug(26, 1, ("read_reply: %s\n", buf));
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
int send_cmd(fd, buf)
     int fd;
     char *buf;
{
    char *xbuf = NULL;
    int len;
    int x;

    len = strlen(buf) + 2;
    xbuf = (char *) xmalloc(len + 1);
    sprintf(xbuf, "%s\r\n", buf);
    Debug(26, 1, ("send_cmd: %s\n", buf));
    x = write_with_timeout(fd, xbuf, len);
    xfree(xbuf);
    return x;
}


#define ASCII_DIGIT(c) ((c)-48)
time_t parse_iso3307_time(buf)
     char *buf;
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

#ifdef HAVE_TIMEGM
    t = timegm(&tms);
#elif defined(_SQUID_SYSV_) || defined(_SQUID_LINUX_) || defined(_SQUID_HPUX_) || defined(_SQUID_AIX_)
    t = mktime(&tms);
#else
    t = (time_t) 0;
#endif

    Debug(26, 1, ("parse_iso3307_time: %d\n", t));
    return t;
}
#undef ASCII_DIGIT

#define SEND_CBUF \
        if (send_cmd(r->sfd, cbuf) < 0) { \
                r->errmsg = (char *) xmalloc (SMALLBUFSIZ); \
                sprintf(r->errmsg, "Failed to send '%s'", cbuf); \
                r->rc = 4; \
                return FAIL_SOFT; \
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
state_t parse_request(r)
     request_t *r;
{
    Debug(26, 1, ("parse_request: looking up '%s'\n", r->host));
    if (get_host(r->host) == (Host *) NULL) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "Unknown host: %s", r->host);
	r->rc = 10;
	return FAIL_HARD;
    }
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
state_t do_connect(r)
     request_t *r;
{
    Host *h = NULL;
    int sock;
    struct sockaddr_in S;
    int len;
    int x;

    r->conn_att++;
    Debug(26, 1, ("do_connect: connect attempt #%d to '%s'\n",
	    r->conn_att, r->host));
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "socket: %s", xstrerror());
	r->rc = 2;
	return FAIL_CONNECT;
    }
    h = get_host(r->host);
    memcpy(&(S.sin_addr.s_addr), h->ipaddr, h->addrlen);
    S.sin_family = AF_INET;
    S.sin_port = htons(r->port);

    x = connect_with_timeout(sock, (struct sockaddr *) &S, sizeof(S));
    if (x == READ_TIMEOUT) {
	(void) request_timeout(r);
	return FAIL_CONNECT;
    }
    if (x < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
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
	log_errno2(__FILE__, __LINE__, "getsockname");
	exit(1);
    }
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
state_t read_welcome(r)
     request_t *r;
{
    int code;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 220)
	    return SERVICE_READY;
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
state_t do_user(r)
     request_t *r;
{
    int code;

    r->login_att++;

    sprintf(cbuf, "USER %s", r->user);
    SEND_CBUF;

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
state_t do_passwd(r)
     request_t *r;
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

state_t do_type(r)
     request_t *r;
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

state_t do_mdtm(r)
     request_t *r;
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

state_t do_size(r)
     request_t *r;
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

state_t do_port(r)
     request_t *r;
{
    int code;
    int sock;
    struct sockaddr_in S;
    unsigned int naddr;
    int tries = 0;
    int port = 0;
    static int init = 0;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "socket: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    S = ifc_addr;
    S.sin_family = AF_INET;

    if (!init) {
	init = 1;
#if defined(HAVE_SRAND48)
	srand48(time(NULL));
#else
	srand(time(NULL));
#endif
    }
    while (1) {
#if defined(HAVE_LRAND48)
	port = (lrand48() % (o_conn_max - o_conn_min)) + o_conn_min;
#else
	port = (rand() % (o_conn_max - o_conn_min)) + o_conn_min;
#endif
	S.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *) &S, sizeof(S)) >= 0)
	    break;
	if (++tries < 10)
	    continue;
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "bind: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }

    if (listen(sock, 1) < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "listen: %s", xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    naddr = ntohl(ifc_addr.sin_addr.s_addr);
    sprintf(cbuf, "PORT %d,%d,%d,%d,%d,%d",
	(naddr >> 24) & 0xFF,
	(naddr >> 16) & 0xFF,
	(naddr >> 8) & 0xFF,
	naddr & 0xFF,
	(port >> 8) & 0xFF,
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

state_t do_pasv(r)
     request_t *r;
{
    int code;
    int sock;
    struct sockaddr_in S;
    int port = 0;
    int n;
    int h1, h2, h3, h4;
    int p1, p2;
    static char junk[SMALLBUFSIZ];
    static int pasv_supported = 1;

    /* if PASV previously failed, don't even try it again.  Just return
     * PASV_FAIL and let the state machine fall back to using PORT */
    if (!pasv_supported)
	return PASV_FAIL;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
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
    n = sscanf(server_reply_msg, "%[^(](%d,%d,%d,%d,%d,%d)",
	junk, &h1, &h2, &h3, &h4, &p1, &p2);
    if (n != 7) {
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 5;
	pasv_supported = 0;
	return PASV_FAIL;
    }
    sprintf(junk, "%d.%d.%d.%d", h1, h2, h3, h4);
    S.sin_addr.s_addr = inet_addr(junk);
    S.sin_port = htons((p1 << 8) + p2);

    if (connect_with_timeout(sock, (struct sockaddr *) &S, sizeof(S)) < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "%s, port %d: %s", junk, port, xstrerror());
	r->rc = 2;
	return FAIL_SOFT;
    }
    r->dfd = sock;
    return PORT_OK;
}

state_t do_cwd(r)
     request_t *r;
{
    int code;

    if (!strcmp(r->path, "."))
	return CWD_OK;

    sprintf(cbuf, "CWD %s", r->path);
    SEND_CBUF;

    if ((code = read_reply(r->sfd)) > 0) {
	if (code >= 200 && code < 300)
	    return CWD_OK;
#ifdef TRY_CWD_FIRST
	return CWD_FAIL;
#else
	r->errmsg = xstrdup(server_reply_msg);
	r->rc = 10;
	return FAIL_HARD;
#endif
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

state_t do_rest(r)
     request_t *r;
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


state_t do_retr(r)
     request_t *r;
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
	if (r->dfd > 0)
	    close(r->dfd);
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

state_t do_list(r)
     request_t *r;
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

state_t do_accept(r)
     request_t *r;
{
    int sock;
    struct sockaddr S;
    int len;

    len = sizeof(S);
    memset(&S, '\0', len);
    sock = accept_with_timeout(r->dfd, &S, &len);
    if (sock == READ_TIMEOUT)
	return request_timeout(r);
    if (sock < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "accept: %s", xstrerror());
	r->rc = 3;
	return FAIL_SOFT;
    }
    close(r->dfd);
    r->dfd = sock;
    return DATA_TRANSFER;
}

state_t read_data(r)
     request_t *r;
{
    int code;
    int n;
    static char buf[READBUFSIZ];
    int x;

    n = read_with_timeout(r->dfd, buf, READBUFSIZ);
    if (n == READ_TIMEOUT) {
	return request_timeout(r);
    } else if (n < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "read: %s", xstrerror());
	r->rc = 4;
	return FAIL_SOFT;
    } else if (n == 0) {
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
	return request_timeout(r);
    if (x < 0) {
	r->rc = 4;
	return FAIL_SOFT;
    }
    r->rest_offset += n;
    return r->state;
}

static char *Month[] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

int is_month(buf)
     char *buf;
{
    int i;

    for (i = 0; i < 12; i++)
	if (!strcasecmp(buf, Month[i]))
	    return 1;
    return 0;
}

#define MAX_TOKENS 64

parts_t *parse_entry(buf)
     char *buf;
{
    parts_t *p = NULL;
    char *t = NULL;
    char *tokens[MAX_TOKENS];
    int i;
    int n_tokens;
    static char *WS = " \t\n";
    static char sbuf[128];
    char *xbuf = NULL;

    if (buf == NULL)
	return NULL;

    if (*buf == '\0')
	return NULL;

    p = (parts_t *) xmalloc(sizeof(parts_t));
    memset(p, '\0', sizeof(parts_t));

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
	    t += strlen(sbuf);
	    while (strchr(WS, *t))
		t++;
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
	!sscanf(tokens[0], "%[-0-9]", sbuf) &&	/* 04-05-70 */
	!sscanf(tokens[1], "%[0-9:apm]", sbuf)) {	/* 09:33pm */
	if (!strcasecmp(tokens[2], "<dir>")) {
	    p->type = 'd';
	    sprintf(sbuf, "%s %s", tokens[0], tokens[1]);
	    p->date = xstrdup(sbuf);
	    p->name = xstrdup(tokens[3]);
	}
	p->type = '-';
	sprintf(sbuf, "%s %s", tokens[0], tokens[1]);
	p->date = xstrdup(sbuf);
	p->size = atoi(tokens[2]);
	p->name = xstrdup(tokens[3]);
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

char *dots_fill(len)
     size_t len;
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

char *htmlize_list_entry(line, r)
     char *line;
     request_t *r;
{
    char *link = NULL;
    char *icon = NULL;
    char *html = NULL;
    char *ename = NULL;
    parts_t *parts = NULL;

    link = (char *) xmalloc(MIDBUFSIZ);
    icon = (char *) xmalloc(MIDBUFSIZ);
    html = (char *) xmalloc(BIGBUFSIZ);

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

void try_readme(r)
     request_t *r;
{
    char *t = NULL;
    char *tfname = NULL;
    request_t *readme = NULL;
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
    readme = (request_t *) xmalloc(sizeof(request_t));
    memset(readme, '\0', sizeof(request_t));

    readme->path = xstrdup("README");
    readme->cfd = fd;
    readme->sfd = r->sfd;
    readme->dfd = -1;
#ifdef TRY_CWD_FIRST
    readme->state = CWD_FAIL;
#else
    readme->state = SIZE_OK;
#endif
    readme->flags = F_NOERRS;

    process_request(readme);
    if (readme->cfd > 0)
	close(readme->cfd);
    if (readme->dfd > 0)
	close(readme->dfd);

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



state_t htmlify_listing(r)
     request_t *r;
{
    int code;
    static char buf[BIGBUFSIZ];
    char *t = NULL;
    FILE *wfp = NULL;
    time_t stamp;
    int n;

    wfp = fdopen(dup(r->cfd), "w");
    setbuf(wfp, NULL);

    stamp = time(NULL);
    fprintf(wfp, "<!-- HTML listing generated by Squid %s -->\n",
	SQUID_VERSION);
    fprintf(wfp, "<!-- %s -->\n", http_time(stamp));
    fprintf(wfp, "<TITLE>\n");
    fprintf(wfp, "FTP Directory: %s\n", r->title_url);
    fprintf(wfp, "</TITLE>\n");
    if (r->flags & F_USEBASE)
	fprintf(wfp, "<BASE HREF=\"%s\">\n", r->url_escaped);

    if (r->cmd_msg) {		/* There was a message sent with the CWD cmd */
	list_t *l;
	fprintf(wfp, "<PRE>\n");
	for (l = r->cmd_msg; l; l = l->next)
	    write_with_timeout(r->cfd, l->ptr, strlen(l->ptr));
	fprintf(wfp, "</PRE>\n");
	fprintf(wfp, "<HR>\n");
    } else if (r->readme_fp) {
	fprintf(wfp, "<H4>README file from %s</H4>\n", r->title_url);
	fprintf(wfp, "<PRE>\n");
	while (fgets(buf, SMALLBUFSIZ, r->readme_fp))
	    fputs(buf, wfp);
	fclose(r->readme_fp);
	fprintf(wfp, "</PRE>\n");
	fprintf(wfp, "<HR>\n");
    }
    fprintf(wfp, "<H2>\n");
    fprintf(wfp, "FTP Directory: %s\n", r->title_url);
    fprintf(wfp, "</H2>\n");
    fprintf(wfp, "<PRE>\n");
    if (strcmp(r->path, ".")) {
	if ((t = htmlize_list_entry("..", r))) {
	    fputs(t, wfp);
	    xfree(t);
	}
    }
    while ((n = readline_with_timeout(r->dfd, buf, BIGBUFSIZ)) > 0) {
	Debug(26, 1, ("Input: %s", buf));
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
    if (n == READ_TIMEOUT) {
	return request_timeout(r);
    } else if (n < 0) {
	r->errmsg = (char *) xmalloc(SMALLBUFSIZ);
	sprintf(r->errmsg, "read: %s", xstrerror());
	r->rc = 4;
	return FAIL_SOFT;
    }
    fprintf(wfp, "</PRE>\n");
    fprintf(wfp, "<HR>\n");
    fprintf(wfp, "<ADDRESS>\n");
    fprintf(wfp, "Generated %s, by %s/%s@%s\n",
	http_time(stamp), progname, SQUID_VERSION, getfullhostname());
    fprintf(wfp, "</ADDRESS>\n");
    fclose(wfp);

    if ((code = read_reply(r->sfd)) > 0) {
	if (code == 226)
	    return TRANSFER_DONE;
    }
    r->errmsg = xstrdup(server_reply_msg);
    r->rc = code < 0 ? 4 : 5;
    return FAIL_SOFT;
}

static int process_request(r)
     request_t *r;
{
    if (r == (request_t *) NULL)
	return 1;

    while (1) {
	Debug(26, 1, ("process_request: in state %s\n",
		state_str[r->state]));
	switch (r->state) {
	case BEGIN:
	    r->state = parse_request(r);
	    break;
	case PARSE_OK:
	    r->state = do_connect(r);
	    break;
	case CONNECTED:
	    r->state = read_welcome(r);
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
	    r->flags |= F_ISDIR;
	    if (strcmp(r->path, ".")) {
		/* tack on the trailing slash now that we know its a dir */
		strcat(r->url, "/");
		strcat(r->title_url, "/");
		strcat(r->url_escaped, "/");
		if (*(r->path + strlen(r->path) - 1) != '/')
		    r->flags |= F_USEBASE;
	    } else {
		/* We must do this only because Netscape's browser is broken */
		r->flags |= F_USEBASE;
	    }
	    if (r->flags & F_HTTPIFY) {
		if (cmd_msg) {
		    r->cmd_msg = cmd_msg;
		    cmd_msg = NULL;
		} else {
		    if (o_readme)
			try_readme(r);
		}
	    }
	    r->state = do_pasv(r);
	    break;
#ifdef TRY_CWD_FIRST
	case CWD_FAIL:
	    r->flags &= ~F_ISDIR;
	    r->state = do_pasv(r);
	    break;
#else
	case RETR_FAIL:
	    r->flags |= F_ISDIR;
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
		Debug(26, 9, ("Writing Marker to FD %d\n", r->cfd));
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
	case FAIL_HARD:
	case FAIL_SOFT:
	    fail(r);
	    return (r->rc);
	    /* NOTREACHED */
	default:
	    errorlog("Nothing to do with state %s\n",
		state_str[r->state]);
	    return (1);
	    /* NOTREACHED */
	}
    }
}

void cleanup_path(r)
     request_t *r;
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
	    xfree(t);
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
	} else if (*(r->path + l - 1) == '/') {
	    /* remove any trailing slashes from path */
	    *(r->path + l - 1) = '\0';
	    again = 1;
	} else if (!strcmp(r->path + l - 2, "/.")) {
	    /* remove trailing /. */
	    *(r->path + l - 2) = '\0';
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
int ftpget_srv_mode(port)
     int port;
{
    /* Accept connections on localhost:port.  For each request,
     * parse into args and exec ftpget. */
    int sock;
    int c;
    struct sockaddr_in S;
    fd_set R;
    char *args[MAX_ARGS];
    char *t = NULL;
    int i;
    int n;
    static char *w_space = " \t\n\r";
    static char buf[BUFSIZ];
    int buflen;

    setsid();			/* become session leader */

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	log_errno2(__FILE__, __LINE__, "socket");
	exit(1);
    }
    if (fcntl(sock, F_SETFD, 1) < 0) {
	Debug(26, 0, ("ftpget_srv_mode: FD %d: failed to set close-on-exec flag: %s\n",
		sock, xstrerror()));
    }
    i = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &i, sizeof(int));
    memset((char *) &S, '\0', sizeof(S));
    S.sin_addr.s_addr = inet_addr("127.0.0.1");
    S.sin_port = htons(port);
    S.sin_family = AF_INET;
    Debug(26, 1, ("Binding to %s, port %d\n",
	    inet_ntoa(S.sin_addr),
	    ntohs(S.sin_port)));
    if (bind(sock, (struct sockaddr *) &S, sizeof(S)) < 0) {
	log_errno2(__FILE__, __LINE__, "bind");
	sleep(5);	/* sleep here so that the cache will restart us */
	exit(1);
    }
    if (listen(sock, 50) < 0) {
	log_errno2(__FILE__, __LINE__, "listen");
	exit(1);
    }
    while (1) {
	FD_ZERO(&R);
	FD_SET(0, &R);
	FD_SET(sock, &R);
	if (select(sock + 1, &R, NULL, NULL, NULL) < 0) {
	    if (errno == EINTR)
		continue;
	    log_errno2(__FILE__, __LINE__, "select");
	    continue;
	}
	if (FD_ISSET(0, &R)) {
	    /* exit server mode if any activity on stdin */
	    close(sock);
	    return 0;
	}
	if (!FD_ISSET(sock, &R))
	    continue;
	if ((c = accept(sock, NULL, 0)) < 0) {
	    log_errno2(__FILE__, __LINE__, "accept");
	    exit(1);
	}
	if (fork()) {
	    /* parent */
	    close(c);
	    continue;
	}
	buflen = 0;
	memset(buf, '\0', BUFSIZ);
	do {
	    if ((n = read(c, &buf[buflen], BUFSIZ - buflen - 1)) <= 0) {
		log_errno2(__FILE__, __LINE__, "read");
		close(c);
		_exit(1);
	    }
	    buflen += n;
	} while (!strchr(buf, '\n'));
	i = 0;
	t = strtok(buf, w_space);
	while (t && i < MAX_ARGS - 1) {
	    args[i] = xstrdup(t);
	    Debug(26, 5, ("args[%d] = %s\n", i, args[i]));
	    t = strtok(NULL, w_space);
	    i++;
	}
	args[i] = NULL;

	dup2(c, 1);
	close(c);
	execvp(fullprogname, args);
	log_errno2(__FILE__, __LINE__, fullprogname);
	_exit(1);
    }
    return 1;
}

void usage(argcount)
     int argcount;
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
    fprintf(stderr, "\t-R              DON'T get README file\n");
    fprintf(stderr, "\t-w chars        Filename width in directory listing\n");
    fprintf(stderr, "\t-W              Wrap long filenames\n");
    fprintf(stderr, "\t-C min:max      Min and max port numbers to used for data\n");
    fprintf(stderr, "\t-Ddbg           Debug options\n");
    fprintf(stderr, "\t-P port         FTP Port number\n");
    fprintf(stderr, "\t-v              Version\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "usage: %s -S port\n", progname);
    exit(1);
}


int main(argc, argv)
     int argc;
     char *argv[];
{
    request_t *r = NULL;
    char *t = NULL;
    int rc;
    int i;
    int len;
    int j, k;
    int port = FTP_PORT;

    fullprogname = xstrdup(argv[0]);
    if ((t = strrchr(argv[0], '/'))) {
	progname = xstrdup(t + 1);
    } else
	progname = xstrdup(argv[0]);
    init_log3(progname, stderr, stderr);
    debug_init();

#ifdef NSIG
    for (i = 0; i < NSIG; i++) {
#else
    for (i = 0; i < _sys_nsig; i++) {
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

    for (argc--, argv++; argc > 0 && **argv == '-'; argc--, argv++) {
	Debug(26, 9, ("processing arg '%s'\n", *argv));
	if (!strcmp(*argv, "-"))
	    break;
	if (!strncmp(*argv, "-D", 2)) {
	    debug_flag(*argv);
	    continue;
	} else if (!strcmp(*argv, "-htmlify") || !strcmp(*argv, "-httpify") ||
	    !strcmp(*argv, "-h")) {
	    o_httpify = 1;
	    continue;
	} else if (!strcmp(*argv, "-S")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = atoi(*argv);
	    Debug(26, 1, ("argv=%s j=%d\n", *argv, j));
	    if (j > 0)
		return (ftpget_srv_mode(j));
	    usage(argc);
	} else if (!strcmp(*argv, "-t")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = atoi(*argv);
	    if (j > 0)
		o_timeout = j;
	    continue;
	} else if (!strcmp(*argv, "-w")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = atoi(*argv);
	    if (j > 0)
		o_list_width = j;
	    continue;
	} else if (!strcmp(*argv, "-n")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = atoi(*argv);
	    if (j > 0)
		o_neg_ttl = j;
	    continue;
	} else if (!strcmp(*argv, "-p")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    o_iconprefix = xstrdup(*argv);
	    continue;
	} else if (!strcmp(*argv, "-s")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    o_iconsuffix = xstrdup(*argv);
	    continue;
	} else if (!strcmp(*argv, "-c")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = k = 0;
	    sscanf(*argv, "%d:%d", &j, &k);
	    if (j)
		o_conn_ret = j;
	    if (k)
		o_conn_del = k;
	    continue;
	} else if (!strcmp(*argv, "-l")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = k = 0;
	    sscanf(*argv, "%d:%d", &j, &k);
	    if (j)
		o_login_ret = j;
	    if (k)
		o_login_del = k;
	    continue;
	} else if (!strcmp(*argv, "-r")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = k = 0;
	    sscanf(*argv, "%d:%d", &j, &k);
	    if (j)
		o_rest_ret = j;
	    if (k)
		o_rest_del = k;
	    continue;
	} else if (!strcmp(*argv, "-C")) {
	    if (--argc < 1)
		usage();
	    argv++;
	    j = k = 0;
	    sscanf(*argv, "%d:%d", &j, &k);
	    if (j)
		o_conn_min = j;
	    if (k)
		o_conn_max = k;
	    continue;
	} else if (!strcmp(*argv, "-R")) {
	    o_readme = 0;
	} else if (!strcmp(*argv, "-W")) {
	    o_list_wrap = 1;
	} else if (!strcmp(*argv, "-P")) {
	    if (--argc < 1)
		usage(argc);
	    argv++;
	    j = atoi(*argv);
	    if (j > 0)
		port = j;
	    continue;
	} else if (!strcmp(*argv, "-v")) {
	    printf("%s version %s\n", progname, SQUID_VERSION);
	    exit(0);
	} else {
	    usage(argc);
	    exit(1);
	}
    }

    if (argc != 6) {
	fprintf(stderr, "Wrong number of arguments left (%d)\n", argc);
	usage(argc);
    }
    r = (request_t *) xmalloc(sizeof(request_t));
    memset(r, '\0', sizeof(request_t));

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
    r->rest_implemented = 1;

    if (*(r->type) != 'A' && *(r->type) != 'I') {
	errorlog("Invalid transfer type: %s\n", r->type);
	usage(argc);
    }
    cleanup_path(r);

    len = 15 + strlen(r->user) + strlen(r->pass) + strlen(r->host)
	+ strlen(r->path);
    r->url = (char *) xmalloc(len);
    r->title_url = (char *) xmalloc(len);

    *r->url = '\0';
    strcat(r->url, "ftp://");
    if (strcmp(r->user, "anonymous")) {
	strcat(r->url, r->user);
	strcat(r->url, ":");
	strcat(r->url, r->pass);
	strcat(r->url, "@");
    }
    strcat(r->url, r->host);
    strcat(r->url, "/");
    if (strcmp(r->path, "."))
	strcat(r->url, r->path);

    *r->title_url = '\0';
    strcat(r->title_url, "ftp://");
    if (strcmp(r->user, "anonymous")) {
	strcat(r->title_url, r->user);
	strcat(r->title_url, "@");
    }
    strcat(r->title_url, r->host);
    strcat(r->title_url, "/");
    if (strcmp(r->path, "."))
	strcat(r->title_url, r->path);

    /* Make a copy of the escaped URL with some room to grow at the end */
    t = rfc1738_escape(r->url);
    r->url_escaped = (char *) xmalloc(strlen(t) + 10);
    strcpy(r->url_escaped, t);

    rc = process_request(MainRequest = r);
    if (r->sfd > 0)
	send_cmd(r->sfd, "QUIT");
    if (r->sfd > 0)
	close(r->sfd);
    if (r->cfd > 0)
	close(r->cfd);
    if (r->dfd > 0)
	close(r->dfd);
    close(0);
    close(1);
    exit(rc);
    /* NOTREACHED */
}
