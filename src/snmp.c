/*
 * $Id$
 *
 * DEBUG: section 49    SNMP support
 * AUTHOR: Kostas Anagnostakis
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

#include "squid.h"

#include "mib.h"
#include "snmp.h"
#include "snmp_oidlist.h"
#include "cache_snmp.h"

#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5
int snmp_intoobigs, snmp_inbadcommunitynames;
int snmp_inbadversions, snmp_intotalreqvars;
int snmp_insetrequests;
int snmp_inasnparseerrors, snmp_inbadvalues;
int snmp_ingetrequests, snmp_ingetnexts, snmp_ingenerrs;
void *users, *communities;

static struct sockaddr_in local_snmpd;
static snmp_init_config = 0;

void snmpFwd_insertPending(struct sockaddr_in *, long);
int snmpFwd_removePending(struct sockaddr_in *, long);
extern int init_agent_auth();
extern void snmp_agent_parse(snmp_request_t *);

extern int default_auth();
extern void init_modules();
extern void (*snmplib_debug_hook) (int, char *);
static void snmpSnmplibDebug(int lvl, char *buf);

struct snmpUdpData {
    struct sockaddr_in address;
    void *msg;
    int len;
    struct snmpUdpData *next;
};

typedef struct snmpUdpData snmpUdpData;

struct snmpFwdQueue {
    struct sockaddr_in addr;
    long req_id;
    time_t req_time;
    struct snmpFwdQueue *next;
};

struct snmpFwdQueue *snmpHead = NULL;

struct snmpUdpData *snmpUdpHead = NULL;
struct snmpUdpData *snmpUdpTail = NULL;

#ifdef USE_ICMP
extern hash_table *addr_table;
#endif
void snmpUdpReply(int, void *);
void snmpAppendUdp(snmpUdpData *);
void snmpUdpSend(int, const struct sockaddr_in *, void *, int);

/* now include mib location definitions
 * and magic numbers */

#include "cache_snmp.h"


static void
snmpSnmplibDebug(int lvl, char *buf)
{
    debug(49, lvl) ("%s", buf);
}

void
snmpHandleUdp(int sock, void *not_used)
{
    struct sockaddr_in from;
    int from_len;
    LOCAL_ARRAY(char, buf, SNMP_REQUEST_SIZE);
    LOCAL_ARRAY(char, deb_line, 4096);
    int len;
    snmp_request_t *snmp_rq;

    debug(49, 5) ("snmpHandleUdp: Called.\n");
    commSetSelect(sock, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);
    from_len = sizeof(struct sockaddr_in);
    memset(&from, '\0', from_len);
    len = recvfrom(sock,
	buf,
	SNMP_REQUEST_SIZE,
	0,
	(struct sockaddr *) &from,
	&from_len);
    if (len < 0) {
#ifdef _SQUID_LINUX_
	/* Some Linux systems seem to set the FD for reading and then
	 * return ECONNREFUSED when sendto() fails and generates an ICMP
	 * port unreachable message. */
	/* or maybe an EHOSTUNREACH "No route to host" message */
	if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif
	    debug(49, 1) ("snmpHandleUdp: FD %d recvfrom: %s\n",
		sock, xstrerror());
	return;
    }
    if (snmp_dump_packet) {
	int count;
	debug(49, 6) ("received %d bytes from %s:\n", (int) len,
	    inet_ntoa(from.sin_addr));
	for (count = 0; count < len; count++) {
	    snprintf(deb_line, 4096, "%s %02X ", deb_line, (u_char) buf[count]);
	    if ((count % 16) == 15 || count == (len - 1)) {
		debug(49, 7) ("snmp in: %s\n", deb_line);
		deb_line[0] = '\0';
	    }
	}
    }
    buf[len] = '\0';
    debug(49, 3) ("snmpHandleUdp: FD %d: received %d bytes from %s.\n",
	sock,
	len,
	inet_ntoa(from.sin_addr));

    snmp_rq = xcalloc(1, sizeof(snmp_request_t));
    snmp_rq->buf = (u_char *) buf;
    snmp_rq->len = len;
    snmp_rq->sock = sock;
    snmp_rq->outbuf = xmalloc(snmp_rq->outlen = SNMP_REQUEST_SIZE);
    memcpy(&snmp_rq->from, &from, sizeof(struct sockaddr_in));
    snmp_agent_parse(snmp_rq);
}

void
snmp_agent_parse_done(int errstat, snmp_request_t * snmp_rq)
{
    LOCAL_ARRAY(char, deb_line, 4096);
    int sock = snmp_rq->sock;
    long this_reqid = snmp_rq->reqid;
    debug(49, 2) ("snmp_agent_parse_done: errstat=%d, reqid=%d _t=%x\n",
	errstat, this_reqid, snmp_rq);

    if (memcmp(&snmp_rq->from, &local_snmpd, sizeof(struct sockaddr_in)) == 0) {
	/* look it up */
	if (snmpFwd_removePending(&snmp_rq->from, this_reqid)) {	/* failed */
	    debug(49, 2) ("snmp: bogus response from %s.\n",
		inet_ntoa(snmp_rq->from.sin_addr));
	    if (snmp_rq->community)
		xfree(snmp_rq->community);
	    xfree(snmp_rq->outbuf);
	    xfree(snmp_rq);
	    return;
	}
    }
    switch (errstat) {
    case 2:			/* we might have to forward */
	if (Config.Snmp.localPort != 0) {
	    snmpFwd_insertPending(&snmp_rq->from, this_reqid);
	    snmpUdpSend(sock, &local_snmpd, snmp_rq->outbuf, snmp_rq->outlen);
	    break;
	}
	debug(49, 4) ("snmp: can't forward.\n");
	break;
    case 1:			/* everything is ok */
	debug(49, 5) ("snmp: parsed.\n");
	if (snmp_dump_packet) {
	    int count = 0;
	    debug(49, 5) ("snmp: sent %d bytes to %s\n", (int) snmp_rq->outlen,
		inet_ntoa(snmp_rq->from.sin_addr));
	    for (count = 0; count < snmp_rq->outlen; count++) {
		snprintf(deb_line, 4096, "%s %02X ", deb_line,
		    (u_char) snmp_rq->outbuf[count]);
		if ((count % 16) == 15 || count == (snmp_rq->len - 1)) {
		    debug(49, 7) ("snmp out: %s\n", deb_line);
		    deb_line[0] = '\0';
		}
	    }
	}
	snmpUdpSend(snmp_rq->sock, &snmp_rq->from, snmp_rq->outbuf, snmp_rq->outlen);
	break;
    case 0:
	debug(49, 5) ("snmpagentparsedone failed\n");
	if (snmp_rq->outbuf)
	    xfree(snmp_rq->outbuf);
	break;
    }
    if (snmp_rq->community)
	xfree(snmp_rq->community);
    cbdataFree(snmp_rq);
    return;
}

void
snmpInit(void)
{
    snmp_intoobigs = 0;
    snmp_inbadcommunitynames = 0;
    snmp_inasnparseerrors = 0;
    snmp_inbadvalues = 0;

    assert(NULL != Config.Snmp.mibPath);
    if (!snmpInitConfig())
	debug(49, 0) ("snmpInit: snmpInitConfig() failed.\n");
    snmplib_debug_hook = snmpSnmplibDebug;

}
int
snmpInitConfig()
{
    wordlist *w;
    char *buf;
    char *tokens[10];

    if (snmp_init_config)
	return 1;

    snmp_init_config = 1;
    assert(NULL != Config.Snmp.mibPath);
    if (Mib == NULL) {
	debug(49, 3) ("init_mib: calling with %s\n", Config.Snmp.mibPath);
	init_mib(Config.Snmp.mibPath);
    }
    if (Mib == NULL) {
	debug(49, 0) ("WARNING: Failed to open MIB '%s'\n",
	    Config.Snmp.mibPath);
	return 0;
    }
    /*
     * Process 'snmp_agent_conf' lines
     */
    for (w = Config.Snmp.snmpconf; w != NULL; w = w->next) {
	buf = xstrdup(w->key);
	tokenize(buf, tokens, 10);
	if (0 == strcmp("view", tokens[0])) {
	    if (create_view(tokens) < 0) {
		debug(49, 1) ("snmpInit: error parsing '%s'\n", w->key);
		safe_free(buf);
		return 0;
	    }
	} else if (0 == strcmp("user", tokens[0])) {
	    if (create_user(tokens) < 0) {
		debug(49, 1) ("snmpInit: error parsing '%s'\n", w->key);
		safe_free(buf);
		return 0;
	    }
	} else if (0 == strcmp("community", tokens[0])) {
	    if (create_community(tokens) < 0)
		debug(49, 1) ("snmpInit: error parsing '%s'\n", w->key);
	} else {
	    debug(49, 1) ("snmpInit: error parsing '%s'\n", w->key);
	    safe_free(buf);
	    return 0;
	}
	safe_free(buf);
    }
    if (!Config.Snmp.communities) {
	debug(49, 2) ("snmpInit: WARNING: communities not defined.\n");
    } else
	debug(49, 5) ("snmpInit: communities defined.\n");
    init_agent_auth();
    assert(0 <= default_auth());
    return 1;
}

void
snmpConnectionOpen(void)
{
    u_short port;
    struct in_addr addr;
    struct sockaddr_in xaddr;
    int len;
    int x;

    if ((port = Config.Port.snmp) > (u_short) 0) {
	enter_suid();
	theInSnmpConnection = comm_open(SOCK_DGRAM,
	    0,
	    Config.Addrs.snmp_incoming,
	    port,
	    COMM_NONBLOCKING,
	    "SNMP Port");
	leave_suid();
	if (theInSnmpConnection < 0)
	    fatal("Cannot open snmp Port");
	commSetSelect(theInSnmpConnection, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);
	debug(1, 1) ("Accepting SNMP messages on port %d, FD %d.\n",
	    (int) port, theInSnmpConnection);
	if ((addr = Config.Addrs.udp_outgoing).s_addr != no_addr.s_addr) {
	    enter_suid();
	    theOutSnmpConnection = comm_open(SOCK_DGRAM,
		0,
		addr,
		port,
		COMM_NONBLOCKING,
		"SNMP Port");
	    leave_suid();
	    if (theOutSnmpConnection < 0)
		fatal("Cannot open Outgoing SNMP Port");
	    commSetSelect(theOutSnmpConnection,
		COMM_SELECT_READ,
		snmpHandleUdp,
		NULL, 0);
	    debug(1, 1) ("Outgoing SNMP messages on port %d, FD %d.\n",
		(int) port, theOutSnmpConnection);
	    fd_note(theOutSnmpConnection, "Outgoing SNMP socket");
	    fd_note(theInSnmpConnection, "Incoming SNMP socket");
	} else {
	    theOutSnmpConnection = theInSnmpConnection;
	}
	memset(&theOutSNMPAddr, '\0', sizeof(struct in_addr));
	len = sizeof(struct sockaddr_in);
	memset(&xaddr, '\0', len);
	x = getsockname(theOutSnmpConnection,
	    (struct sockaddr *) &xaddr, &len);
	if (x < 0)
	    debug(51, 1) ("theOutSnmpConnection FD %d: getsockname: %s\n",
		theOutSnmpConnection, xstrerror());
	else {
	    theOutSNMPAddr = xaddr.sin_addr;
	    if (Config.Snmp.localPort != 0) {
		local_snmpd.sin_addr = xaddr.sin_addr;
		local_snmpd.sin_port = Config.Snmp.localPort;
	    }
	}
    }
}

void
snmpFwd_insertPending(struct sockaddr_in *ad, long reqid)
{
    struct snmpFwdQueue *new;

    new = (struct snmpFwdQueue *) xcalloc(1, sizeof(struct snmpFwdQueue));
    xmemcpy(&new->addr, ad, sizeof(struct sockaddr_in));
    new->req_id = reqid;
    new->req_time = squid_curtime;
    if (snmpHead == NULL) {
	new->next = NULL;
	snmpHead = new;
    }
    new->next = snmpHead;
    snmpHead = new;
}

int
snmpFwd_removePending(struct sockaddr_in *fr, long reqid)
{
    struct snmpFwdQueue *p, *prev = NULL;
    for (p = snmpHead; p != NULL; p = p->next, prev = p)
	if (reqid == p->req_id) {
	    xmemcpy(fr, &p->addr, sizeof(struct sockaddr_in));
	    if (p == snmpHead)
		snmpHead = p->next;
	    else if (p->next == NULL)
		prev->next = NULL;
	    debug(49, 3) ("snmpFwd_removePending: freeing %p\n", p);
	    xfree(p);
	    return 0;
	}
    return 1;
}

void
snmpUdpSend(int fd,
    const struct sockaddr_in *to,
    void *msg, int len)
{
    snmpUdpData *data = xcalloc(1, sizeof(snmpUdpData));
    debug(49, 5) ("snmpUdpSend: Queueing response for %s\n",
	inet_ntoa(to->sin_addr));
    data->address = *to;
    data->msg = msg;
    data->len = len;
    snmpAppendUdp(data);
    commSetSelect(fd, COMM_SELECT_WRITE, snmpUdpReply, snmpUdpHead, 0);

}
void
snmpUdpReply(int fd, void *data)
{
    snmpUdpData *queue = data;
    int x;
    /* Disable handler, in case of errors. */
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    while ((queue = snmpUdpHead) != NULL) {
	debug(49, 5) ("snmpUdpReply: FD %d sending %d bytes to %s port %d\n",
	    fd,
	    queue->len,
	    inet_ntoa(queue->address.sin_addr),
	    ntohs(queue->address.sin_port));
	x = comm_udp_sendto(fd,
	    &queue->address,
	    sizeof(struct sockaddr_in),
	    queue->msg,
	    queue->len);
	if (x < 0) {
	    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
		break;		/* don't de-queue */
	}
	snmpUdpHead = queue->next;
	debug(49, 3) ("snmpUdpReply: freeing %p\n", queue->msg);
	safe_free(queue->msg);
	debug(49, 3) ("snmpUdpReply: freeing %p\n", queue);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (snmpUdpHead) {
	commSetSelect(fd, COMM_SELECT_WRITE, snmpUdpReply, snmpUdpHead, 0);
    }
}

void
snmpAppendUdp(snmpUdpData * item)
{
    item->next = NULL;
    if (snmpUdpHead == NULL) {
	snmpUdpHead = item;
	snmpUdpTail = item;
    } else if (snmpUdpTail == snmpUdpHead) {
	snmpUdpTail = item;
	snmpUdpHead->next = item;
    } else {
	snmpUdpTail->next = item;
	snmpUdpTail = item;
    }

}

void
snmpConnectionShutdown(void)
{
    if (theInSnmpConnection < 0)
	return;
    if (theInSnmpConnection != theOutSnmpConnection) {
	debug(49, 1) ("FD %d Closing SNMP socket\n", theInSnmpConnection);
	comm_close(theInSnmpConnection);
    }
    /*
     * Here we set 'theInSnmpConnection' to -1 even though the SNMP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */ theInSnmpConnection = -1;
    /* 
     * Normally we only write to the outgoing SNMP socket, but we
     * also have a read handler there to catch messages sent to that
     * specific interface.  During shutdown, we must disable reading
     * on the outgoing socket.
     */
    assert(theOutSnmpConnection > -1);
    commSetSelect(theOutSnmpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}

void
snmpConnectionClose(void)
{
    snmpConnectionShutdown();
    if (theOutSnmpConnection > -1) {
	debug(49, 1) ("FD %d Closing SNMP socket\n", theOutSnmpConnection);
	comm_close(theOutSnmpConnection);
    }
}
