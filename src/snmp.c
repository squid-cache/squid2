
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

#ifdef SQUID_SNMP

#include "squid.h"
#include "mib_module.h"


#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5
int snmp_intoobigs, snmp_inbadcommunitynames;
int snmp_inbadversions, snmp_intotalreqvars;
int snmp_insetrequests;
int snmp_inasnparseerrors, snmp_inbadvalues;
int snmp_ingetrequests, snmp_ingetnexts, snmp_ingenerrs;
void *users, *communities;

static struct sockaddr_in local_snmpd;

void snmpFwd_insertPending(struct sockaddr_in *, long);
int snmpFwd_removePending(struct sockaddr_in *, long);
extern int init_agent_auth();
extern int memoryAccounted();
extern int snmp_agent_parse(char *, int, char *, int *, u_long, long *);
extern int read_config();
extern void read_main_config_file();
char *snmp_configfile;
extern void init_modules();
static SNMPFV var_cnf;
static SNMPFV var_peertbl;

static int snmp_dump_packet;

int main_config_read = 0;

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

/* mib stuff here */

struct subtree {
    oid name[16];		/* objid prefix of subtree */
    u_char namelen;		/* number of subid's in name above */
    struct variable *variables;	/* pointer to variables array */
    int variables_len;		/* number of entries in above array */
    int variables_width;	/* sizeof each variable entry */
    struct subtree *next;
};

#if 1
#define variable2 variable
#define variable4 variable
#define variable5 variable
#define variable7 variable
#define variable13 variable
#else
/**
 * This is a new variable structure that doesn't have as much memory
 * tied up in the object identifier.  It's elements have also been re-arranged
 * so that the name field can be variable length.  Any number of these
 * structures can be created with lengths tailor made to a particular
 * application.  The first 5 elements of the structure must remain constant.
 */
struct variable2 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[2];		/* object identifier of variable */
};

struct variable4 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[4];		/* object identifier of variable */
};

struct variable7 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[7];		/* object identifier of variable */
};

struct variable13 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[13];		/* object identifier of variable */
};

#endif



/* MIB definitions
 * We start from the SQUIDMIB as the root of the subtree
 *
 * we are under : iso.org.dod.internet.experimental.nsfnet.squid
 *
 */


#define SQUIDMIB 1, 3, 6, 1, 3, 25, 17


/* basic groups under .squid */

#define SQ_SYS SQUIDMIB, 1
#define SQ_CONF SQUIDMIB, 2
#define SQ_PRF SQUIDMIB, 3
#define SQ_ACC SQUIDMIB, 6
#define SQ_SEC SQUIDMIB, 5
#define SQ_NET SQUIDMIB, 4

/* cacheSystem group */

enum {
    SYSVMSIZ,
    SYSSTOR
};

/* cacheConfig group */

enum {
    CONF_ADMIN,
    CONF_UPTIME,
    CONF_ST_MMAXSZ,
    CONF_ST_MHIWM,
    CONF_ST_MLOWM,
    CONF_ST_SWMAXSZ,
    CONF_ST_SWHIWM,
    CONF_ST_SWLOWM,
    CONF_WAIS_RHOST,
    CONF_WAIS_RPORT,
    CONF_TIO_RD,
    CONF_TIO_CON,
    CONF_TIO_REQ,
    CONF_LOG_LVL,
    CONF_PTBL_ID,
    CONF_PTBL_NAME,
    CONF_PTBL_IP,
    CONF_PTBL_HTTP,
    CONF_PTBL_ICP,
    CONF_PTBL_TYPE,
    CONF_PTBL_STATE
};


/* cacheNetwork group */

enum {
    NETDB_ID,
    NETDB_NET,
    NETDB_PING_S,
    NETDB_PING_R,
    NETDB_HOPS,
    NETDB_RTT,
    NETDB_PINGTIME,
    NETDB_LASTUSE,
    NETDB_LINKCOUNT,
    NET_IPC_ID,
    NET_IPC_NAME,
    NET_IPC_IP,
    NET_IPC_STATE,
    NET_FQDN_ID,
    NET_FQDN_NAME,
    NET_FQDN_IP,
    NET_FQDN_LASTREF,
    NET_FQDN_EXPIRES,
    NET_FQDN_STATE,
    NET_TCPCONNS,
    NET_UDPCONNS,
    NET_INTHRPUT,
    NET_OUTHRPUT
};

/* cachePerf group */

enum {
    PERF_SYS_PF,
    PERF_SYS_NUMR,
    PERF_SYS_DEFR,
    PERF_SYS_MEMUSAGE,
    PERF_SYS_CPUUSAGE,
    PERF_SYS_MAXRESSZ,
    PERF_SYS_CURMEMSZ,
    PERF_SYS_CURLRUEXP,
    PERF_SYS_CURUNLREQ,
    PERF_SYS_CURUNUSED_FD,
    PERF_SYS_CURRESERVED_FD,
    PERF_SYS_NUMOBJCNT,
    PERF_PROTOSTAT_ID,
    PERF_PROTOSTAT_KBMAX,
    PERF_PROTOSTAT_KBMIN,
    PERF_PROTOSTAT_KBAVG,
    PERF_PROTOSTAT_KBNOW,
    PERF_PROTOSTAT_HIT,
    PERF_PROTOSTAT_MISS,
    PERF_PROTOSTAT_REFCOUNT,
    PERF_PROTOSTAT_TRNFRB,
    PERF_PROTOSTAT_AGGR_CLHTTP,
    PERF_PROTOSTAT_AGGR_ICP_S,
    PERF_PROTOSTAT_AGGR_ICP_R,
    PERF_PROTOSTAT_AGGR_CURSWAP,
    PERF_SYS_FD_NUMBER,
    PERF_SYS_FD_TYPE,
    PERF_SYS_FD_TOUT,
    PERF_SYS_FD_NREAD,
    PERF_SYS_FD_NWRITE,
    PERF_SYS_FD_ADDR,
    PERF_SYS_FD_NAME,
    PERF_PEERSTAT_ID,
    PERF_PEERSTAT_SENT,
    PERF_PEERSTAT_PACKED,
    PERF_PEERSTAT_FETCHES,
    PERF_PEERSTAT_RTT,
    PERF_PEERSTAT_IGN,
    PERF_PEERSTAT_KEEPAL_S,
    PERF_PEERSTAT_KEEPAL_R
};

SNMPFV var_cachesys_entry;
SNMPFV var_perfsys_entry;
SNMPFV var_protostat_entry;
SNMPFV var_conf_entry;
SNMPFV var_netdb_entry;
SNMPFV var_ipcache_entry;
SNMPFV var_fqdn_entry;
SNMPFV var_conf_entry;
SNMPFV var_net_vars;
SNMPFV var_aggreg_entry;

struct variable cachesys_vars[] =
{
    {SYSVMSIZ, INTEGER, RONLY, var_cachesys_entry, 1,
	{1}},
    {SYSSTOR, INTEGER, RONLY, var_cachesys_entry, 1,
	{2}}
};

struct variable4 cacheperf_vars[] =
{
    {PERF_SYS_PF, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 1}},
    {PERF_SYS_NUMR, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 2}},
    {PERF_SYS_DEFR, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 3}},
    {PERF_SYS_FD_NUMBER, INTEGER, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 1}},
    {PERF_SYS_FD_TYPE, INTEGER, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 2}},
    {PERF_SYS_FD_TOUT, INTEGER, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 3}},
    {PERF_SYS_FD_NREAD, INTEGER, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 4}},
    {PERF_SYS_FD_NWRITE, INTEGER, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 5}},
    {PERF_SYS_FD_ADDR, IPADDRESS, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 6}},
    {PERF_SYS_FD_NAME, STRING, RONLY, var_perfsys_entry, 4,
	{1, 4, 1, 7}},
    {PERF_SYS_MEMUSAGE, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 5}},
    {PERF_SYS_CPUUSAGE, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 6}},
    {PERF_SYS_MAXRESSZ, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 7}},
    {PERF_SYS_NUMOBJCNT, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 8}},
    {PERF_SYS_CURMEMSZ, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 9}},
    {PERF_SYS_CURLRUEXP, TIMETICKS, RONLY, var_perfsys_entry, 2,
	{1, 10}},
    {PERF_SYS_CURUNLREQ, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 11}},
    {PERF_SYS_CURUNUSED_FD, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 12}},
    {PERF_SYS_CURRESERVED_FD, INTEGER, RONLY, var_perfsys_entry, 2,
	{1, 13}},
    {PERF_PROTOSTAT_ID, INTEGER, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 1}},
    {PERF_PROTOSTAT_KBMAX, INTEGER, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 2}},
    {PERF_PROTOSTAT_KBMIN, COUNTER, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 3}},
    {PERF_PROTOSTAT_KBAVG, GAUGE, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 4}},
    {PERF_PROTOSTAT_KBNOW, COUNTER, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 5}},
    {PERF_PROTOSTAT_HIT, GAUGE, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 6}},
    {PERF_PROTOSTAT_MISS, GAUGE, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 7}},
    {PERF_PROTOSTAT_REFCOUNT, COUNTER, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 8}},
    {PERF_PROTOSTAT_TRNFRB, COUNTER, RONLY, var_protostat_entry, 4,
	{2, 1, 1, 9}},
    {PERF_PROTOSTAT_AGGR_CLHTTP, COUNTER, RONLY, var_aggreg_entry, 3,
	{2, 2, 1}},
    {PERF_PROTOSTAT_AGGR_ICP_S, COUNTER, RONLY, var_aggreg_entry, 3,
	{2, 2, 2}},
    {PERF_PROTOSTAT_AGGR_ICP_R, COUNTER, RONLY, var_aggreg_entry, 3,
	{2, 2, 3}},
    {PERF_PROTOSTAT_AGGR_CURSWAP, COUNTER, RONLY, var_aggreg_entry, 3,
	{2, 2, 4}},
    {PERF_PEERSTAT_ID, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 1}},
    {PERF_PEERSTAT_SENT, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 2}},
    {PERF_PEERSTAT_PACKED, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 3}},
    {PERF_PEERSTAT_FETCHES, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 4}},
    {PERF_PEERSTAT_RTT, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 5}},
    {PERF_PEERSTAT_IGN, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 6}},
    {PERF_PEERSTAT_KEEPAL_S, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 7}},
    {PERF_PEERSTAT_KEEPAL_R, INTEGER, RONLY, var_perfsys_entry, 4,
	{3, 1, 1, 8}}
};

struct variable4 network_variables[] =
{
    {NETDB_ID, INTEGER, RONLY, var_netdb_entry, 2,
	{1, 1}},
    {NETDB_NET, IPADDRESS, RONLY, var_netdb_entry, 2,
	{1, 2}},
    {NETDB_PING_S, INTEGER, RONLY, var_netdb_entry, 2,
	{1, 3}},
    {NETDB_PING_R, INTEGER, RONLY, var_netdb_entry, 2,
	{1, 4}},
    {NETDB_HOPS, INTEGER, RONLY, var_netdb_entry, 2,
	{1, 5}},
    {NETDB_RTT, TIMETICKS, RONLY, var_netdb_entry, 2,
	{1, 6}},
    {NETDB_PINGTIME, TIMETICKS, RONLY, var_netdb_entry, 2,
	{1, 7}},
    {NETDB_LASTUSE, TIMETICKS, RONLY, var_netdb_entry, 2,
	{1, 8}},
    {NET_IPC_ID, INTEGER, RONLY, var_ipcache_entry, 3,
	{2, 1, 1}},
    {NET_IPC_NAME, STRING, RONLY, var_ipcache_entry, 3,
	{2, 1, 2}},
    {NET_IPC_IP, IPADDRESS, RONLY, var_ipcache_entry, 3,
	{2, 1, 3}},
    {NET_IPC_STATE, INTEGER, RONLY, var_ipcache_entry, 3,
	{2, 1, 4}},
    {NET_FQDN_ID, INTEGER, RONLY, var_fqdn_entry, 3,
	{3, 1, 1}},
    {NET_FQDN_NAME, STRING, RONLY, var_fqdn_entry, 3,
	{3, 1, 2}},
    {NET_FQDN_IP, IPADDRESS, RONLY, var_fqdn_entry, 3,
	{3, 1, 3}},
    {NET_FQDN_LASTREF, TIMETICKS, RONLY, var_fqdn_entry, 3,
	{3, 1, 4}},
    {NET_FQDN_EXPIRES, TIMETICKS, RONLY, var_fqdn_entry, 3,
	{3, 1, 5}},
    {NET_FQDN_STATE, INTEGER, RONLY, var_fqdn_entry, 3,
	{3, 1, 6}},
    {NET_TCPCONNS, INTEGER, RONLY, var_net_vars, 1,
	{4}},
    {NET_UDPCONNS, INTEGER, RONLY, var_net_vars, 1,
	{5}},
    {NET_INTHRPUT, INTEGER, RONLY, var_net_vars, 1,
	{6}},
    {NET_OUTHRPUT, INTEGER, RONLY, var_net_vars, 1,
	{7}}
};


struct variable config_variables[] =
{
    {CONF_ADMIN, STRING, RONLY, var_cnf, 1,
	{1}},
    {CONF_UPTIME, TIMETICKS, RONLY, var_cnf, 1,
	{2}},
    {CONF_ST_MMAXSZ, INTEGER, RONLY, var_cnf, 2,
	{3, 1}},
    {CONF_ST_MHIWM, INTEGER, RONLY, var_cnf, 2,
	{3, 2}},
    {CONF_ST_MLOWM, INTEGER, RONLY, var_cnf, 2,
	{3, 3}},
    {CONF_ST_SWMAXSZ, INTEGER, RONLY, var_cnf, 2,
	{3, 4}},
    {CONF_ST_SWHIWM, INTEGER, RONLY, var_cnf, 2,
	{3, 5}},
    {CONF_ST_SWLOWM, INTEGER, RONLY, var_cnf, 2,
	{3, 6}},
    {CONF_WAIS_RHOST, STRING, RONLY, var_cnf, 1,
	{4}},
    {CONF_WAIS_RPORT, INTEGER, RONLY, var_cnf, 1,
	{5}},
    {CONF_TIO_RD, INTEGER, RONLY, var_cnf, 2,
	{6, 1}},
    {CONF_TIO_CON, INTEGER, RONLY, var_cnf, 2,
	{6, 2}},
    {CONF_TIO_REQ, INTEGER, RONLY, var_cnf, 2,
	{6, 3}},
    {CONF_LOG_LVL, STRING, RONLY, var_cnf, 1,
	{7}},
    {CONF_PTBL_ID, INTEGER, RONLY, var_peertbl, 3,
	{8, 1, 1}},
    {CONF_PTBL_NAME, STRING, RONLY, var_peertbl, 3,
	{8, 1, 2}},
    {CONF_PTBL_IP, IPADDRESS, RONLY, var_peertbl, 3,
	{8, 1, 3}},
    {CONF_PTBL_HTTP, INTEGER, RONLY, var_peertbl, 3,
	{8, 1, 4}},
    {CONF_PTBL_ICP, INTEGER, RONLY, var_peertbl, 3,
	{8, 1, 5}},
    {CONF_PTBL_TYPE, INTEGER, RONLY, var_peertbl, 3,
	{8, 1, 6}},
    {CONF_PTBL_STATE, INTEGER, RONLY, var_peertbl, 3,
	{8, 1, 7}}
};

void
snmpHandleUdp(int sock, void *not_used)
{
    struct sockaddr_in from;
    int from_len;
    long this_reqid;
    int errstat;
    LOCAL_ARRAY(char, buf, SNMP_REQUEST_SIZE);
    char *outbuf;
    LOCAL_ARRAY(char, deb_line, 4096);
    int len;
    int outlen = SNMP_REQUEST_SIZE;
    snmp_dump_packet = 1;
    debug(49, 5) ("snmpHandleUdp: Initialized.\n");
    commSetSelect(sock, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);
    debug(49, 5) ("snmpHandleUdp: got past select\n");
    from_len = sizeof(from);
    memset(&from, '\0', from_len);
    len = recvfrom(sock,
	buf,
	SQUID_UDP_SO_RCVBUF - 1,
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
	    debug(51, 1) ("snmpHandleUdp: FD %d recvfrom: %s\n",
		sock, xstrerror());
	return;
    }
    if (snmp_dump_packet) {
	int count;
	debug(49, 5) ("received %d bytes from %s:\n", (int) len,
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
    debug(49, 4) ("snmpHandleUdp: FD %d: received %d bytes from %s.\n",
	sock,
	len,
	inet_ntoa(from.sin_addr));
    outbuf = xmalloc(SNMP_REQUEST_SIZE);
    errstat = snmp_agent_parse(buf, len, outbuf, &outlen,
	(u_long) (from.sin_addr.s_addr), (long *) (&this_reqid));
    if (memcmp(&from, &local_snmpd, sizeof(from)) == 0) {
	/* look it up */
	if (snmpFwd_removePending(&from, this_reqid)) {		/* failed */
	    debug(49, 5) ("snmp: bogus response\n");
	    return;
	}
    }
    switch (errstat) {
    case 2:			/* we might have to forward */
	if (Config.Snmp.localPort > 0) {
	    snmpFwd_insertPending(&from, this_reqid);
#ifdef SNMP_DIRECT
	    x = comm_udp_sendto(sock,
		&local_snmpd,
		sizeof(struct sockaddr_in),
		outbuf,
		outlen);
	    if (x < 0)
		debug(49, 4) ("snmp could not deliver packet to %s\n",
		    inet_ntoa(local_snmpd.sin_addr));
#else
	    snmpUdpSend(sock, &local_snmpd, outbuf, outlen);
#endif
	    return;
	}
	debug(49, 4) ("snmp: can't forward.\n");
	break;
    case 1:			/* everything is ok */
	debug(49, 5) ("snmp: parsed.\n");
	if (snmp_dump_packet) {
/*          int count=0; */
	    debug(49, 5) ("snmp: sent %d bytes to %s\n", (int) outlen,
		inet_ntoa(from.sin_addr));
/*          for (count = 0; count < outlen; count++) {
 * debug(49, 7) ("%02X\n", (u_char) outbuf[count]);
 * }
 * debug(49, 5) ("DONE\n"); */
	}
#ifdef SNMP_DIRECT
	x = comm_udp_sendto(sock,
	    &from,
	    sizeof(struct sockaddr_in),
	    outbuf,
	    outlen);
	if (x < 0)
	    debug(49, 4) ("snmp could not deliver\n");
#else
	snmpUdpSend(sock, &from, outbuf, outlen);
#endif
	break;
    case 0:
	debug(49, 5) ("snmpagentparse failed\n");
	break;
    }
    return;
}

void
snmpInit(void)
{
    snmp_intoobigs = 0;
    snmp_inbadcommunitynames = 0;
    snmp_inasnparseerrors = 0;
    snmp_inbadvalues = 0;
    users = NULL;
    communities = NULL;
    /*read_main_config_file(); */
    init_agent_auth();

    debug(49, 5) ("init_mib: calling with %s\n", Config.Snmp.mibPath);

    init_mib(Config.Snmp.mibPath);
    if (!Config.Snmp.communities)
	debug(49, 5) ("snmpInit: communities not defined yet !\n");
    else
	debug(49, 5) ("snmpInit: well, well , communities defined!\n");
    if (read_config() < 0)
	exit(2);

    {
	static oid base[] =
	{SQ_SYS};
	mib_register(base, sizeof(base) / sizeof(oid), cachesys_vars,
	    sizeof(cachesys_vars) / sizeof(*cachesys_vars),
	    sizeof(*cachesys_vars));
    }

    {
	static oid base[] =
	{SQ_PRF};
	mib_register(base, sizeof(base) / sizeof(oid), cacheperf_vars,
	    sizeof(cacheperf_vars) / sizeof(*cacheperf_vars),
	    sizeof(*cacheperf_vars));
    }
    {
	static oid base[] =
	{SQ_CONF};
	mib_register(base, sizeof(base) / sizeof(oid), config_variables,
	    sizeof(config_variables) / sizeof(*config_variables),
	    sizeof(*config_variables));
    }
    {
	static oid base[] =
	{SQ_NET};
	mib_register(base, sizeof(base) / sizeof(oid), network_variables,
	    sizeof(network_variables) / sizeof(*network_variables),
	    sizeof(*network_variables));
    }
    return;
}

u_char *
var_cnf(struct variable * vp, oid * name, int *length,
    int exact, int *var_len, SNMPWM ** write_method)
{
    void *cp;
    int result;
    static long long_return;
    static char snbuf[256];
    oid newname[MAX_NAME_LEN];

    debug(49, 3) ("snmp: var_cnf called with magic=%d, *length=%d, *var_len=%d\n",
	vp->magic, *length, *var_len);
    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_cnf oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    debug(49, 5) ("snmp var_cnf: hey, here we are.\n");
    result = compare(name, *length, newname, (int) vp->namelen);
    if ((exact && (result != 0)) || (!exact && (result >= 0))) {
	debug(49, 5) ("snmp var_cnf: niah, didn't match.\n");
	return NULL;
    }
    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */

    switch (vp->magic) {
    case CONF_ADMIN:
	cp = Config.adminEmail;
	*var_len = strlen(cp);
	return (u_char *) cp;
    case CONF_UPTIME:
	long_return = tvSubDsec(squid_start, current_time);
	return (u_char *) & long_return;
    case CONF_ST_MMAXSZ:
	long_return = (long) Config.Mem.maxSize;
	return (u_char *) & long_return;
    case CONF_ST_MHIWM:
	long_return = (long) Config.Mem.highWaterMark;
	return (u_char *) & long_return;
    case CONF_ST_MLOWM:
	long_return = (long) Config.Mem.lowWaterMark;
	return (u_char *) & long_return;
    case CONF_ST_SWMAXSZ:
	long_return = (long) Config.Swap.maxSize;
	return (u_char *) & long_return;
    case CONF_ST_SWHIWM:
	long_return = (long) Config.Swap.highWaterMark;
	return (u_char *) & long_return;
    case CONF_ST_SWLOWM:
	long_return = (long) Config.Swap.lowWaterMark;
	return (u_char *) & long_return;
    case CONF_WAIS_RHOST:
	if (Config.Wais.relayHost)
	    cp = Config.Wais.relayHost;
	else
	    cp = "None";
	*var_len = strlen(cp);
	return (u_char *) cp;
    case CONF_WAIS_RPORT:
	long_return = (long) Config.Wais.relayPort;
	return (u_char *) & long_return;
    case CONF_TIO_RD:
	long_return = (long) Config.Timeout.read;
	return (u_char *) & long_return;
    case CONF_TIO_CON:
	long_return = (long) Config.Timeout.connect;
	return (u_char *) & long_return;
    case CONF_TIO_REQ:
	long_return = (long) Config.Timeout.request;
	return (u_char *) & long_return;
    case CONF_LOG_LVL:
	if (!(cp = Config.debugOptions))
	    cp = "None";
	*var_len = strlen(cp);
	return (u_char *) cp;
    default:
	return NULL;
    }
}


u_char *
var_peertbl(struct variable * vp, oid * name, int *length,
    int exact, int *var_len, SNMPWM ** write_method)
{
    void *cp;
    peer *p = NULL;
    static int cnt = 0;
    int result;
    static long long_return;
    static char snbuf[256];
    oid newname[MAX_NAME_LEN];

    debug(49, 3) ("snmp: var_peertbl called with magic=%d\n", vp->magic);
    debug(49, 3) ("snmp: var_peertbl with (%d,%d)\n", *length, *var_len);
    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_peertbl oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    newname[vp->namelen] = (oid) 1;

    debug(49, 5) ("snmp var_peertbl: hey, here we are.\n");

    p = Config.peers;
    cnt = 1;

    while (p != NULL) {
	newname[vp->namelen] = cnt++;
	result = compare(name, *length, newname, (int) vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0))) {
	    debug(49, 5) ("snmp var_peertbl: yup, a match.\n");
	    break;
	}
	p = p->next;
    }
    if (p == NULL)
	return NULL;

    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    sprint_objid(snbuf, newname, *length);
    debug(49, 5) ("snmp var_peertbl with peertable request for %s (%d)\n", snbuf, newname[10]);

    switch (vp->magic) {
    case CONF_PTBL_ID:
	long_return = cnt - 1;
	return (u_char *) & long_return;
    case CONF_PTBL_NAME:
	cp = p->host;
	*var_len = strlen(cp);
	return (u_char *) cp;
    case CONF_PTBL_IP:
	long_return = (long) (p->in_addr.sin_addr.s_addr);
	return (u_char *) & long_return;
    case CONF_PTBL_HTTP:
	long_return = p->http_port;
	return (u_char *) & long_return;
    case CONF_PTBL_ICP:
	long_return = p->icp_port;
	return (u_char *) & long_return;
    case CONF_PTBL_TYPE:
	long_return = p->type;
	return (u_char *) & long_return;
    case CONF_PTBL_STATE:
	long_return = neighborUp(p);
	return (u_char *) & long_return;
    default:
	return (u_char *) NULL;
    }
}

/* port read from the configfile: */
int conf_snmp_port = -1;

/* trapsink host and community; setable by configfile: */

void
read_main_config_file()
{
#ifdef OLD_SNMPCONF
    FILE *in;
    char *val;
    char line[1024];

    if (main_config_read)
	return;


    /* only do this once: */
    main_config_read = 1;

    /* init path's: */
    {
	char *pfx = getenv("SNMPCONFIGFILE");
	if (pfx == NULL)
	    pfx = Config.Snmp.configFile;

	if (pfx && (pfx = strdup(pfx)))
	    snmp_configfile = pfx;
	else
	    return;
    }

    debug(49, 2) ("snmp read_main_config_file(): %s\n", snmp_configfile);

    if (!(in = fopen(snmp_configfile, "r"))) {
	debug(49, 0) ("snmp: read_main_config_file (): cannot open %s - using default paths.\n",
	    snmp_configfile);
	return;
    }
    while (fgets(line, sizeof(line), in)) {
	char *key;

	if (!*line || *line == '\n' || *line == '#')
	    continue;
	if (line[strlen(line) - 1] == '\n')
	    line[strlen(line) - 1] = 0;

	if (!(val = strchr(line, ':'))) {

	    if (strncmp(line, "view", 4)
		&& strncmp(line, "user", 4)
		&& strncmp(line, "community", 9)) {
		debug(49, 0) ("snmp: read_main_config_file(): %s with this line:\n\t%s\n",
		    "warning: reading config: don't know what to do ",
		    line);
	    }
	    continue;
	}
	key = line;

	for (*val++ = 0; *val == ' ' || *val == '\t'; val++)
	    continue;

	/* okey dokey; now we have a key and a value: */

/** printf ("got key `%s' and val `%s'\n", key, val); **/

	if (!strcmp(key, "trap sink")) {
	    int len = sizeof(trap_sink);
	    if (strlen(val) < len)
		xstrncpy(trap_sink, val, len);
	    else {
		xstrncpy(trap_sink, val, len - 1);
		trap_sink[len - 1] = 0;
	    }

	    debug(49, 3) ("added from config: trap sink addess is %s\n",
		trap_sink);
	} else if (!strcmp(key, "trap community")) {
	    int len = sizeof(trap_community);
	    if (strlen(val) < len)
		xstrncpy(trap_community, val, len);
	    else {
		xstrncpy(trap_community, val, len - 1);
		trap_community[len - 1] = 0;
	    }

	    debug(49, 4) ("added from config: trap community string is %s\n",
		trap_community);
	} else if (!strcmp(key, "snmpEnableAuthenTraps")) {
	    if (!strcmp(val, "enabled"))
		conf_authentraps = 1;
	    else if (!strcmp(val, "disabled"))
		conf_authentraps = 2;
	    else
		debug(49, 1) ("warning: reading config: unknown val for %s\n", key);
	    debug(49, 4) ("added from config: snmpEnableAuthenTraps set to %s\n", val);
	} else {
	    debug(49, 2) ("warning: reading config: unknown key `%s'\n", key);
	}
    }
    fclose(in);
#endif
    return;
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
	debug(1, 1) ("Accepting SNMP connections on port %d, FD %d.\n",
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
	    debug(1, 1) ("Accepting SNMP connections on port %d, FD %d.\n",
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
	    if (Config.Snmp.localPort > 0) {
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
	    debug(0, 0) ("snmpFwd_removePending: freeing %p\n", p);
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
    while ((queue = snmpUdpHead)) {
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
	debug(0, 0) ("snmpUdpReply: freeing %p\n", queue->msg);
	safe_free(queue->msg);
	debug(0, 0) ("snmpUdpReply: freeing %p\n", queue);
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

u_char *
var_protostat_entry(struct variable *vp, oid * name, int *length, int exact, int *var_len,
    SNMPWM ** write_method)
{
    oid newname[MAX_NAME_LEN];
    int result;
    static char snbuf[256];
    static char snbuf2[256];
    static int current;
    proto_stat *p = NULL;

    debug(49, 3) ("snmp: var_protostat called with magic=%d \n", vp->magic);
    debug(49, 3) ("snmp: var_protostat with (%d,%d)\n", *length, *var_len);
    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_protostat oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    newname[vp->namelen] = (oid) 1;

    debug(49, 5) ("snmp var_protostat: hey, here we are.\n");

    current = 0;
    while (current < MAX_PROTOSTAT) {
	newname[vp->namelen] = current + 1;
	sprint_objid(snbuf, name, *length);
	sprint_objid(snbuf2, newname, (int) vp->namelen + 1);
/*      debug(49,3)("snmp: var_protostat comparing \n       %s \n with  %s\n",snbuf,snbuf2); */
	result = compare(name, *length, newname, (int) vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0))) {
	    debug(49, 5) ("snmp var_protostat: yup, a match.\n");
	    break;
	}
	current++;
    }
    if (current == MAX_PROTOSTAT)
	return NULL;

    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    sprint_objid(snbuf, newname, *length);
    debug(49, 5) ("snmp var_protostat  request for %s (%d)\n", snbuf, current);

    p = &HTTPCacheInfo->proto_stat_data[current];

    switch (vp->magic) {
    case PERF_PROTOSTAT_ID:
	long_return = current + 1;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_KBMAX:
	long_return = p->kb.max;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_KBMIN:
	long_return = p->kb.min;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_KBAVG:
	long_return = p->kb.avg;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_KBNOW:
	long_return = p->kb.now;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_HIT:
	long_return = p->hit;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_MISS:
	long_return = p->miss;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_REFCOUNT:
	long_return = p->refcount;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_TRNFRB:
	long_return = p->transferbyte;
	return (u_char *) & long_return;
    default:
	return NULL;
    }
}


u_char *
var_perfsys_entry(struct variable * vp, oid * name, int *length, int exact, int *var_len,
    SNMPWM ** write_method)
{
    oid newname[MAX_NAME_LEN];
    int result;
    static fde *f;
    static struct rusage rusage;
    static struct in_addr addr;
    static char *cp;
    peer *p = Config.peers;
    peer *e = NULL;
    static long long_return;
    static char snbuf[256];
    int cnt = 0;
    int num;

    if (vp->magic < PERF_PROTOSTAT_ID) {
	debug(49, 3) ("snmp: var_perfsys called with magic=%d, *length=%d, *var_len=%d\n",
	    vp->magic, *length, *var_len);
	sprint_objid(snbuf, name, *length);
	debug(49, 3) ("snmp: var_perfsys oid: %s\n", snbuf);

	memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
	debug(49, 5) ("snmp var_perfsys: hey, here we are.\n");
	result = compare(name, *length, newname, (int) vp->namelen);
	if ((exact && (result != 0)) || (!exact && (result >= 0))) {
	    debug(49, 5) ("snmp var_perfsys: niah, didn't match.\n");
	    return NULL;
	}
	debug(49, 5) ("hey, matched.\n");
	memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
	*length = vp->namelen;
	*write_method = 0;
	*var_len = sizeof(long);	/* default length */

	xmemcpy(newname, vp->name, (int) vp->namelen * sizeof(oid));

	*var_len = sizeof(long);
    } else if (vp->magic >= PERF_PEERSTAT_ID) {
	debug(49, 3) ("snmp: var_perfsys called with magic=%d for peerstat table\n", vp->magic);
	debug(49, 3) ("snmp: var_perfsys with (%d,%d)\n", *length, *var_len);
	sprint_objid(snbuf, name, *length);
	debug(49, 3) ("snmp: var_perfsys oid: %s\n", snbuf);

	memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
	newname[vp->namelen] = (oid) 1;

	debug(49, 5) ("snmp var_perfsys: hey, here we are.\n");

	p = Config.peers;
	cnt = 1;

	while (p != NULL) {
	    newname[vp->namelen] = cnt++;
	    result = compare(name, *length, newname, (int) vp->namelen + 1);
	    if ((exact && (result == 0)) || (!exact && (result < 0))) {
		debug(49, 5) ("snmp var_perfsys: yup, a match.\n");
		break;
	    }
	    p = p->next;
	}
	if (p == NULL)
	    return NULL;

	debug(49, 5) ("hey, matched.\n");
	memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
	*length = vp->namelen + 1;
	*write_method = 0;
	*var_len = sizeof(long);	/* default length */
	sprint_objid(snbuf, newname, *length);
	debug(49, 5) ("snmp var_perfsys with peerstattable request for %s (%d)\n", snbuf, newname[10]);

	e = p;
    } else if (vp->magic >= PERF_SYS_FD_NUMBER && vp->magic <= PERF_SYS_FD_NAME) {

	debug(49, 3) ("snmp: var_perfsys called with magic=%d for fd table\n", vp->magic);
	debug(49, 3) ("snmp: var_perfsys with (%d,%d)\n", *length, *var_len);
	sprint_objid(snbuf, name, *length);
	debug(49, 3) ("snmp: var_perfsys oid: %s\n", snbuf);

	memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
	newname[vp->namelen] = (oid) 1;

	debug(49, 5) ("snmp var_perfsys: hey, here we are.\n");
	cnt = 0;
	num = 1;
	while (cnt < Squid_MaxFD) {
	    f = &fd_table[cnt++];
	    if (!f->open)
		continue;
	    newname[vp->namelen] = num++;
	    result = compare(name, *length, newname, (int) vp->namelen + 1);
	    if ((exact && (result == 0)) || (!exact && (result < 0))) {
		debug(49, 5) ("snmp var_perfsys: yup, a match.\n");
		break;
	    }
	}
	if (cnt == Squid_MaxFD)
	    return NULL;

	debug(49, 5) ("hey, matched.\n");
	memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
	*length = vp->namelen + 1;
	*write_method = 0;
	*var_len = sizeof(long);	/* default length */
	sprint_objid(snbuf, newname, *length);
	debug(49, 5) ("snmp var_perfsys with fdtable request for %s (%d)\n", snbuf, newname);

    }
    switch (vp->magic) {
    case PERF_SYS_PF:
	squid_getrusage(&rusage);
	long_return = (long) rusage_pagefaults(&rusage);
	return (u_char *) & long_return;

    case PERF_SYS_NUMR:
	long_return = IOStats.Http.reads;
	return (u_char *) & long_return;

    case PERF_SYS_DEFR:
	long_return = IOStats.Http.reads_deferred;
	return (u_char *) & long_return;

    case PERF_SYS_FD_NUMBER:
	if (!f->open)
	    return NULL;
	long_return = (int) name[11];
	return (u_char *) & long_return;

    case PERF_SYS_FD_TYPE:
	long_return = f->type;
	return (u_char *) & long_return;

    case PERF_SYS_FD_TOUT:
	long_return = (long) (f->timeout_handler ? (f->timeout - squid_curtime) / 60 : 0);
	return (u_char *) & long_return;

    case PERF_SYS_FD_NREAD:
	long_return = (long) f->bytes_read;
	return (u_char *) & long_return;

    case PERF_SYS_FD_NWRITE:
	long_return = (long) f->bytes_written;
	return (u_char *) & long_return;

    case PERF_SYS_FD_ADDR:
	if (f->type != FD_SOCKET)
	    long_return = (long) 0;
	else {
	    safe_inet_addr(f->ipaddr, &addr);
	    long_return = (long) addr.s_addr;
	}
	return (u_char *) & long_return;

    case PERF_SYS_FD_NAME:
	cp = f->desc;
	*var_len = strlen(cp);
	return (u_char *) cp;

    case PERF_SYS_MEMUSAGE:
	return (u_char *) & long_return;

    case PERF_SYS_CPUUSAGE:
	squid_getrusage(&rusage);
	long_return = (long) rusage_cputime(&rusage);
	return (u_char *) & long_return;

    case PERF_SYS_MAXRESSZ:
	squid_getrusage(&rusage);
	long_return = (long) rusage_maxrss(&rusage);
	return (u_char *) & long_return;

    case PERF_SYS_CURMEMSZ:
	long_return = (long) memoryAccounted() >> 10;	/* needs to be fixed */
	return (u_char *) & long_return;

    case PERF_SYS_CURLRUEXP:
	long_return = (long) ((double) storeExpiredReferenceAge() / 86400.0);
	return (u_char *) & long_return;

    case PERF_SYS_CURUNLREQ:
	long_return = (long) Counter.unlink.requests;
	return (u_char *) & long_return;

    case PERF_SYS_CURUNUSED_FD:
	long_return = (long) Squid_MaxFD - Number_FD;
	return (u_char *) & long_return;

    case PERF_SYS_CURRESERVED_FD:
	long_return = (long) Number_FD;
	return (u_char *) & long_return;

    case PERF_SYS_NUMOBJCNT:
	long_return = (long) meta_data.mem_obj_count;
	return (u_char *) & long_return;


    case PERF_PEERSTAT_ID:
	long_return = cnt - 1;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_SENT:
	long_return = e->stats.pings_sent;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_PACKED:
	long_return = e->stats.pings_acked;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_FETCHES:
	long_return = e->stats.fetches;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_RTT:
	long_return = e->stats.rtt;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_IGN:
	long_return = e->stats.ignored_replies;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_KEEPAL_S:
	long_return = e->stats.n_keepalives_sent;
	return (u_char *) & long_return;
    case PERF_PEERSTAT_KEEPAL_R:
	long_return = e->stats.n_keepalives_recv;
	return (u_char *) & long_return;
    default:
	return NULL;
    }
}

u_char *
var_ipcache_entry(struct variable * vp, oid * name, int *length, int exact, int *var_len,
    SNMPWM ** write_method)
{
    static char Name[18], *cp;
    static long long_return;
    static int current = 0;
    oid newname[MAX_NAME_LEN];
    int result;
    extern dlink_list lru_list;
    dlink_node *m = NULL;
    ipcache_entry *IPc;


    sprint_objid(Name, name, *length);
    debug(49, 6) ("snmp var_ipcache_entry : With oid=%s \n", Name);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    *write_method = 0;

    newname[vp->namelen] = (oid) 1;

    if (exact) {
	current = name[vp->namelen];
	debug(49, 5) ("snmp var_ipcache_entry: current=%d\n", current);
	if (current < 0 || current > 2000)	/* out of bounds */
	    return NULL;
	newname[vp->namelen] = current;
    } else if (*length == vp->namelen) {
	debug(49, 6) ("snmp var_ipcache_entry: we have a getnext, sigh.\n");
	current = name[vp->namelen] + 1;
	if (current < 0 || current > 2000) {
	    if ((vp->name[vp->namelen - 1] != name[vp->namelen - 1])) {
		current = 1;
	    } else
		return NULL;
	}
	newname[vp->namelen] = current;
    } else {
	debug(49, 5) ("Slow code for snmp ipcache table. (%d!=%d)\n",
	    *length, vp->namelen);
	current = 1;
	for (m = lru_list.head; m; m = m->next) {
	    newname[vp->namelen] = current++;
	    sprint_objid(Name, newname, vp->namelen + 1);
	    debug(49, 5) ("snmp ipcache_table: newname=%s\n", Name);
	    sprint_objid(Name, name, *length);
	    debug(49, 5) ("snmp ipcache_table: name=%s\n", Name);
	    result = compare(name, *length, newname, (int) vp->namelen + 1);
	    if ((exact && (result == 0)) || (!exact && (result < 0))) {
		debug(49, 5) ("snmp ipcache_table, breaking %d\n",
		    current);
		break;
	    } else
		debug(49, 5) ("Nope, none of the above.\n");
	}
	if (m == NULL) {
	    debug(49, 5) ("snmp ipcache_table , m==NULL (%d)\n",
		current);
	    return NULL;

	}
    }

    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *var_len = sizeof(u_long);
    debug(49, 5) ("snmp ipcache_table: Wow, got past checks with current=%d\n", current);
    if (m == NULL)
	return NULL;
    if ((IPc = m->data) == NULL)
	return NULL;

    current++;
    switch (vp->magic) {
    case NET_IPC_ID:
	long_return = (int) current - 1;
	return (u_char *) & long_return;
    case NET_IPC_NAME:
	cp = IPc->name;
	*var_len = strlen(cp);
	return (u_char *) cp;
    case NET_IPC_IP:
	long_return = IPc->addrs.in_addrs[0].s_addr;	/* first one only */
	return (u_char *) & long_return;
    case NET_IPC_STATE:
	long_return = IPc->status;
	return (u_char *) & long_return;
    default:
	return NULL;
    }
}

u_char *
var_fqdn_entry(struct variable * vp, oid * name, int *length, int exact, int
    *var_len,
    SNMPWM ** write_method)
{
    static int current = 0;
    static long long_return;
    static char *cp = NULL;
    static fqdncache_entry *fq;
    static struct in_addr fqaddr;
    int i;
    oid newname[MAX_NAME_LEN];
    int result;
    static char snbuf[256];

    debug(49, 3) ("snmp: var_fqdn_entry called with magic=%d \n", vp->magic);
    debug(49, 3) ("snmp: var_fqdn_entry with (%d,%d)\n", *length, *var_len);
    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_fqdn_entry oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    newname[vp->namelen] = (oid) 1;

    debug(49, 5) ("snmp var_fqdn_entry: hey, here we are.\n");

    fq = NULL;
    i = 0;
    while (fq != NULL) {
	newname[vp->namelen] = i + 1;
	result = compare(name, *length, newname, (int) vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0))) {
	    debug(49, 5) ("snmp var_fqdn_entry: yup, a match.\n");
	    break;
	}
	i++;
	fq = NULL;
    }
    if (fq == NULL)
	return NULL;

    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    sprint_objid(snbuf, newname, *length);
    debug(49, 5) ("snmp var_fqdn_entry  request for %s (%d)\n", snbuf, current);

    switch (vp->magic) {
    case NET_FQDN_ID:
	long_return = (long) current;
	return (u_char *) & long_return;
    case NET_FQDN_NAME:
	cp = fq->names[0];
	*var_len = strlen(cp);
	return (u_char *) cp;
    case NET_FQDN_IP:
	safe_inet_addr(fq->name, &fqaddr);
	long_return = (long) fqaddr.s_addr;
	return (u_char *) & long_return;
    case NET_FQDN_LASTREF:
	long_return = fq->lastref;
	return (u_char *) & long_return;
    case NET_FQDN_EXPIRES:
	long_return = fq->expires;
	return (u_char *) & long_return;
    case NET_FQDN_STATE:
	long_return = fq->status;
	return (u_char *) & long_return;
    default:
	return NULL;
    }
}

u_char *
var_net_vars(struct variable * vp, oid * name, int *length, int exact, int
    *var_len,
    SNMPWM ** write_method)
{
    static long long_return;
    oid newname[MAX_NAME_LEN];
    static char snbuf[256];
    int result;

    debug(49, 3) ("snmp: var_net_vars called with magic=%d, *length=%d, *var_len=%d\n",
	vp->magic, *length, *var_len);
    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_net_vars oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    debug(49, 5) ("snmp var_net_vars: hey, here we are.\n");
    result = compare(name, *length, newname, (int) vp->namelen);
    if ((exact && (result != 0)) || (!exact && (result >= 0))) {
	debug(49, 5) ("snmp var_net_vars: niah, didn't match.\n");
	return NULL;
    }
    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */

    xmemcpy(newname, vp->name, (int) vp->namelen * sizeof(oid));

    *var_len = sizeof(long);

    switch (vp->magic) {
    case NET_TCPCONNS:
	return (u_char *) long_return;
    case NET_UDPCONNS:
	return (u_char *) long_return;
    case NET_INTHRPUT:
	return (u_char *) long_return;
    case NET_OUTHRPUT:
	return (u_char *) long_return;
    default:
	return NULL;
    }
    /* NOTREACHED */
}

u_char *
var_netdb_entry(struct variable * vp, oid * name, int *length, int exact, int *var_len,
    SNMPWM ** write_method)
{
    oid newname[MAX_NAME_LEN];
    static char Name[16];
    static netdbEntry *n = NULL;
    static long long_return;
    int current;

#ifdef USE_ICMP
    for (n = netdbGetFirst(addr_table), current = 0; n != NULL && current < name[10];
	(n = n->next), current++);
#endif
    if (n == NULL)
	return NULL;
    /* find "next" entry */
    sprint_objid(Name, name, *length);
    debug(49, 6) ("snmp netdb_entry With oid=%s \n", Name);
    *length = vp->namelen + 1;
    *write_method = NULL;
    *var_len = sizeof(long);
    vp->magic = newname[11];
    switch (vp->magic) {
    case NETDB_NET:
	long_return = (long) n->network;
	return (u_char *) & long_return;
    case NETDB_PING_S:
	long_return = (long) n->pings_sent;
	return (u_char *) & long_return;
    case NETDB_PING_R:
	long_return = (long) n->pings_recv;
	return (u_char *) & long_return;
    case NETDB_HOPS:
	long_return = (long) n->hops;
	return (u_char *) & long_return;
    case NETDB_RTT:
	long_return = (long) n->rtt;
	return (u_char *) & long_return;
    case NETDB_PINGTIME:
	long_return = (long) n->next_ping_time;
	return (u_char *) & long_return;
    case NETDB_LASTUSE:
	long_return = (long) n->last_use_time;
	return (u_char *) & long_return;
    default:
	return NULL;
    }
}

u_char *
var_cachesys_entry(struct variable * vp, oid * name, int *length, int exact,
    int *var_len,
    SNMPWM ** write_method)
{
    static long long_return;
    oid newname[MAX_NAME_LEN];
    static char snbuf[256];
    int result;

    debug(49, 3) ("snmp: var_cachesys_entry called with magic=%d, *length=%d, *var_len=%d\n",
	vp->magic, *length, *var_len);

    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_cachesys_entry oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    debug(49, 5) ("snmp var_cachesys_entry: hey, here we are.\n");
    result = compare(name, *length, newname, (int) vp->namelen);
    if ((exact && (result != 0)) || (!exact && (result >= 0))) {
	debug(49, 5) ("snmp var_cachesys_entry: niah, didn't match.\n");
	return NULL;
    }
    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */

    xmemcpy(newname, vp->name, (int) vp->namelen * sizeof(oid));

    *var_len = sizeof(long_return);

    switch (vp->magic) {
    case SYSVMSIZ:
	long_return = store_mem_size;
	return (u_char *) & long_return;
    case SYSSTOR:
	long_return = store_swap_size;
	return (u_char *) & long_return;
    default:
	return NULL;
    }

}

u_char *
var_aggreg_entry(struct variable * vp, oid * name, int *length, int exact,
    int *var_len,
    SNMPWM ** write_method)
{
    static long long_return;
    oid newname[MAX_NAME_LEN];
    static char snbuf[256];
    int result;

    debug(49, 3) ("snmp: var_aggreg_entry called with magic=%d, *length=%d, *var_len=%d\n",
	vp->magic, *length, *var_len);
    sprint_objid(snbuf, name, *length);
    debug(49, 3) ("snmp: var_aggreg_entry oid: %s\n", snbuf);

    memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    debug(49, 5) ("snmp var_aggreg_entry: hey, here we are.\n");
    result = compare(name, *length, newname, (int) vp->namelen);
    if ((exact && (result != 0)) || (!exact && (result >= 0))) {
	debug(49, 5) ("snmp var_aggreg_entry: niah, didn't match.\n");
	return NULL;
    }
    debug(49, 5) ("hey, matched.\n");
    memcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */

    xmemcpy(newname, vp->name, (int) vp->namelen * sizeof(oid));

    *var_len = sizeof(long);

    switch (vp->magic) {
    case PERF_PROTOSTAT_AGGR_CLHTTP:
	long_return = (long) Counter.client_http.requests;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_AGGR_ICP_S:
	long_return = (long) Counter.icp.pkts_sent;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_AGGR_ICP_R:
	long_return = (long) Counter.icp.pkts_recv;
	return (u_char *) & long_return;
    case PERF_PROTOSTAT_AGGR_CURSWAP:
	long_return = (long) store_swap_size;
	return (u_char *) & long_return;
    default:
	return NULL;
    }
}

void
snmpConnectionClose(void)
{
    if (theInSnmpConnection < 0)
	return;
    comm_close(theInSnmpConnection);
    theInSnmpConnection = -1;
}

#endif
