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

#include "mib_module.h"
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

void snmpFwd_insertPending(struct sockaddr_in *, long);
int snmpFwd_removePending(struct sockaddr_in *, long);
extern int init_agent_auth();
extern int snmp_agent_parse(char *, int, char *, int *, u_long, long *);
extern int read_config();
extern void read_main_config_file();
char *snmp_configfile;
extern void init_modules();
static SNMPFV var_cnf;
static SNMPFV var_peertbl;

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

/* now include mib location definitions
 * and magic numbers */

#include "cache_snmp.h"


SNMPFV var_cachesys_entry;
SNMPFV var_perfsys_entry;
#if OLD_CODE
SNMPFV var_protostat_entry;
#endif
SNMPFV var_conf_entry;
SNMPFV var_netdb_entry;
SNMPFV var_ipcache_entry;
SNMPFV var_fqdn_entry;
SNMPFV var_conf_entry;
SNMPFV var_net_vars;
SNMPFV var_aggreg_entry;
SNMPFV var_system;

struct variable cachesys_vars[] =
{
    {SYSVMSIZ, INTEGER, RONLY, var_cachesys_entry, 1,
	{1}},
    {SYSSTOR, INTEGER, RONLY, var_cachesys_entry, 1,
	{2}}
};

struct variable2 system_variables[] =
{
    {VERSION_DESCR, STRING, RONLY, var_system, 1,
	{1}},
    {VERSION_ID, OBJID, RONLY, var_system, 1,
	{2}},
    {UPTIME, TIMETICKS, RONLY, var_system, 1,
	{3}},
    {SYSCONTACT, STRING, RWRITE, var_system, 1,
	{4}},
    {SYSYSNAME, STRING, RWRITE, var_system, 1,
	{5}},
    {SYSLOCATION, STRING, RWRITE, var_system, 1,
	{6}},
    {SYSSERVICES, INTEGER, RONLY, var_system, 1,
	{7}},
    {SYSORLASTCHANGE, TIMETICKS, RONLY, var_system, 1,
	{8}}
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
#if OLD_CODE
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
#endif
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
    int outlen;
    snmp_dump_packet = 1;
    debug(49, 5) ("snmpHandleUdp: Initialized.\n");
    commSetSelect(sock, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);
    debug(49, 5) ("snmpHandleUdp: got past select\n");
    from_len = sizeof(from);
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
    outbuf = xmalloc(outlen = SNMP_REQUEST_SIZE);
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
	if (Config.Snmp.localPort != 0) {
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
	{1, 3, 6, 1, 2, 1, 1};
	mib_register(base, 7, system_variables,
	    sizeof(system_variables) / sizeof(*system_variables),
	    sizeof(*system_variables));
    }

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
    result = snmpCompare(name, *length, newname, (int) vp->namelen);
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
	result = snmpCompare(name, *length, newname, (int) vp->namelen + 1);
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

u_char *
var_perfsys_entry(struct variable *vp, oid * name, int *length, int exact, int *var_len,
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

    if (vp->magic < (u_char) PERF_PROTOSTAT_ID) {
	debug(49, 3) ("snmp: var_perfsys called with magic=%d, *length=%d, *var_len=%d\n",
	    vp->magic, *length, *var_len);
	sprint_objid(snbuf, name, *length);
	debug(49, 3) ("snmp: var_perfsys oid: %s\n", snbuf);

	memcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
	debug(49, 5) ("snmp var_perfsys: hey, here we are.\n");
	result = snmpCompare(name, *length, newname, (int) vp->namelen);
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
    } else if (vp->magic >= (u_char) PERF_PEERSTAT_ID) {
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
	    result = snmpCompare(name, *length, newname, (int) vp->namelen + 1);
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
    } else if (vp->magic >= (u_char) PERF_SYS_FD_NUMBER && vp->magic <= (u_char) PERF_SYS_FD_NAME) {

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
	    result = snmpCompare(name, *length, newname, (int) vp->namelen + 1);
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
	/* XXX needs to be fixed */
	long_return = (long) statMemoryAccounted() >> 10;
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
	long_return = (long) memInUse(MEM_STOREENTRY);
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
    result = snmpCompare(name, *length, newname, (int) vp->namelen);
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
    result = snmpCompare(name, *length, newname, (int) vp->namelen);
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
    result = snmpCompare(name, *length, newname, (int) vp->namelen);
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


u_char *
var_system(struct variable * vp, oid * name, int *length, int exact,
    int *var_len,
    SNMPWM ** write_method)
{
    oid newname[MAX_NAME_LEN];
    int result;
    char *pp;
    xmemcpy((char *) newname, (char *) vp->name, (int) vp->namelen * sizeof(oid));
    newname[8] = 0;
    result = snmpCompare(name, *length, newname, (int) vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
	return NULL;
    xmemcpy((char *) name, (char *) newname, ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    switch (vp->magic) {
    case VERSION_DESCR:
    case VERSION_ID:
	pp = SQUID_VERSION;
	*var_len = strlen(pp);
	return (u_char *) pp;
    case UPTIME:
    case SYSORLASTCHANGE:
	long_return = tvSubDsec(squid_start, current_time);
	return (u_char *) & long_return;
    case SYSCONTACT:
	*var_len = strlen(Config.adminEmail);
	return (u_char *) Config.adminEmail;
    case SYSYSNAME:
	*var_len = strlen(Config.visibleHostname);
	return (u_char *) Config.visibleHostname;
    case SYSLOCATION:
	pp = "Cyberspace";
	*var_len = strlen(pp);
	return (u_char *) pp;
    case SYSSERVICES:
	long_return = 72;
	return (u_char *) & long_return;
    default:
	ERROR("");
    }
    return NULL;
}

void
snmpConnectionClose(void)
{
    if (theInSnmpConnection < 0)
	return;
    if (theInSnmpConnection != theOutSnmpConnection)
	comm_close(theInSnmpConnection);
    /*
     * Here we set 'theInSnmpConnection' to -1 even though the SNMP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */
    theInSnmpConnection = -1;
    /* 
     * Normally we only write to the outgoing SNMP socket, but we
     * also have a read handler there to catch messages sent to that
     * specific interface.  During shutdown, we must disable reading
     * on the outgoing socket.
     */
    assert(theOutSnmpConnection > -1);
    commSetSelect(theOutSnmpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}
