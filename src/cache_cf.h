/*
 * $Id$
 *
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#ifndef _CACHE_CONFIG_H_
#define _CACHE_CONFIG_H_

#define DefaultDnsChildrenMax		32	/* 32 processes */
#define DefaultRedirectChildrenMax	32	/* 32 processes */

typedef struct _wordlist {
    char *key;
    struct _wordlist *next;
} wordlist;

typedef struct _intlist {
    int i;
    struct _intlist *next;
} intlist;

typedef struct _relist {
    char *pattern;
    regex_t regex;
    struct _relist *next;
} relist;

typedef enum {
    IP_ALLOW,
    IP_DENY
} ip_access_type;

typedef struct _ip_acl {
    struct in_addr addr;
    struct in_addr mask;
    ip_access_type access;
    struct _ip_acl *next;
} ip_acl;

struct SquidConfig {
    struct {
	int maxSize;
	int highWaterMark;
	int lowWaterMark;
    } Mem , Swap;
    struct {
	int maxObjSize;
	int defaultTtl;
    } Gopher, Http, Ftp;
    struct {
	int maxObjSize;
	int defaultTtl;
	char *relayHost;
	u_short relayPort;
    } Wais;
    struct {
	int min;
	int pct;
	int max;
    } quickAbort;
    int expireAge;
    int negativeTtl;
    int negativeDnsTtl;
    int positiveDnsTtl;
    int readTimeout;
    int lifetimeDefault;
    int lifetimeShutdown;
    int connectTimeout;
    int ageMaxDefault;
    int cleanRate;
    int maxRequestSize;
    struct {
	u_short http;
	u_short icp;
    } Port;
    struct {
	char *log;
	char *access;
	char *hierarchy;
	char *store;
	int rotateNumber;
	int log_fqdn;
    } Log;
#if USE_PROXY_AUTH
    char *proxyAuthFile;
    char *proxyAuthIgnoreDomain;
#endif				/* USE_PROXY_AUTH */
    char *adminEmail;
    char *effectiveUser;
    char *effectiveGroup;
    struct {
	char *ftpget;
	char *ftpget_opts;
	char *dnsserver;
	char *redirect;
	char *pinger;
    } Program;
    int dnsChildren;
    int redirectChildren;
    int sourcePing;
    int commonLogFormat;
#if LOG_FULL_HEADERS
    int logMimeHdrs;
#endif				/* LOG_FULL_HEADERS */
    int identLookup;
    int neighborTimeout;
    int stallDelay;
    int singleParentBypass;
    struct {
	char *host;
	char *prefix;
	u_short port;
	int withProxy;
    } Accel;
    char *appendDomain;
    char *volatile debugOptions;
    char *pidFilename;
    char *visibleHostname;
    char *ftpUser;
    char *errHtmlText;
    struct {
	char *host;
	char *file;
	int rate;
	int on;
	u_short port;
    } Announce;
    struct {
	struct in_addr tcp_incoming;
	struct in_addr tcp_outgoing;
	struct in_addr udp_incoming;
	struct in_addr udp_outgoing;
	struct in_addr client_netmask;
    } Addrs;
    int tcpRcvBufsz;
    wordlist *cache_dirs;
    wordlist *cache_stoplist;
    wordlist *hierarchy_stoplist;
    wordlist *local_domain_list;
    wordlist *mcast_group_list;
    wordlist *inside_firewall_list;
    wordlist *dns_testname_list;
    ip_acl *local_ip_list;
    ip_acl *firewall_ip_list;
    struct {
	char *host;
	u_short port;
    } sslProxy;
    struct {
	int size;
	int low;
	int high;
    } ipcache;
    int minDirectHops;
};

extern struct SquidConfig Config;

/* Global Variables */
extern char *ConfigFile;	/* the whole thing */
extern char *DefaultConfigFile;
extern char *DefaultSwapDir;	/* argh */
extern char *cfg_filename;	/* Only the tail component of the path */
extern char config_input_line[];
extern char w_space[];
extern int config_lineno;
extern volatile int unbuffered_logs;
extern char ForwardedBy[];
extern int httpd_accel_mode;

extern int parseConfigFile _PARAMS((char *file_name));
extern int setCacheSwapMax _PARAMS((int size));
extern ip_access_type ip_access_check _PARAMS((struct in_addr, ip_acl *));
extern u_short setHttpPortNum _PARAMS((u_short));
extern u_short setIcpPortNum _PARAMS((u_short));
extern void intlistDestroy _PARAMS((intlist **));
extern void wordlistDestroy _PARAMS((wordlist **));
extern void configFreeMemory _PARAMS((void));


#endif /* ndef  _CACHE_CONFIG_H_ */
