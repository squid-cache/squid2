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


/* Global Variables */
extern char *ConfigFile;	/* the whole thing */
extern char *DefaultConfigFile;
extern char *DefaultSwapDir;	/* argh */
extern char *cfg_filename;	/* Only the tail component of the path */
extern char config_input_line[];
extern char w_space[];
extern int DnsPositiveTtl;
extern int config_lineno;
extern int emulate_httpd_log;
extern int identLookup;
extern int httpd_accel_mode;
extern int unbuffered_logs;
extern int zap_disk_store;
extern wordlist *bind_addr_list;
extern wordlist *ftp_stoplist;
extern wordlist *gopher_stoplist;
extern wordlist *http_stoplist;
extern char ForwardedBy[];

/* Global Functions */
extern char *getAccelPrefix _PARAMS((void));
extern char *getAccessLogFile _PARAMS((void));
extern char *getAdminEmail _PARAMS((void));
extern char *getAnnounceFile _PARAMS((void));
extern char *getAnnounceHost _PARAMS((void));
extern char *getAppendDomain _PARAMS((void));
extern char *getCacheLogFile _PARAMS((void));
extern char *getDebugOptions _PARAMS((void));
extern char *getDnsProgram _PARAMS((void));
extern char *getRedirectProgram _PARAMS((void));
extern char *getEffectiveGroup _PARAMS((void));
extern char *getEffectiveUser _PARAMS((void));
extern char *getFtpOptions _PARAMS((void));
extern char *getFtpProgram _PARAMS((void));
extern char *getFtpUser _PARAMS((void));
extern char *getHierarchyLogFile _PARAMS((void));
extern char *getPidFilename _PARAMS((void));
extern char *getStoreLogFile _PARAMS((void));
extern char *getVisibleHostname _PARAMS((void));
extern char *getWaisRelayHost _PARAMS((void));
extern double getCacheHotVmFactor _PARAMS((void));
extern int getAccelWithProxy _PARAMS((void));
extern int getAnnounceRate _PARAMS((void));
extern int getBehindFirewall _PARAMS((void));
extern int getCacheMemHighWaterMark _PARAMS((void));
extern int getCacheMemLowWaterMark _PARAMS((void));
extern int getCacheMemMax _PARAMS((void));
extern int getCacheNeighborObj _PARAMS((void));
extern int getCacheSwapHighWaterMark _PARAMS((void));
extern int getCacheSwapLowWaterMark _PARAMS((void));
extern int getCacheSwapMax _PARAMS((void));
extern int getCleanRate _PARAMS((void));
extern int getClientLifetime _PARAMS((void));
extern int getConnectTimeout _PARAMS((void));
extern int getDnsChildren _PARAMS((void));
extern int getRedirectChildren _PARAMS((void));
extern int getFtpMax _PARAMS((void));
extern int getFtpTTL _PARAMS((void));
extern int getGopherMax _PARAMS((void));
extern int getGopherTTL _PARAMS((void));
extern int getHttpMax _PARAMS((void));
extern int getHttpTTL _PARAMS((void));
extern int getLogfileRotateNumber _PARAMS((void));
extern int getMaxRequestSize _PARAMS((void));
extern int getNegativeDNSTTL _PARAMS((void));
extern int getNegativeTTL _PARAMS((void));
extern int getQuickAbort _PARAMS((void));
extern int getReadTimeout _PARAMS((void));
extern int getShutdownLifetime _PARAMS((void));
extern int getSourcePing _PARAMS((void));
extern int getStallDelay _PARAMS((void));
extern int getWAISMax _PARAMS((void));
extern int ip_acl_match _PARAMS((struct in_addr, ip_acl *));
extern int parseConfigFile _PARAMS((char *file_name));
extern int setCacheSwapMax _PARAMS((int size));
extern ip_access_type ip_access_check _PARAMS((struct in_addr, ip_acl *));
extern u_short getAccelPort _PARAMS((void));
extern u_short getAnnouncePort _PARAMS((void));
extern u_short getHttpPortNum _PARAMS((void));
extern u_short getIcpPortNum _PARAMS((void));
extern u_short getWaisRelayPort _PARAMS((void));
extern u_short setHttpPortNum _PARAMS((int));
extern u_short setIcpPortNum _PARAMS((int));
extern void intlistDestroy _PARAMS((intlist **));
extern void wordlistDestroy _PARAMS((wordlist **));
extern struct in_addr getTcpIncomingAddr _PARAMS((void));
extern struct in_addr getTcpOutgoingAddr _PARAMS((void));
extern struct in_addr getUdpIncomingAddr _PARAMS((void));
extern struct in_addr getUdpOutgoingAddr _PARAMS((void));
extern struct in_addr getClientNetmask _PARAMS((void));
extern int getTcpRcvBufsz _PARAMS((void));
extern wordlist *getCacheDirs _PARAMS((void));
extern wordlist *getDnsTestnameList _PARAMS((void));
extern wordlist *getFtpStoplist _PARAMS((void));
extern wordlist *getGopherStoplist _PARAMS((void));
extern wordlist *getHttpStoplist _PARAMS((void));
extern wordlist *getHierarchyStoplist _PARAMS((void));
extern wordlist *getInsideFirewallList _PARAMS((void));
extern wordlist *getLocalDomainList _PARAMS((void));
#if REDIRECT_IN_PROGRESS
extern int getRedirectChildren _PARAMS((void));
extern char *getRedirectProgram _PARAMS((void));
#endif


#endif /* ndef  _CACHE_CONFIG_H_ */
