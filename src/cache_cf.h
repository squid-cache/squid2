
/*
 *  $Id$
 *
 *  File:         config.h
 *  Description:  Declarations of parsing and config functions
 *  Author:       Chuck Neerdaels, USC
 *  Created:      Mon May 23 
 *  Language:     C
 *
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#ifndef _CACHE_CONFIG_H_
#define _CACHE_CONFIG_H_

#include "ansihelp.h"
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct _stoplist {
    char *key;
    struct _stoplist *next;
} stoplist;

typedef enum {
    IP_ALLOW,
    IP_DENY
} ip_access_type;



typedef struct _ip_acl {
    int a1, a2, a3, a4;
    ip_access_type access;
    struct _ip_acl *next;
} ip_acl;

extern int errno;
extern int httpd_accel_mode;
extern int emulate_httpd_log;
extern int zap_disk_store;
extern stoplist *http_stoplist;
extern stoplist *gopher_stoplist;
extern stoplist *ftp_stoplist;
extern stoplist *bind_addr_list;
extern ip_acl *proxy_ip_acl;
extern ip_acl *accel_ip_acl;
extern ip_acl *manager_ip_acl;

int parseConfigFile _PARAMS((char *file_name));
int daemonize();
int check_suid();

int getHttpMax();
int getHttpTTL();
int getGopherMax();
int getGopherTTL();
int getFtpMax();
int getFtpTTL();
int getNegativeTTL();
int getCacheMemMax();
int getCacheMemHighWaterMark();
int getCacheMemLowWaterMark();
int getCacheSwapMax();
int setCacheSwapMax _PARAMS((int size));
int getCacheSwapHighWaterMark();
int getCacheSwapLowWaterMark();
double getCacheHotVmFactor();
int getReadTimeout();
int getClientLifetime();
int getCleanRate();
int getDnSChildren();
int ip_acl_match _PARAMS((int c1, int c2, int c3, int c4,
	int a1, int a2, int a3, int a4));
ip_access_type ip_access_check _PARAMS((struct in_addr address,
	ip_acl * list));

int getSourcePing();
int getBehindFirewall();
int getQuickAbort();
int getCacheNeighborObj();
char *getAccelPrefix();
int getAccelWithProxy();
char *getAccessLogFile();
char *getHierarchyLogFile();
char *getCacheLogFile();
int getAsciiPortNum();
int getBinaryPortNum();
int getUdpPortNum();
char *getFtpProgram();
char *getFtpOptions();
char *getDnsProgram();
char *getAdminEmail();
int getDebugLevel();
char *getAppendDomain();
int setAsciiPortNum _PARAMS((int));
int setUdpPortNum _PARAMS((int));
int setBinaryPortNum _PARAMS((int));
int getLogfileRotateNumber _PARAMS((void));

#if USE_WAIS_RELAY
char *getWaisRelayHost();
int getWaisRelayPort();
#endif


#endif /* ndef  _CACHE_CONFIG_H_ */
