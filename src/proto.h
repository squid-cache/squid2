/*
 *  $Id$
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
#ifndef PROTO_H
#define PROTO_H

#include "ansihelp.h"
#include "comm.h"		/* just in case.... for HARVESTHOSTNAMELEN */
#include <sys/types.h>
#include <netinet/in.h>
#if !defined(__ultrix) || !defined(SOCK_STREAM)		/* not protected */
#include <sys/socket.h>
#endif

/* 32 bit integer compatability hack */
#include "autoconf.h"		/* include for the SIZEOF_ stuff */
#if SIZEOF_LONG == 4
typedef long num32;
typedef unsigned long u_num32;
#elif SIZEOF_INT == 4
typedef int num32;
typedef unsigned int u_num32;
#else
typedef long num32;		/* assume that long's are 32bit */
typedef unsigned long u_num32;
#endif
#define NUM32LEN sizeof(num32)	/* this should always be 4 */


#define ICP_AUTH_SIZE (2)	/* size of authenticator field */
struct icp_common_s {
    unsigned char opcode;	/* opcode */
    unsigned char version;	/* version number */
    unsigned short length;	/* total length (bytes) */
    u_num32 reqnum;		/* req number (req'd for UDP) */
    u_num32 auth[ICP_AUTH_SIZE];	/* authenticator (future) */
    u_num32 shostid;		/* sender host id */
};
typedef struct icp_common_s icp_common_t;
#define ICP_COMMON_SZ (sizeof(icp_common_t))
#define ICP_HDR_SZ (sizeof(icp_common_t)+sizeof(u_num32))
#define ICP_MAX_URL (4096)
typedef enum {
    ICP_OP_INVALID,		/* to insure 0 doesn't get accidently interpreted. */
    ICP_OP_QUERY,		/* query opcode (cl->sv) */
    ICP_OP_HIT,			/* hit (cl<-sv) */
    ICP_OP_MISS,		/* miss (cl<-sv) */
    ICP_OP_ERR,			/* error (cl<-sv) */
    ICP_OP_SEND,		/* send object non-auth (cl->sv) */
    ICP_OP_SENDA,		/* send object authoritative (cl->sv) */
    ICP_OP_DATABEG,		/* first data, but not last (sv<-cl) */
    ICP_OP_DATA,		/* data middle of stream (sv<-cl) */
    ICP_OP_DATAEND,		/* last data (sv<-cl) */
    ICP_OP_SECHO,		/* echo from source (sv<-os) */
    ICP_OP_DECHO,		/* echo from dumb cached (sv<-dc) */
    ICP_OP_END			/* marks end of opcodes */
} icp_opcode;

#define ICP_OP_HIGHEST (ICP_OP_END - 1)		/* highest valid opcode */


/* Header for QUERY packet */
struct icp_query_s {
    u_num32 q_rhostid;		/* requestor host id */
    char *q_url;		/* variable sized URL data */
};
typedef struct icp_query_s icp_query_t;
#define ICP_QUERY_SZ (sizeof(icp_query_t))

/* Header for HIT packet */
struct icp_hit_s {
    u_num32 h_size;		/* size if known */
    char *h_url;		/* variable sized URL data */
};
typedef struct icp_hit_s icp_hit_t;
#define ICP_HIT_SZ (sizeof(icp_hit_t))

/* Header for MISS packet */
struct icp_miss_s {
    char *m_url;		/* variable sized URL data */
};
typedef struct icp_miss_s icp_miss_t;
#define ICP_MISS_SZ (sizeof(icp_miss_t))

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Header for ERROR packet */
struct icp_error_s {
    unsigned short e_code;	/* error code */
    char *e_msg;		/* variable sized string message */
};
typedef struct icp_error_s icp_error_t;
#define ICP_ERROR_SZ (sizeof(icp_error_t))

#define ICP_ERROR_MSGLEN	256	/* max size for string, incl '\0' */

/* Error Codes - These can come back in the response packet */
typedef enum {
    ICP_ERROR_INVALID,		/* invalid (not used) */
    ICP_ERROR_BADVERS,		/* version error */
    ICP_ERROR_BADURL,		/* bad URL */
    ICP_ERROR_BADFLAGS,		/* bad flags */
    ICP_ERROR_TIMEDOUT,		/* couldn't get data */
    ICP_ERROR_ACCESS,		/* authorization problem */
    ICP_ERROR_INTERNAL		/* cache server internal err */
} icp_error_code;

/* Header for SEND packet */
struct icp_send_s {
    u_num32 s_rhostid;		/* requestor host id */
    char *s_url;		/* variable sized url */
};
typedef struct icp_send_s icp_send_t;
#define ICP_SEND_SZ (sizeof(icp_send_t))


/* Header for SENDA packet */
struct icp_senda_s {
    u_num32 sa_rhostid;		/* requestor host id */
    char *sa_url;		/* variable sized url */
};
typedef struct icp_senda_s icp_senda_t;
#define ICP_SENDA_SZ (sizeof(icp_senda_t))


/* Header for DATABEGIN packet */
struct icp_datab_s {
    u_num32 db_ttl;		/* time to live */
    u_num32 db_ts;		/* timestamp when gotten from owner */
    u_num32 db_size;		/* size of object if known */
    char *db_data;		/* variable sized data */
};
typedef struct icp_datab_s icp_datab_t;
#define ICP_DATAB_SZ (sizeof(icp_datab_t))


/* Header for DATA packet */
struct icp_data_s {
    u_num32 d_offset;		/* offset into object for d_data  */
    char *d_data;		/* variable sized data */
};
typedef struct icp_data_s icp_data_t;
#define ICP_DATA_SZ (sizeof(icp_databe_t))


/* ICP message type. */
struct icp_message_s {
    icp_common_t header;
    union {
	icp_query_t query;
	icp_hit_t hit;
	icp_miss_t miss;
	icp_error_t error;
	icp_send_t send;
	icp_senda_t senda;
	icp_datab_t data_begin;
	icp_data_t data;	/* Shared between DATA and DATAEND. */
    } op;
};
typedef struct icp_message_s icp_message_t;
#define ICP_MESSAGE_SZ (sizeof(icp_message_t))

/* Version */
#define ICP_VERSION_1		1	/* version 1 */
#define ICP_VERSION_2		2	/* version 2 */
#define ICP_VERSION_CURRENT	ICP_VERSION_2	/* current version */



extern int icp_proto_errno;	/* operation errors */
extern int icp_query _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, struct in_addr rid, char *url, char *hostname, int port));
extern int icp_hit _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, u_num32 size));
extern int icp_miss _PARAMS((int sock, u_num32 reqnum, u_num32 * auth));
extern int icp_error _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, unsigned short errcode, char *errstr));
extern int icp_send _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, struct in_addr rid, char *url));
extern int icp_databegin _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, u_num32 ttl, u_num32 timestamp, char *data));
extern int icp_data _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, char *data));
extern int icp_dataend _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, char *data));

typedef struct _protodispatch_data {
    int fd;
    char *url;
    struct sentry *entry;
    char host[HARVESTHOSTNAMELEN + 1];
    int inside_firewall;
    int direct_fetch;
    int source_ping;
    int cachable;
    int n_edges;
    struct _edge *single_parent;
} protodispatch_data;

extern int proto_cachable _PARAMS((char *url, char *type, char *mime_hdr));

#define DIRECT_NO    0
#define DIRECT_MAYBE 1
#define DIRECT_YES   2

#endif /* PROTO_H */
