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

#ifndef PROTO_H
#define PROTO_H

#define ICP_AUTH_SIZE (2)	/* size of authenticator field */
struct icp_common_s {
    unsigned char opcode;	/* opcode */
    unsigned char version;	/* version number */
    unsigned short length;	/* total length (bytes) */
    u_num32 reqnum;		/* req number (req'd for UDP) */
    u_num32 flags;
    u_num32 pad;
    /* u_num32 auth[ICP_AUTH_SIZE];     authenticator (old) */
    u_num32 shostid;		/* sender host id */
};

#define ICP_FLAG_HIT_OBJ 0x80000000ul

#define ICP_COMMON_SZ (sizeof(icp_common_t))
#define ICP_HDR_SZ (sizeof(icp_common_t)+sizeof(u_num32))
typedef enum {
    ICP_OP_INVALID,		/* 00 to insure 0 doesn't get accidently interpreted. */
    ICP_OP_QUERY,		/* 01 query opcode (cl->sv) */
    ICP_OP_HIT,			/* 02 hit (cl<-sv) */
    ICP_OP_MISS,		/* 03 miss (cl<-sv) */
    ICP_OP_ERR,			/* 04 error (cl<-sv) */
    ICP_OP_SEND,		/* 05 send object non-auth (cl->sv) */
    ICP_OP_SENDA,		/* 06 send object authoritative (cl->sv) */
    ICP_OP_DATABEG,		/* 07 first data, but not last (sv<-cl) */
    ICP_OP_DATA,		/* 08 data middle of stream (sv<-cl) */
    ICP_OP_DATAEND,		/* 09 last data (sv<-cl) */
    ICP_OP_SECHO,		/* 10 echo from source (sv<-os) */
    ICP_OP_DECHO,		/* 11 echo from dumb cache (sv<-dc) */
    ICP_OP_UNUSED0,		/* 12 */
    ICP_OP_UNUSED1,		/* 13 */
    ICP_OP_UNUSED2,		/* 14 */
    ICP_OP_UNUSED3,		/* 15 */
    ICP_OP_UNUSED4,		/* 16 */
    ICP_OP_UNUSED5,		/* 17 */
    ICP_OP_UNUSED6,		/* 18 */
    ICP_OP_UNUSED7,		/* 19 */
    ICP_OP_UNUSED8,		/* 20 */
    ICP_OP_RELOADING,		/* 21 access denied while reloading */
    ICP_OP_DENIED,		/* 22 access denied (cl<-sv) */
    ICP_OP_HIT_OBJ,		/* 23 hit with object data (cl<-sv) */
    ICP_OP_END			/* 24 marks end of opcodes */
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
#define ICP_VERSION_1		1
#define ICP_VERSION_2		2
#define ICP_VERSION_3		3
#define ICP_VERSION_CURRENT	ICP_VERSION_2

#if 0
extern int icp_proto_errno;	/* operation errors */
extern int icp_hit _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, u_num32 size));
extern int icp_miss _PARAMS((int sock, u_num32 reqnum, u_num32 * auth));
extern int icp_error _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, unsigned short errcode, char *errstr));
extern int icp_databegin _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, u_num32 ttl, u_num32 timestamp, char *data));
extern int icp_data _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, char *data));
extern int icp_dataend _PARAMS((int sock, u_num32 reqnum, u_num32 * auth, char *data));
#endif

typedef struct _protodispatch_data {
    int fd;
    char *url;
    StoreEntry *entry;
    request_t *request;
    int inside_firewall;
    int direct_fetch;
    int source_ping;
    int query_neighbors;
    int n_edges;
    struct _edge *single_parent;
#if DELAY_HACK
    int delay_fetch;
#endif
} protodispatch_data;

extern int protoDispatch _PARAMS((int, char *, StoreEntry *, request_t *));
extern void protoUnregister _PARAMS((int fd,
	StoreEntry *,
	request_t *,
	struct in_addr));
extern int getFromDefaultSource _PARAMS((int, StoreEntry *));
extern int protoStart _PARAMS((int, StoreEntry *, edge *, request_t *));
extern void protoCancelTimeout _PARAMS((int fd, StoreEntry *));

#define DIRECT_NO    0
#define DIRECT_MAYBE 1
#define DIRECT_YES   2

#endif /* PROTO_H */
