/*  $Id$ */

#ifndef PROTO_H
#define PROTO_H

#define ICP_AUTH_SIZE (2)	/* size of authenticator field */
struct icp_common_s {
    unsigned char opcode;	/* opcode */
    unsigned char version;	/* version number */
    unsigned short length;	/* total length (bytes) */
    u_num32 reqnum;		/* req number (req'd for UDP) */
    u_num32 auth[ICP_AUTH_SIZE];	/* authenticator (future) */
    u_num32 shostid;		/* sender host id */
};

#define ICP_COMMON_SZ (sizeof(icp_common_t))
#define ICP_HDR_SZ (sizeof(icp_common_t)+sizeof(u_num32))
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
    ICP_OP_DECHO,		/* echo from dumb cache (sv<-dc) */
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
    StoreEntry *entry;
    request_t *request;
    int inside_firewall;
    int direct_fetch;
    int source_ping;
    int cachable;
    int n_edges;
    struct _edge *single_parent;
} protodispatch_data;

extern int proto_cachable _PARAMS((char *url, int method));
extern int protoDispatch _PARAMS((int, char *, StoreEntry *, request_t *));
extern int protoUndispatch _PARAMS((int, char *, StoreEntry *, request_t *));
extern int getFromDefaultSource _PARAMS((int, StoreEntry *));
extern int getFromCache _PARAMS((int, StoreEntry *, edge *, request_t *));

#define DIRECT_NO    0
#define DIRECT_MAYBE 1
#define DIRECT_YES   2

#endif /* PROTO_H */
