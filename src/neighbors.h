
/*  $Id$ */

#ifndef NEIGHBORS_H
#define NEIGHBORS_H

/* Labels for hierachical log file */
/* put them all here for easier reference when writing a logfile analyzer */

typedef enum {
    HIER_NONE,
    HIER_DIRECT,
    HIER_NEIGHBOR_HIT,
    HIER_PARENT_HIT,
    HIER_SINGLE_PARENT,
    HIER_FIRSTUP_PARENT,
    HIER_NO_PARENT_DIRECT,
    HIER_FIRST_PARENT_MISS,
    HIER_LOCAL_IP_DIRECT,
    HIER_FIREWALL_IP_DIRECT,
    HIER_DEAD_PARENT,
    HIER_DEAD_NEIGHBOR,
    HIER_REVIVE_PARENT,
    HIER_REVIVE_NEIGHBOR,
    HIER_NO_DIRECT_FAIL,
    HIER_SOURCE_FASTEST,
    HIER_UDP_HIT_OBJ,
    HIER_MAX
} hier_code;

typedef enum {
    EDGE_SIBLING,
    EDGE_PARENT
} neighbor_t;

/* Mark a neighbor cache as dead if it doesn't answer this many pings */
#define HIER_MAX_DEFICIT  20

typedef struct _dom_list {
    char *domain;
    int do_ping;		/* boolean */
    struct _dom_list *next;
} dom_list;

#define EDGE_MAX_ADDRESSES 10
#define RTT_AV_FACTOR      1000
struct _edge {
    char *host;
    neighbor_t type;
    struct sockaddr_in in_addr;
    int neighbor_up;		/* 0 if no, 1 if yes */
    struct {
	int pings_sent;
	int pings_acked;
	int ack_deficit;
	int fetches;
	int rtt;
	int counts[ICP_OP_END];
    } stats;

    u_short icp_port;
    u_short http_port;
    icp_common_t header;
    dom_list *domains;
    struct _acl_list *acls;
    int proxy_only;
    int weight;
    time_t last_fail_time;	/* detect down dumb caches */
    struct in_addr addresses[10];
    int n_addresses;
    struct _edge *next;
};

typedef struct {
    int n;
    int n_parent;
    int n_neighbor;
    edge *edges_head;
    edge *edges_tail;
    edge *first_ping;
    int fd;
} neighbors;

struct neighbor_cf {
    char *host;
    char *type;
    int http_port;
    int icp_port;
    int proxy_only;
    int weight;
    dom_list *domains;
    struct _acl_list *acls;
    struct neighbor_cf *next;
};

extern edge *getFirstEdge _PARAMS((void));
extern edge *getFirstUpParent _PARAMS((request_t *));
extern edge *getNextEdge _PARAMS((edge *));
extern edge *getSingleParent _PARAMS((request_t *, int *n));
extern int neighborsUdpPing _PARAMS((protodispatch_data *));
extern void neighbors_cf_domain _PARAMS((char *, char *));
extern void neighbors_cf_acl _PARAMS((char *, char *));
extern neighbors *neighbors_create _PARAMS(());
extern void hierarchy_log_append _PARAMS((char *, hier_code, int, char *));
extern void neighborsUdpAck _PARAMS((int, char *, icp_common_t *, struct sockaddr_in *, StoreEntry *, char *, int));
extern void neighbors_cf_add _PARAMS((char *, char *, int, int, int, int));
extern void neighbors_init _PARAMS((void));
extern void neighbors_open _PARAMS((int));
extern void neighbors_rotate_log _PARAMS((void));
extern void neighborsDestroy _PARAMS((void));

extern char *hier_strings[];

#endif
