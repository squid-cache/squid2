
/* $Id$ */

#ifndef COMM_H
#define COMM_H

#define COMM_OK		  (0)
#define COMM_ERROR	 (-1)
#define COMM_NO_HANDLER	 (-2)
#define COMM_NOMESSAGE	 (-3)
#define COMM_TIMEOUT	 (-4)

#define COMM_BLOCKING	  (0x0)
#define COMM_NONBLOCKING  (0x1)
#define COMM_INTERRUPT    (0x2)
#define COMM_DGRAM        (0x4)

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)
#define COMM_SELECT_EXCEPT (0x4)
#define COMM_SELECT_TIMEOUT (0x8)
#define COMM_SELECT_LIFETIME (0x10)

typedef int (*PF) _PARAMS((int, void *));

#define FD_ASCII_NOTE_SZ 64

typedef struct fde {
    int openned;		/* Set if we did a comm_connect.  Ignored for ftp_pipes. */
    int sender;			/* Set if this fd is connected to a client */
    int port;			/* Our tcp port # */
    char ipaddr[16];		/* dotted decimal address of peer */
    int (*handler) ();		/* Interrupt handler */
    StoreEntry *store_entry;

    /* Select handlers. */
    void * client_data;	/* App. data to associate w/ handled conn. */
    int (*read_handler) ();	/* Read  select handler. */
    void * read_data;		/* App. data to associate w/ handled conn. */
    int (*write_handler) ();	/* Write select handler. */
    void * write_data;		/* App. data to associate w/ handled conn. */
    int (*except_handler) ();	/* Except select handler. */
    void * except_data;	/* App. data to associate w/ handled conn. */
    int (*timeout_handler) ();	/* Timeout handler. */
    time_t timeout_time;	/* Allow 1-second granularity timeouts */
    time_t timeout_delta;	/* The delta requested */
    void * timeout_data;	/* App. data to associate w/ handled conn. */
    int (*lifetime_handler) ();	/* Lifetime expire handler. */
    void * lifetime_data;	/* App. data to associate w/ handled conn. */
    char ascii_note[FD_ASCII_NOTE_SZ];
    unsigned int comm_type;
    time_t stall_until;		/* don't select for read until this time reached */
} FD_ENTRY;

extern FD_ENTRY *fd_table;

extern char **getAddressList _PARAMS((char *name));
extern char *comm_client _PARAMS((int fd));
extern char *comm_peerhost _PARAMS((int fd));
extern char *fd_note _PARAMS((int fd, char *));
extern int commSetNonBlocking _PARAMS((int fd));
extern int comm_accept _PARAMS((int fd, struct sockaddr_in *, struct sockaddr_in *));
extern int comm_close _PARAMS((int fd));
extern int comm_connect _PARAMS((int sock, char *hst, int prt));
extern int comm_connect_addr _PARAMS((int sock, struct sockaddr_in *));
extern int comm_get_fd_lifetime _PARAMS((int fd));
extern int comm_get_select_handler _PARAMS((int fd, unsigned int type, PF *, void * *));
extern int comm_init _PARAMS((void));
extern int comm_init _PARAMS((void));
extern int comm_listen _PARAMS((int sock));
extern int comm_open _PARAMS((unsigned int io_type, int port, PF, char *note));
extern int comm_peerport _PARAMS((int fd));
extern int comm_pending _PARAMS((int fd, long sec, long usec));
extern int comm_port _PARAMS((int fd));
extern int comm_read _PARAMS((int fd, char *buf, int size));
extern int comm_select _PARAMS((long sec, long usec, time_t));
extern int comm_set_fd_lifetime _PARAMS((int fd, int lifetime));
extern int comm_set_select_handler _PARAMS((int fd, unsigned int type, PF, void *));
extern int comm_set_select_handler_plus_timeout _PARAMS((int, unsigned int, PF, void *, time_t));
extern int comm_sethandler _PARAMS((int fd, PF, void *));
extern int comm_udp_recv _PARAMS((int, char *, int, struct sockaddr_in *, int *));
extern int comm_udp_send _PARAMS((int fd, char *host, int port, char *buf, int len));
extern int comm_udp_sendto _PARAMS((int fd, struct sockaddr_in *, int size, char *buf, int len));
extern int comm_write _PARAMS((int fd, char *buf, int size));
extern int fd_of_first_client _PARAMS((StoreEntry *));
extern struct in_addr *getAddress _PARAMS((char *name));
extern void comm_set_stall _PARAMS((int, int));
extern int comm_get_fd_timeout _PARAMS((int fd));

extern int RESERVED_FD;

#endif /* COMM_H */
