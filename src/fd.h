

enum { 
    FD_NONE, 
    FD_LOG,
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_UNKNOWN
}; 

enum {
	FD_CLOSE,
	FD_OPEN
};

#define FD_AT_EOF		0x01
#define FD_CLOSE_REQUEST	0x02
#define FD_WRITE_DAEMON		0x04
#define FD_WRITE_PENDING	0x08

typedef struct fde {
    unsigned int type;
    unsigned int open;
    u_short local_port;
    u_short remote_port;
    char ipaddr[16];            /* dotted decimal address of peer */
    char ascii_note[FD_ASCII_NOTE_SZ];
    int flags;

    struct {
        char filename[SQUID_MAXPATHLEN];
        FILE_WRITE_HD *wrt_handle;
        void *wrt_handle_data;
        dwrite_q *write_q;
        dwrite_q *write_q_tail;
    } disk;
 
    PF *read_handler;
    void *read_data;
    PF *write_handler;
    void *write_data;
    PF *timeout_handler;
    time_t timeout_time;
    time_t timeout_delta;
    void *timeout_data;
    int lifetime;
    PF *lifetime_handler;
    void *lifetime_data;
    struct close_handler *close_handler;        /* linked list */
    time_t stall_until;         /* don't select for read until this time */
    RWStateData *rwstate;       /* State data for comm_write */
} FD_ENTRY;


extern FD_ENTRY *fd_table;

extern const char *fdstatTypeStr[];

