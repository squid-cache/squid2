


enum {
    FD_NONE,
    FD_LOG,
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_UNKNOWN
};

enum {
    FD_READ,
    FD_WRITE
};

enum {
    FD_CLOSE,
    FD_OPEN
};

#define FD_AT_EOF		0x01
#define FD_CLOSE_REQUEST	0x02
#define FD_WRITE_DAEMON		0x04
#define FD_WRITE_PENDING	0x08

#define FD_DESC_SZ		64

typedef void PF _PARAMS((int, void *));
typedef void FILE_READ_HD(int fd, const char *buf, int size, int errflag, void *
    data);
typedef void FILE_WRITE_HD(int, int, void *);
typedef void FILE_WALK_HD(int fd, int errflag, void *data);
typedef void FILE_WALK_LHD(int fd, const char *buf, int size, void *line_data);

typedef struct _dwrite_q {
    char *buf;
    int len;
    int cur_offset;
    struct _dwrite_q *next;
    void (*free) (void *);
} dwrite_q;


typedef struct fde {
    unsigned int type;
    unsigned int open;
    u_short local_port;
    u_short remote_port;
    char ipaddr[16];		/* dotted decimal address of peer */
    char desc[FD_DESC_SZ];
    int flags;
    int bytes_read;
    int bytes_written;

    struct {
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
    time_t timeout;
    void *timeout_data;
    void *lifetime_data;
    struct close_handler *close_handler;	/* linked list */
    time_t stall_until;		/* don't select for read until this time */
    CommWriteStateData *rwstate;	/* State data for comm_write */
} FD_ENTRY;

extern void fd_close _PARAMS((int fd));
extern void fd_open _PARAMS((int fd, unsigned int type, const char *));
extern void fd_note _PARAMS((int fd, const char *));
extern void fd_bytes _PARAMS((int fd, int len, unsigned int type));
extern void fdFreeMemory _PARAMS((void));

extern FD_ENTRY *fd_table;
extern const char *fdstatTypeStr[];
