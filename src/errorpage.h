typedef enum {
    ERR_NONE,
    ERR_READ_TIMEOUT,
    ERR_LIFETIME_EXP,
    ERR_NO_CLIENTS_BIG_OBJ,
    ERR_READ_ERROR,
    ERR_CLIENT_ABORT,
    ERR_CONNECT_FAIL,
    ERR_INVALID_URL,
    ERR_NO_FDS,
    ERR_DNS_FAIL,
    ERR_NOT_IMPLEMENTED,
    ERR_CANNOT_FETCH,
    ERR_NO_RELAY,
    ERR_DISK_IO,
    ERR_URL_BLOCKED,
    ERR_MAX
} error_t;

void cached_error_entry _PARAMS((StoreEntry *, error_t, char *));
char *cached_error_url _PARAMS((char *, error_t, char *));
