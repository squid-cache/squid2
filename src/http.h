

extern int httpCachable _PARAMS((char *, int, char *));
extern int proxyhttpStart _PARAMS((edge *, char *, StoreEntry *));
extern int httpStart _PARAMS((int, char *, int, char *, StoreEntry *));

typedef enum {
    METHOD_NONE,
    METHOD_GET,
    METHOD_POST,
    METHOD_HEAD
} RequestMethod;

#define HTTP_REPLY_FIELD_SZ 128
struct _http_reply {
    double version;
    int code;
    int content_length;
    int hdr_sz;
    char content_type[HTTP_REPLY_FIELD_SZ];
    char date[HTTP_REPLY_FIELD_SZ];
    char expires[HTTP_REPLY_FIELD_SZ];
    char last_modified[HTTP_REPLY_FIELD_SZ];
    char user_agent[HTTP_REPLY_FIELD_SZ << 2];
};

extern char *RequestMethodStr[];
