/* $Id$ */

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

#define BUF_TYPE_8K 	1
#define BUF_TYPE_MALLOC 2

typedef struct {
    StoreEntry *entry;
    request_t *request;
    char *req_hdr;
    int buf_type;		/* BUF_TYPE_8K or BUF_TYPE_MALLOC */
    char *reqbuf;		/* Holds the HTTP request being sent to
				 * the neighbor/origin server. */
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
    char *reply_hdr;
    int reply_hdr_state;
} HttpStateData;

extern int httpCachable _PARAMS((char *, int));
extern int proxyhttpStart _PARAMS((edge *, char *, StoreEntry *));
extern int httpStart _PARAMS((int, char *, request_t *, char *, StoreEntry *));
extern void httpParseHeaders _PARAMS((char *, struct _http_reply *));
extern void httpProcessReplyHeader _PARAMS((HttpStateData *, char *, int));
extern void httpReplyHeaderStats _PARAMS((StoreEntry *));
