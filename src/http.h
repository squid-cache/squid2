

extern int httpCachable _PARAMS((char *, int, char *));
extern int proxyhttpStart _PARAMS((edge *, char *, StoreEntry *));
extern int httpStart _PARAMS((int, char *, char *, char *, StoreEntry *));

typedef enum {
    METHOD_NONE,
    METHOD_GET,
    METHOD_POST,
    METHOD_HEAD
} RequestMethod;

extern char *RequestMethodStr[];
