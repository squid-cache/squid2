#if !SNMP_CONFIG_H
#define SNMP_CONFIG_H 1

/* viewTypes */
#define VIEWINCLUDED    1
#define VIEWEXCLUDED    2

int create_view(char **);
int create_user(char **);
int create_community(char **);
void tokenize(char *, char **, int);

typedef struct _viewEntry {
    char viewName[32];
    int viewIndex;
    int viewType;
    int viewSubtreeLen;
    oid viewSubtree[32];
    struct _viewEntry *next;
} viewEntry;

typedef struct _communityEntry {
    char name[64];
    int readView;
    int writeView;
    struct _communityEntry *next;
} communityEntry;

typedef struct _usecEntry {
    u_char userName[32];
    int userLen;
    int qoS;
    u_char authKey[16];
    u_char privKey[16];
    int noauthReadView;
    int noauthWriteView;
    int authReadView;
    int authWriteView;
    struct _usecEntry *next;
} usecEntry;

#endif
