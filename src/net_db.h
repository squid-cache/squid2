
typedef struct _net_db {
    char network[16];
    int n;
    double hops;
    double rtt;
    time_t last;
    time_t expires;
    int link_count;
} netdbEntry;
