extern void clientAccessCheck(icpStateData *, void (*)(icpStateData *, int));
extern void clientAccessCheckDone(icpStateData *, int answer);
extern int icpProcessExpired(int fd, icpStateData *);

#if USE_PROXY_AUTH
char *proxyAuthenticate(char *headers);
#endif /* USE_PROXY_AUTH */
