extern void clientAccessCheck(icpStateData *, void (*)__P((icpStateData *, int)));
extern void clientAccessCheckDone __P((icpStateData *, int answer));
extern int icpProcessExpired __P((int fd, icpStateData *));

#if USE_PROXY_AUTH
char *proxyAuthenticate(char *headers);
#endif /* USE_PROXY_AUTH */
