extern void clientAccessCheck _PARAMS((icpStateData *,
	void              (*)_PARAMS((icpStateData *, int))));
extern void clientAccessCheckDone _PARAMS((icpStateData *, int answer));
extern int icpProcessExpired _PARAMS((int fd, icpStateData *));

#if USE_PROXY_AUTH
char *proxyAuthenticate(char *headers);
#endif /* USE_PROXY_AUTH */
