#ifndef CLIENT_SIDE_H
#define CLIENT_SIDE_H

extern void clientAccessCheck(icpStateData *, void (*)_PARAMS((icpStateData *, int)));
extern void clientAccessCheckDone _PARAMS((icpStateData *, int answer));
extern int icpProcessExpired _PARAMS((int fd, icpStateData *));

#if USE_PROXY_AUTH
const char *proxyAuthenticate(const char *headers);
#endif /* USE_PROXY_AUTH */

#endif /* CLIENT_SIDE_H */
