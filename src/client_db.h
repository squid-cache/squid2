#ifndef CLIENT_DB_H
#define CLIENT_DB_H

void clientdbInit _PARAMS((void));
void clientdbUpdate _PARAMS((struct in_addr, log_type, u_short port));
int clientdbDeniedPercent _PARAMS((struct in_addr));
void clientdbDump _PARAMS((StoreEntry *));
extern int client_info_sz;

#endif /* CLIENT_DB_H */
