
extern int icmp_sock;

extern void icmpOpen __P((void));
extern void icmpClose __P((void));
void icmpPing __P((struct in_addr to));
void icmpSourcePing __P((struct in_addr to, icp_common_t *, char *url));
void icmpDomainPing __P((struct in_addr to, char *domain));
