
/*  $Id$ */

#ifndef _CACHE_CONFIG_H_
#define _CACHE_CONFIG_H_

typedef struct _wordlist {
    char *key;
    struct _wordlist *next;
} wordlist;

typedef struct _intlist {
    int i;
    struct _intlist *next;
} intlist;

typedef struct _relist {
    char *pattern;
    regex_t regex;
    struct _relist *next;
} relist;

typedef enum {
    IP_ALLOW,
    IP_DENY
} ip_access_type;

typedef struct _ip_acl {
    struct in_addr addr;
    struct in_addr mask;
    ip_access_type access;
    struct _ip_acl *next;
} ip_acl;

extern int httpd_accel_mode;
extern int emulate_httpd_log;
extern int zap_disk_store;
extern int unbuffered_logs;
extern wordlist *http_stoplist;
extern wordlist *gopher_stoplist;
extern wordlist *ftp_stoplist;
extern wordlist *bind_addr_list;
extern ip_acl *proxy_ip_acl;
extern ip_acl *accel_ip_acl;
extern ip_acl *manager_ip_acl;
extern char config_input_line[];
extern int config_lineno;
extern int DnsPositiveTtl;


/* cache_cf.c */
extern char *getAccelPrefix _PARAMS((void));
extern char *getAccessLogFile _PARAMS((void));
extern char *getAdminEmail _PARAMS((void));
extern char *getAppendDomain _PARAMS((void));
extern char *getCacheLogFile _PARAMS((void));
extern char *getDebugOptions _PARAMS((void));
extern char *getDnsProgram _PARAMS((void));
extern int getDnsChildren _PARAMS((void));
extern char *getEffectiveGroup _PARAMS((void));
extern char *getEffectiveUser _PARAMS((void));
extern char *getFtpOptions _PARAMS((void));
extern char *getFtpProgram _PARAMS((void));
extern char *getHierarchyLogFile _PARAMS((void));
extern char *getStoreLogFile _PARAMS((void));
extern char *getWaisRelayHost _PARAMS((void));
extern char *getPidFilename _PARAMS((void));
extern char *getVisibleHostname _PARAMS((void));
extern char *getFtpUser _PARAMS((void));
extern double getCacheHotVmFactor _PARAMS((void));
extern int getAccelWithProxy _PARAMS((void));
extern int getAsciiPortNum _PARAMS((void));
extern int getBehindFirewall _PARAMS((void));
extern int getCacheMemHighWaterMark _PARAMS((void));
extern int getCacheMemLowWaterMark _PARAMS((void));
extern int getCacheMemMax _PARAMS((void));
extern int getCacheNeighborObj _PARAMS((void));
extern int getCacheSwapHighWaterMark _PARAMS((void));
extern int getCacheSwapLowWaterMark _PARAMS((void));
extern int getCacheSwapMax _PARAMS((void));
extern int getCleanRate _PARAMS((void));
extern int getClientLifetime _PARAMS((void));
extern int getDnSChildren _PARAMS((void));
extern int getMaxRequestSize _PARAMS((void));
extern int getFtpMax _PARAMS((void));
extern int getFtpTTL _PARAMS((void));
extern int getGopherMax _PARAMS((void));
extern int getGopherTTL _PARAMS((void));
extern int getHttpMax _PARAMS((void));
extern int getHttpTTL _PARAMS((void));
extern int getLogfileRotateNumber _PARAMS((void));
extern int getNegativeTTL _PARAMS((void));
extern int getNegativeDNSTTL _PARAMS((void));
extern int getQuickAbort _PARAMS((void));
extern int getReadTimeout _PARAMS((void));
extern int getSourcePing _PARAMS((void));
extern int getStallDelay _PARAMS((void));
extern int getUdpPortNum _PARAMS((void));
extern int getWaisRelayPort _PARAMS((void));
extern int ip_acl_match _PARAMS((struct in_addr, ip_acl *));

extern int parseConfigFile _PARAMS((char *file_name));
extern int setAsciiPortNum _PARAMS((int));
extern int setCacheSwapMax _PARAMS((int size));
extern int setUdpPortNum _PARAMS((int));
extern ip_access_type ip_access_check _PARAMS((struct in_addr, ip_acl *));
extern int getWAISMax _PARAMS((void));
extern int getConnectTimeout _PARAMS((void));
extern char *getAnnounceHost _PARAMS((void));
extern int getAnnouncePort _PARAMS((void));
extern char *getAnnounceFile _PARAMS((void));
extern int getAnnounceRate _PARAMS((void));
wordlist *getHttpStoplist _PARAMS((void));
wordlist *getFtpStoplist _PARAMS((void));
wordlist *getGopherStoplist _PARAMS((void));
wordlist *getLocalDomainList _PARAMS((void));
wordlist *getCacheDirs _PARAMS((void));
wordlist *getInsideFirewallList _PARAMS((void));
wordlist *getBindAddrList _PARAMS((void));
extern void wordlistDestroy _PARAMS((wordlist **));
extern void intlistDestroy _PARAMS((intlist **));


extern char w_space[];

#endif /* ndef  _CACHE_CONFIG_H_ */
