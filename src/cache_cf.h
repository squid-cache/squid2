
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


/* Global Variables */
extern char *ConfigFile;	/* the whole thing */
extern char *DefaultConfigFile;
extern char *DefaultSwapDir;	/* argh */
extern char *cfg_filename;	/* Only the tail component of the path */
extern char config_input_line[];
extern char w_space[];
extern int DnsPositiveTtl;
extern int config_lineno;
extern int emulate_httpd_log;
extern int httpd_accel_mode;
extern int unbuffered_logs;
extern int zap_disk_store;
extern wordlist *bind_addr_list;
extern wordlist *ftp_stoplist;
extern wordlist *gopher_stoplist;
extern wordlist *http_stoplist;


/* Global Functions */
extern char *getAccelPrefix _PARAMS((void));
extern char *getAccessLogFile _PARAMS((void));
extern char *getAdminEmail _PARAMS((void));
extern char *getAnnounceFile _PARAMS((void));
extern char *getAnnounceHost _PARAMS((void));
extern char *getAppendDomain _PARAMS((void));
extern char *getCacheLogFile _PARAMS((void));
extern char *getDebugOptions _PARAMS((void));
extern char *getDnsProgram _PARAMS((void));
extern char *getEffectiveGroup _PARAMS((void));
extern char *getEffectiveUser _PARAMS((void));
extern char *getFtpOptions _PARAMS((void));
extern char *getFtpProgram _PARAMS((void));
extern char *getFtpUser _PARAMS((void));
extern char *getHierarchyLogFile _PARAMS((void));
extern char *getPidFilename _PARAMS((void));
extern char *getStoreLogFile _PARAMS((void));
extern char *getVisibleHostname _PARAMS((void));
extern char *getWaisRelayHost _PARAMS((void));
extern double getCacheHotVmFactor _PARAMS((void));
extern int getAccelWithProxy _PARAMS((void));
extern int getAnnounceRate _PARAMS((void));
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
extern int getConnectTimeout _PARAMS((void));
extern int getDnSChildren _PARAMS((void));
extern int getDnsChildren _PARAMS((void));
extern int getFtpMax _PARAMS((void));
extern int getFtpTTL _PARAMS((void));
extern int getGopherMax _PARAMS((void));
extern int getGopherTTL _PARAMS((void));
extern int getHttpMax _PARAMS((void));
extern int getHttpTTL _PARAMS((void));
extern int getLogfileRotateNumber _PARAMS((void));
extern int getMaxRequestSize _PARAMS((void));
extern int getNegativeDNSTTL _PARAMS((void));
extern int getNegativeTTL _PARAMS((void));
extern int getQuickAbort _PARAMS((void));
extern int getReadTimeout _PARAMS((void));
extern int getShutdownLifetime _PARAMS((void));
extern int getSourcePing _PARAMS((void));
extern int getStallDelay _PARAMS((void));
extern int getWAISMax _PARAMS((void));
extern int ip_acl_match _PARAMS((struct in_addr, ip_acl *));
extern int parseConfigFile _PARAMS((char *file_name));
extern int setCacheSwapMax _PARAMS((int size));
extern ip_access_type ip_access_check _PARAMS((struct in_addr, ip_acl *));
extern u_short getAccelPort _PARAMS((void));
extern u_short getAnnouncePort _PARAMS((void));
extern u_short getAsciiPortNum _PARAMS((void));
extern u_short getUdpPortNum _PARAMS((void));
extern u_short getWaisRelayPort _PARAMS((void));
extern u_short setAsciiPortNum _PARAMS((int));
extern u_short setUdpPortNum _PARAMS((int));
extern void intlistDestroy _PARAMS((intlist **));
extern void wordlistDestroy _PARAMS((wordlist **));
wordlist *getBindAddrList _PARAMS((void));
wordlist *getOutboundAddrList _PARAMS((void));
wordlist *getCacheDirs _PARAMS((void));
wordlist *getDnsTestnameList _PARAMS((void));
wordlist *getFtpStoplist _PARAMS((void));
wordlist *getGopherStoplist _PARAMS((void));
wordlist *getHttpStoplist _PARAMS((void));
wordlist *getInsideFirewallList _PARAMS((void));
wordlist *getLocalDomainList _PARAMS((void));


#endif /* ndef  _CACHE_CONFIG_H_ */
