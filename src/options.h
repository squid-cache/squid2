/*
 * $Id$
 */

/*
 * If you are upset that the cachemgr.cgi form comes up with the hostname
 * field blank, then define this.
 */
#undef CACHEMGR_HOSTNAME "getfullhostname()"

/*
 * If you want to use Squid's ICMP features (highly recommended!) then
 * define this.  When USE_ICMP is defined, Squid will send ICMP pings
 * to origin server sites.  This information is used in numerous ways:
 *         - Sent in ICP replies so neighbor caches know how close
 *           you are to the source.
 *         - For finding the closest instance of a URN.
 *         - With the 'test_reachability' option.  Squid will return
 *           ICP_OP_MISS_NOFETCH for sites which it cannot ping.
 */
#undef USE_ICMP 1

/*
 * David Luyer's Delay hack
 */
#undef DELAY_HACK 1

/*
 * If you want to log User-Agent request header values, define this.
 * By default, they are written to useragent.log in the Squid log
 * directory.
 */
#undef USE_USERAGENT_LOG 1

/*
 * A dangerous feature which causes Squid to kill its parent process
 * (presumably the RunCache script) upon receipt of SIGTERM or SIGINT.
 * Use with caution.
 */
#undef KILL_PARENT_OPT 1

/*
 * Normally Squid's ACL information is stored as singly-linked lists.
 * When matches are found, they are moved to the top of the list.
 * However, these options allow you to explore other searching structures
 * such as splay trees and binary trees.  Define only one of these.
 */
#undef USE_SPLAY_TREE 1
#undef USE_BIN_TREE 1

/* 
 * Squid frequently calls gettimeofday() for accurate timestamping.
 * If you are concerned that gettimeofday() is called too often, and
 * could be causing performance degradation, then you can define
 * ALARM_UPDATES_TIME and cause Squid's clock to be updated at regular
 * intervals (one second) with ALARM signals.
 */
#define ALARM_UPDATES_TIME 1

/*
 * Normally Squid uses URLs as cache keys, and these are kept in memory.
 * For large caches, this can become a significant use of memory.  Define
 * one of the options below for alternatives.  SHA (Secure Hash Algorithm)
 * is a 20-byte cryptographic digest.  MD5 is a 16-byte cryptographic
 * digest.  Calculating SHA digests requires more CPU, and MD5 digests
 * are slighly more likely to have collisions.
 */
#undef STORE_KEY_SHA 1
#undef STORE_KEY_MD5 1

/*
 * Define this for Aschyncronous I/O suport.
 */
#undef USE_ASYNC_IO 1

/*
 * Define this to include code which lets you specify access control
 * elements based on ethernet hardware addresses.  This code uses
 * functions found in 4.4 BSD derviations (e.g. FreeBSD, ?).
 */
#define USE_ARP_ACL 1
