/* $Id$ */

/* Define if struct tm has tm_gmtoff member */
#undef HAVE_TM_GMTOFF

/* Define if struct mallinfo has mxfast member */
#undef HAVE_EXT_MALLINFO

/* Default FD_SETSIZE value */
#undef DEFAULT_FD_SETSIZE

/* Maximum number of open filedescriptors */
#undef SQUID_MAXFD

/* UDP send buffer size */
#undef SQUID_UDP_SO_SNDBUF

/* UDP receive buffer size */
#undef SQUID_UDP_SO_RCVBUF

/* TCP send buffer size */
#undef SQUID_TCP_SO_SNDBUF

/* TCP receive buffer size */
#undef SQUID_TCP_SO_RCVBUF

/* Host type from configure */
#undef CONFIG_HOST_TYPE

/* If we need to declare sys_errlist[] as external */
#undef NEED_SYS_ERRLIST

/* If gettimeofday is known to take only one argument */
#undef GETTIMEOFDAY_NO_TZP

/* If libresolv.a has been hacked to export _dns_ttl_ */
#undef LIBRESOLV_DNS_TTL_HACK

/* Define if struct ip has ip_hl member */
#undef HAVE_IP_HL

/* Define if your compiler supports prototyping */
#undef HAVE_ANSI_PROTOTYPES

/* Define if we should use GNU regex */
#undef USE_GNUREGEX

/*
 * setresuid() may be broken on some Linuxes
 */
#undef HAVE_SETRESUID
