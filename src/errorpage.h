/*
 * $Id$
 *
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *   Squid is the result of efforts by numerous individuals from the
 *   Internet community.  Development is led by Duane Wessels of the
 *   National Laboratory for Applied Network Research and funded by
 *   the National Science Foundation.
 * 
 */

extern void squid_error_entry _PARAMS((StoreEntry *, int, char *));
extern char *squid_error_url _PARAMS((char *, int, int, char *, int, char *));
extern char *squid_error_request _PARAMS((char *, int, char *, int));
extern void errorInitialize _PARAMS((void));
extern char *access_denied_msg _PARAMS((int, int, char *, char *));

extern char *tmp_error_buf;
