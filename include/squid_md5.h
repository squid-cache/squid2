#ifndef SQUID_MD5_H
#define SQUID_MD5_H

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if !USE_SQUID_MD5
/*
 * If Squid is compiled with OpenSSL then we use the MD5 routines
 * from there via some wrapper macros, and the rest of this file is ignored..
 */

#if USE_OPENSSL && HAVE_OPENSSL_MD5_H
#define USE_SQUID_MD5 0
#include <openssl/md5.h>

/* Hack to adopt Squid to the OpenSSL syntax */
#define SQUID_MD5_DIGEST_LENGTH MD5_DIGEST_LENGTH

#define SQUID_MD5Init MD5_Init
#define SQUID_MD5Update MD5_Update
#define SQUID_MD5Final MD5_Final
#define SQUID_MD5_CTX MD5_CTX

#elif USE_OPENSSL && !HAVE_OPENSSL_MD5_H
#error Cannot find OpenSSL MD5 headers

#elif (HAVE_SYS_MD5_H || HAVE_MD5_H) && HAVE_MD5INIT
/*
 * Solaris 10 provides MD5 as part of the system.
 */
#if HAVE_MD5_H
#include <md5.h>
#else
#include <sys/md5.h>
#endif

/*
 * They also define SQUID_MD5_CTX with different field names
 * fortunately we do not access it directly in the squid code.
 */

#define SQUID_MD5Init MD5Init
#define SQUID_MD5Update MD5Update
#define SQUID_MD5Final MD5Final
#define SQUID_MD5_CTX MD5_CTX

#ifdef MD5_DIGEST_LENGTH
#define SQUID_MD5_DIGEST_LENGTH MD5_DIGEST_LENGTH
#else
#define SQUID_MD5_DIGEST_LENGTH 16
#endif

#else /* No system MD5 code found */

/* Turn on internal MD5 code */
#undef  USE_SQUID_MD5
#define USE_SQUID_MD5 1
#endif
#endif

#if USE_SQUID_MD5

/*
 * This is the header file for the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to SQUID_MD5Init, call SQUID_MD5Update as
 * needed on buffers full of bytes, and then call SQUID_MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 *
 * Changed so as no longer to depend on Colin Plumb's `usual.h'
 * header definitions; now uses stuff from dpkg's config.h
 *  - Ian Jackson <ian@chiark.greenend.org.uk>.
 * Still in the public domain.
 *
 * Changed SQUID_MD5Update to take a void * for easier use and some other
 * minor cleanup. - Henrik Nordstrom <henrik@henriknordstrom.net>.
 * Still in the public domain.
 *
 */

#include "squid_types.h"

typedef struct MD5Context {
    uint32_t buf[4];
    uint32_t bytes[2];
    uint32_t in[16];
} SQUID_MD5_CTX;

void SQUID_MD5Init(struct MD5Context *context);
void SQUID_MD5Update(struct MD5Context *context, const void *buf, unsigned len);
void SQUID_MD5Final(uint8_t digest[16], struct MD5Context *context);
void SQUID_MD5Transform(uint32_t buf[4], uint32_t const in[16]);

#define SQUID_MD5_DIGEST_LENGTH         16

#endif /* USE_SQUID_MD5 */
#endif /* SQUID_MD5_H */
