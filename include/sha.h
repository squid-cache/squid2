#ifndef SHA_H
#define SHA_H

/* NIST Secure Hash Algorithm */
/* heavily modified by Uwe Hollerbach uh@alumni.caltech edu */
/* from Peter C. Gutmann's implementation as found in */
/* Applied Cryptography by Bruce Schneier */
/* This code is hereby placed in the public domain */

/* Useful defines & typedefs */

#define SHA_BLOCKSIZE		64
#define SHA_DIGESTSIZE		20

typedef struct {
    int digest[5];		/* message digest */
    int count_lo, count_hi;	/* 64-bit bit count */
    int data[16];		/* SHA data buffer */
    int local;			/* unprocessed amount in data */
} SHA_INFO;

extern void sha_init(SHA_INFO *);
extern void sha_update(SHA_INFO *, char *, int);
extern void sha_final(SHA_INFO *);

#endif /* SHA_H */
