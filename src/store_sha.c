#include "squid.h"

const char *
shaDigestText(const sha_digest * key)
{
    LOCAL_ARRAY(char, buf, 64);
    snprintf(buf, 64, "%08X-%08X-%08X-%08X-%08X",
	key[0],
	key[1],
	key[2],
	key[3],
	key[4]);
    return buf;
}

const sha_digest *
shaScanDigest(const char *buf)
{
    static sha_digest digest[SHA_DIGEST_INTS];
    sscanf(buf, "%08X-%08X-%08X-%08X-%08X",
	&digest[0],
	&digest[1],
	&digest[2],
	&digest[3],
	&digest[4]);
    return digest;
}

int
shaHashCmp(const void *a, const void *b)
{
    const int *A = a;
    const int *B = b;
    int i;
    for (i = 0; i < SHA_DIGEST_INTS; i++) {
	if (A[i] < B[i])
	    return -1;
	if (A[i] > B[i])
	    return 1;
    }
    return 0;
}

unsigned int
shaHashHash(const void *key, unsigned int n)
{
    const int *digest = key;
    return (digest[0] & (--n));
}
