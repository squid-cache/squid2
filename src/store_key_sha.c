#include "squid.h"

#if STORE_KEY_SHA

const char *
storeKeyText(const int *key)
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

const int *
storeKeyScan(const char *buf)
{
    static int digest[SHA_DIGEST_INTS];
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

const cache_key *
storeKeyPrivate(const char *url, method_t method, int num)
{
    static cache_key digest[SHA_DIGEST_INTS];
    SHA_INFO S;
    int n;
    char key_buf[MAX_URL + 100];
    assert(num > 0);
    debug(20, 3) ("storeKeyPrivate: '%s'\n", url);
    n = snprintf(key_buf, MAX_URL + 100, "%d %s %s",
	num,
	RequestMethodStr[method],
	url);
    sha_init(&S);
    sha_update(&S, key_buf, n);
    sha_final(&S);
    xmemcpy(digest, S.digest, SHA_DIGESTSIZE);
    return digest;
}

const cache_key *
storeKeyPublic(const char *url, method_t method)
{
    static cache_key digest[SHA_DIGEST_INTS];
    SHA_INFO S;
    int n;
    char key_buf[MAX_URL + 100];
    n = snprintf(key_buf, MAX_URL + 100, "%s %s",
	RequestMethodStr[method],
	url);
    sha_init(&S);
    sha_update(&S, key_buf, n);
    sha_final(&S);
    xmemcpy(digest, S.digest, SHA_DIGESTSIZE);
    return digest;
}

const cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = xmalloc(SHA_DIGESTSIZE);
    xmemcpy(dup, key, SHA_DIGESTSIZE);
    meta_data.store_keys += SHA_DIGESTSIZE;
    return dup;
}

void
storeKeyFree(const cache_key * key)
{
    xfree((void *) key);
    meta_data.store_keys -= SHA_DIGESTSIZE;
}

int
storeKeyHashBuckets(int nobj)
{
    if (nobj < 0x2000)
	return 0x2000;
    if (nobj < 0x4000)
	return 0x4000;
    if (nobj < 0x8000)
	return 0x8000;
    return 0x10000;
}

#endif /* STORE_KEY_SHA */
