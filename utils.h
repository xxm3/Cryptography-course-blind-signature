#ifndef UTILS_H
#define UTILS_H
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* check is g is a primitive root modulo the odd prime p */
/* returns 0 if not a prim root, 1 if is, -1 on error */
/* doesn't clean up on error, but should */
/* we do not check that p is an odd prime */
/* pminusone should be p-1, we don't check */
int primroot(BIGNUM *g, BIGNUM *p, BIGNUM *pminusone, BN_CTX *ctx);

void print_bn(BIGNUM *n, char *in);
uint32_t generate_digest(const uint8_t *message, uint32_t message_len, uint8_t **digest);
#endif // UTILS_H