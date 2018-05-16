#ifndef UTILS_H
#define UTILS_H
#include <openssl/bn.h>
#include <openssl/rand.h>
int is_primitive_root(BIGNUM *g, BIGNUM *p, BIGNUM *pmin1, BN_CTX *ctx);
#endif // UTILS_H