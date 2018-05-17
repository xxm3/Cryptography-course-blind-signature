#ifndef EL_GAMAL_H
#define EL_GAMAL_H
#include "utils.h"

enum sizes {P_SIZE_1024 = 1024};

typedef struct 
{
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *p;
    BIGNUM *g;
} ELG_key_pair;

typedef struct 
{
    BIGNUM *y;
    BIGNUM *p;
    BIGNUM *g;
} ELG_public_key;

int generate_key_pair(uint32_t key_size, ELG_key_pair *key);
int encrypt(ELG_key_pair *key, uint8_t *message, uint8_t *encrypted);
int decrypt(ELG_key_pair *key, uint8_t *encrypted, uint8_t *decrypted);

void ELG_key_pair_cleanup(ELG_key_pair *key);

#endif // EL_GAMAL_H