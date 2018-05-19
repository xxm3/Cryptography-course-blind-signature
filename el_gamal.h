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
    BIGNUM *a;
    BIGNUM *b;
} ELG_encrypted_msg;

int generate_key_pair(uint32_t key_size, ELG_key_pair *key);
int encrypt(ELG_key_pair *key, BIGNUM *message, ELG_encrypted_msg **encrypted);
int decrypt(ELG_key_pair *key, ELG_encrypted_msg *encrypted, BIGNUM **decrypted);
void ELG_key_pair_cleanup(ELG_key_pair *key);
ELG_encrypted_msg *ELG_enc_msg_new();
void ELG_enc_msg_cleanup(ELG_encrypted_msg *m);
#endif // EL_GAMAL_H