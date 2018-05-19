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
} ELG_enc_msg;

typedef struct 
{
    BIGNUM *m;
    BIGNUM *r;
    BIGNUM *s;
} ELG_signed_msg;

int gen_elg_key_pair(uint32_t key_size, ELG_key_pair *key);

int encrypt(ELG_key_pair *key, BIGNUM *message, ELG_enc_msg **encrypted);
int decrypt(ELG_key_pair *key, ELG_enc_msg *encrypted, BIGNUM **decrypted);
int sign(ELG_key_pair *key, uint8_t *message, uint32_t message_len, ELG_signed_msg **signed_msg);
int verify(ELG_key_pair *key, ELG_signed_msg *signed_msg);

ELG_enc_msg *ELG_enc_msg_new();
ELG_signed_msg *ELG_signed_msg_new();
void ELG_key_pair_cleanup(ELG_key_pair *key);
void ELG_enc_msg_cleanup(ELG_enc_msg *m);
void ELG_signed_msg_cleanup(ELG_signed_msg *m);
#endif // EL_GAMAL_H