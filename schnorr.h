#ifndef SCHNORR_H
#define SCHNORR_H
#include "utils.h"

typedef struct 
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *y;
} Schnorr_pub_key;

typedef struct 
{
    BIGNUM *m;
    BIGNUM *e;
    BIGNUM *s;
} Schnorr_signed_msg;

int gen_schnorr_pub_key(Schnorr_pub_key *pubkey, BIGNUM **privkey);
int schnorr_sign(BIGNUM *message, Schnorr_pub_key *pubkey, 
                 BIGNUM *privkey, Schnorr_signed_msg **signature);
int schnorr_verify(Schnorr_pub_key *pubkey, Schnorr_signed_msg *signature);
Schnorr_pub_key *Schnorr_pub_key_new();
Schnorr_signed_msg *Schnorr_signed_msg_new();
void Schnorr_pub_key_cleanup(Schnorr_pub_key *k);
void Schnorr_signed_msg_cleanup(Schnorr_signed_msg *s);

int schnorr_prepare(Schnorr_pub_key *pubkey, BIGNUM *privkey, BIGNUM **r, BIGNUM **k);
int gen_blind_signature_keys(Schnorr_pub_key *pubkey, BIGNUM **privkey);
int schnorr_commit(Schnorr_pub_key *pubkey, BIGNUM *privkey, 
                   BIGNUM *r, uint8_t *message, uint32_t message_len, BIGNUM **e);
int schnorr_blind_sign(Schnorr_pub_key *pubkey, BIGNUM *privkey, 
                       BIGNUM *e,  BIGNUM *k, BIGNUM **s);
int schnorr_blind_finish(Schnorr_pub_key *pubkey, BIGNUM *privkey, 
                         BIGNUM *e, BIGNUM *s, BIGNUM *r);

#endif // SCHNORR_H