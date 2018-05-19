#include "schnorr.h"
#include <string.h>
// rfc 3526 group 5; Typically a Schnorr group is used
const char *group_g = "2";
const char *group_p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" \
	                    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" \
	                    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" \
	                    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" \
                        "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

int gen_schnorr_pub_key(Schnorr_pub_key *pubkey, BIGNUM **privkey)
{
    int ret = 0;
    BN_CTX *ctx;

    if (!BN_pseudo_rand_range(*privkey, pubkey->q))
    {
        printf("Failed to BN_pseudo_rand_range\n");
        goto err;
    }

    if (!(ctx = BN_CTX_new()) || !(pubkey->y = BN_new()))
        goto err;

    if (!BN_mod_exp(pubkey->y, pubkey->g, *privkey, pubkey->p, ctx))
        goto err;

    ret = 1;
err:
    BN_CTX_free(ctx);
    if (!ret)
        BN_free(pubkey->y);

    return ret;
}

int schnorr_sign(BIGNUM *message, Schnorr_pub_key *pubkey, 
                 BIGNUM *privkey, Schnorr_signed_msg **signature)
{
    int ret = 0;
    BIGNUM *k = NULL, *r = NULL, *tmp;
    BN_CTX *ctx = NULL;
    uint8_t *digest = NULL, *m = NULL, *rstr = NULL;
    uint32_t digest_len, m_len, r_len;

    if (!(k = BN_new()))
        return 0;

    if (!BN_rand_range(k, pubkey->p))
        goto err;

    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!(r = BN_new()))
        goto err;
    
    if (!BN_mod_exp(r, pubkey->g, k, pubkey->p, ctx))
        goto err;
    
    if (!(m = (uint8_t *)OPENSSL_malloc(BN_num_bytes(message) + BN_num_bytes(r))))
        goto err;

    if (!(rstr = (uint8_t *)OPENSSL_malloc(BN_num_bytes(r))))
        goto err;
    
    if (!(m_len = BN_bn2bin(message, m)))
        goto err;
    
    if (!(r_len = BN_bn2bin(r, rstr)))
        goto err;

    memcpy((void*)m + m_len, (void *)rstr, r_len);

    if (!(digest_len = generate_digest(m, r_len+m_len, &digest)))
        goto err;
    
    if (!((*signature)->e = BN_new()))
        goto err;

    if (!BN_bin2bn(digest, digest_len, (*signature)->e))
        goto err;

    if (!(tmp = BN_new()))
        goto err;

    if (!BN_mod_mul(tmp, privkey, (*signature)->e, pubkey->q, ctx))
        goto err;

    if (!((*signature)->s = BN_new()))
        goto err;

    if (!BN_mod_sub((*signature)->s, k, tmp, pubkey->q, ctx))
        goto err;

    ret = 1;
err:
    if (m)
        OPENSSL_free(m);
    if (rstr)
        OPENSSL_free(rstr);
    if (digest)
        OPENSSL_free(digest); 
    BN_free(k);
    BN_free(r);
    BN_free(tmp);
    BN_CTX_free(ctx);
    return ret;
}

int schnorr_verify(Schnorr_pub_key *pubkey, Schnorr_signed_msg *signature)
{
    int is_valid = 0;
    BIGNUM *e = NULL, *r = NULL, *tmp = NULL, *tmp2 = NULL;
    BN_CTX *ctx = NULL;
    uint8_t *digest = NULL, *m = NULL, *rstr = NULL;
    uint32_t digest_len, m_len, r_len;

    if (!(tmp = BN_new()) || !(tmp2 = BN_new()))
        goto err;

    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!BN_mod_exp(tmp, pubkey->g, signature->s, pubkey->p, ctx))
        goto err;

    if (!BN_mod_exp(tmp2, pubkey->y, signature->e, pubkey->p, ctx))
        goto err;

    if (!(r = BN_new()))
        goto err;

    if (!BN_mod_mul(r, tmp, tmp2, pubkey->p, ctx))
        goto err;

    if (!(m = (uint8_t *)OPENSSL_malloc(BN_num_bytes(signature->m) + BN_num_bytes(r))))
        goto err;

    if (!(rstr = (uint8_t *)OPENSSL_malloc(BN_num_bytes(r))))
        goto err;
    
    if (!(m_len = BN_bn2bin(signature->m, m)))
        goto err;
    
    if (!(r_len = BN_bn2bin(r, rstr)))
        goto err;

    memcpy((void*)m + m_len, (void *)rstr, r_len);

    if (!(digest_len = generate_digest(m, r_len+m_len, &digest)))
        goto err;

    if (!(e = BN_new()))
        goto err;

    if (!BN_bin2bn(digest, digest_len, e))
        goto err;

    if (BN_cmp(e, signature->e) != 0)
        goto err;
        
    is_valid = 1;

err:
    OPENSSL_free(m);
    OPENSSL_free(rstr);
    OPENSSL_free(digest);
    BN_free(e);
    BN_free(r);
    BN_free(tmp);
    BN_free(tmp2);
    BN_CTX_free(ctx);
    return is_valid;  
}

int schnorr_prepare(Schnorr_pub_key *pubkey, BIGNUM *privkey, BIGNUM **r, BIGNUM **k)
{
    int ret = 0;
    BN_CTX *ctx = NULL;

    if (!BN_rand_range(*k, pubkey->p))
        goto err;

    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!(*r = BN_new()))
        goto err;

    if (!BN_mod_exp(*r, pubkey->g, *k, pubkey->p, ctx))
        goto err;
    
    ret = 1;
err:
    BN_CTX_free(ctx);
    return ret;
}

int schnorr_commit(Schnorr_pub_key *pubkey, BIGNUM *privkey, 
                   BIGNUM *r, uint8_t *message, uint32_t message_len, BIGNUM **e)
{
    int ret = 0;
    uint8_t *digest = NULL, *input;
    uint32_t digest_len;
    BIGNUM *a = NULL, *b = NULL, *tmp = NULL, *tmp2 = NULL, *r2;
    BN_CTX *ctx = NULL;

    if (!(a = BN_new()) || !(b = BN_new()))
        goto err;

    if (!BN_rand_range(a, pubkey->q) || !BN_rand_range(b, pubkey->q))
        goto err;

    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!(r2 = BN_new()))
        goto err;

    if (!(tmp = BN_new()))
        goto err;

    if (!BN_mod_exp(tmp, pubkey->g, a, pubkey->p, ctx))
        goto err;

    if (!BN_mod_mul(tmp, tmp, r, pubkey->p, ctx))
        goto err;

    if (!BN_mod_exp(r2, pubkey->y, b, pubkey->p, ctx))
        goto err;

    if (!BN_mod_mul(r2, r2, tmp, pubkey->p, ctx))
        goto err;

    if (!(input = (uint8_t *)OPENSSL_malloc(BN_num_bytes(r2) + message_len)))
        goto err;
    
    memcpy((void*)input, (void*)message, message_len);

    if (!BN_bn2bin(r2, input + message_len))
        goto err;

    if (!(digest_len = generate_digest(input, BN_num_bytes(r2) + message_len, &digest)))
        goto err;    

    if (!(*e = BN_new()))
        goto err;

    if (!BN_bin2bn(digest, digest_len, *e))
        goto err;

    if (!BN_mod_add(*e, *e, b, pubkey->q, ctx))
        goto err;
    
    ret = 1;
err:
    
    OPENSSL_free(digest);
    OPENSSL_free(input);
    BN_free(a);
    BN_free(b);
    BN_free(r2);
    BN_free(tmp);
    BN_CTX_free(ctx);
    return ret;
}

int schnorr_blind_sign(Schnorr_pub_key *pubkey, BIGNUM *privkey, 
                       BIGNUM *e,  BIGNUM *k, BIGNUM **s)
{
    int ret = 0;
    BIGNUM *tmp;
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    tmp = BN_new();
    if (!BN_mod_mul(tmp, e, privkey, pubkey->q, ctx))
        goto err;
    if (!BN_mod_add(*s, tmp, k, pubkey->q, ctx))
        goto err;
    ret = 1;
err:
    BN_CTX_free(ctx);
    BN_free(tmp);
    return ret;
}

int schnorr_blind_finish(Schnorr_pub_key *pubkey, BIGNUM *privkey, 
                         BIGNUM *e, BIGNUM *s, BIGNUM *r)
{
    int is_valid = 0;
    BIGNUM *tmp, *tmp2;
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    tmp = BN_new();
    tmp2 = BN_new();
    if (!BN_mod_exp(tmp, pubkey->y, e, pubkey->p, ctx))
        goto err;
    if (!BN_mod_inverse(tmp, tmp, pubkey->p, ctx))
        goto err;
    if (!BN_mod_exp(tmp2, pubkey->g, s, pubkey->p, ctx))
        goto err;
    if (!BN_mod_mul(tmp2, tmp2, tmp, pubkey->p, ctx))
        goto err;
    if (BN_cmp(tmp2, r) != 0)
        goto err;
    is_valid = 1;
err:
    BN_CTX_free(ctx);
    BN_free(tmp);
    BN_free(tmp2);
    return is_valid;
}

Schnorr_signed_msg *Schnorr_signed_msg_new()
{
    Schnorr_signed_msg *s = OPENSSL_malloc(sizeof(Schnorr_signed_msg));
    if (!s) return NULL;
    s->m = s->e = s->s = NULL;
    return s;
}

void Schnorr_signed_msg_cleanup(Schnorr_signed_msg *s)
{
    if (!s) return;
    
    BN_free(s->m);
    BN_free(s->s);
    BN_free(s->e);
    OPENSSL_free(s);
}

Schnorr_pub_key *Schnorr_pub_key_new()
{
    Schnorr_pub_key *k = OPENSSL_malloc(sizeof(Schnorr_pub_key));
    if (!k) return NULL;
    
    k->p = k->q = k->g = k->y = NULL;
    
    if (!(k->p = BN_new()) || !BN_hex2bn(&k->p, group_p))
        goto err;
    
    if (!(k->g = BN_new()) || !BN_hex2bn(&k->g, group_g))
        goto err;

    if (!(k->q = BN_new()))
        goto err;
    
    if (BN_rshift1(k->q, k->p) != 1)
        goto err;

    return k;

err:
    BN_free(k->p);
    BN_free(k->g);
    BN_free(k->q);
    OPENSSL_free(k);
    return NULL;
}

void Schnorr_pub_key_cleanup(Schnorr_pub_key *k)
{
    if (!k) return;
    
    BN_free(k->q);
    BN_free(k->p);
    BN_free(k->g);
    BN_free(k->y);
    OPENSSL_free(k);
}