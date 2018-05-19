#include "el_gamal.h"
#include "schnorr.h"
static const uint8_t rnd_seed[] = "string to make the random number generator";

int gen_elg_key_pair(uint32_t key_size, ELG_key_pair *key)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p, *g = NULL, *pmin1 = NULL, *x = NULL, *y = NULL, *tmp;
    
    if (!(p = BN_new()))
    {
        printf("Failed to allocate memory\n");
        return -1;
    }

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    if (!BN_generate_prime_ex(p, key_size, 1, NULL, NULL, NULL))
    {
        printf("Failed to generate prime number\n");
        goto err;
    }

    if (!(g = BN_new()) ||
        !(pmin1 = BN_dup(p)))
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    if (!BN_sub_word(pmin1, 1))
    {
        printf("Failed to BN_sub_word\n");
        goto err;
    }

    if (!(ctx = BN_CTX_new()))
    {
        printf("Failed to allocate memory\n");
        goto err;
    }
    if (!BN_one(g))
        goto err;

    if (!primroot(g, p, pmin1, ctx)) // need optimization
        goto err;

    if (!(x = BN_new()))
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    if (!BN_pseudo_rand_range(x, pmin1))
    {
        printf("Failed to BN_pseudo_rand_range\n");
        goto err;
    }

    if (!(y = BN_new()))
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    if (!BN_mod_exp(y, g, x, p, ctx))
    {
        printf("Failed to BN_mod_exp\n");
        goto err; 
    }

    key->x = x;
    key->g = g;
    key->p = p;
    key->y = y;

err:
    if (ret == -1)
    {
        BN_free(p);
        BN_free(g);
        BN_free(x);
        BN_free(y);
    }    
    BN_CTX_free(ctx);
    BN_free(pmin1);
    return ret;
}

int encrypt(ELG_key_pair *key, BIGNUM *message, ELG_enc_msg **encrypted)
{
    int ret = 0;
    BIGNUM *k = NULL, *pmin1 = NULL, *a = NULL, *b = NULL;
    BN_CTX *ctx = NULL;

    if (!(k = BN_new()) || !(pmin1 = BN_dup(key->p)) ||
        !(a = BN_new()) || !(b = BN_new()))
        goto err;
    
    if (!BN_sub_word(pmin1, 1))
        goto err;

    if (!BN_pseudo_rand_range(k, pmin1))
    {
        printf("Failed to BN_pseudo_rand_range\n");
        goto err;
    }

    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!BN_mod_exp((*encrypted)->a, key->g, k, key->p, ctx))
        goto err;
   
    if (!BN_mod_exp(b, key->y, k, key->p, ctx))
        goto err;

    if (!BN_mod_mul((*encrypted)->b, b, message, key->p, ctx))
    {
        ret = 0;
        goto err;
    }       
   
    ret = 1;
err:
    BN_free(k);
    BN_free(a);
    BN_free(b);
    BN_free(pmin1);
    BN_CTX_free(ctx);
    return ret;
}

int decrypt(ELG_key_pair *key, ELG_enc_msg *encrypted, BIGNUM **decrypted)
{
    int ret = 0;
    BIGNUM *tmp;
    BN_CTX *ctx;
   
    if (!(tmp = BN_new()) || !(ctx = BN_CTX_new()))
        goto err;

    if (!BN_mod_exp(tmp, encrypted->a, key->x, key->p, ctx))
        goto err;

    if (!BN_mod_inverse(tmp, tmp, key->p, ctx))
        goto err;    
    
    if (!BN_mod_mul(*decrypted, tmp, encrypted->b, key->p, ctx))
        goto err; 

    ret = 1; 
err:
    BN_free(tmp);
    BN_CTX_free(ctx);
    return ret;
}

int sign(ELG_key_pair *key, uint8_t *message, uint32_t message_len, ELG_signed_msg **signature)
{
    int ret = 0;
    BIGNUM *k = NULL, *pmin1 = NULL, *tmp = NULL, *r = NULL, *s = NULL, *inverse = NULL, *m = NULL;
    BN_CTX *ctx = NULL;
    uint8_t *digest = NULL;
    uint32_t digest_len;
    
    if (!(digest_len = generate_digest(message, message_len, &digest)))
        return 0;

    if (!(k = BN_new()) || !(pmin1 = BN_dup(key->p))|| !(tmp = BN_new()))
        goto err;

    if (!BN_sub_word(pmin1, 1))
        goto err;

    if (!(ctx = BN_CTX_new()))
        goto err;

    /* we should find such k in (1 < k < p-1) and gcd(k, p-1) = 1*/
    do 
    {
        if (!BN_pseudo_rand_range(k, pmin1))
        {
            printf("Failed to BN_pseudo_rand_range\n");
            goto err;
        }
        if (!BN_gcd(tmp, k, pmin1, ctx))
            goto err;
    }
    while(!BN_is_one(tmp));
    
    if (!(r = BN_new()))
        goto err;
    
    if (!BN_mod_exp(r, key->g, k, key->p, ctx))
        goto err;

    if (!BN_mod_mul(tmp, key->x, r, pmin1, ctx))
        goto err;
    
    if (!(inverse = BN_new()))
        goto err;

    if (!BN_mod_inverse(inverse, k, pmin1, ctx))
        goto err;

    if (!(s = BN_new()) || !(m = BN_new()))
        goto err;

    if (!BN_bin2bn(digest, digest_len, m))
        goto err;

    if (!BN_mod_sub(s, m, tmp, pmin1, ctx))
        goto err;

     if (!BN_mod_mul(s, s, inverse, pmin1, ctx))
        goto err;
    
    (*signature)->m = m;
    (*signature)->r = r;
    (*signature)->s = s;
    
    ret = 1;
err:
    if (!ret)
    {   
        BN_free(r);
        BN_free(s);
        BN_free(m);
    }
    if (digest)
        OPENSSL_free(digest);
    BN_free(k);
    BN_free(pmin1);
    BN_free(tmp);
    BN_CTX_free(ctx);
    BN_free(inverse);
    return ret;
}

int verify(ELG_key_pair *key, ELG_signed_msg *signed_msg)
{
    int is_valid = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *pmin1 = NULL, *y = NULL, *r = NULL, *g = NULL;
    uint8_t *digest = NULL, *message = NULL;
    uint32_t digest_len = 0, message_len = BN_num_bytes(signed_msg->m);

    if (!(pmin1 = BN_dup(key->p)))
        return 0;

    if (BN_is_zero(signed_msg->r) || BN_is_zero(signed_msg->s))
    {
        printf("Signature is invalid\n");
        goto err;
    }

    if ((BN_cmp(key->p, signed_msg->r) != 1) || (BN_cmp(pmin1, signed_msg->s) != 1))
    {
        printf("Signature is invalid\n");
        goto err;
    }
    if (!(message = OPENSSL_malloc(message_len)))
        goto err;

    if (!(message_len = BN_bn2bin(signed_msg->m, message)))
        goto err;

    if (!(digest_len = generate_digest(message, message_len, &digest)))
        goto err;

    if (!(y = BN_new()) || !(r = BN_new()) || !(g = BN_new()))
        goto err;

    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!BN_mod_exp(y, key->y, signed_msg->r, key->p, ctx))
        goto err;
    
    if (!BN_mod_exp(r, signed_msg->r, signed_msg->s, key->p, ctx))
        goto err;

    if (!BN_mod_exp(g, key->g, signed_msg->m, key->p, ctx))
        goto err;

    if (!BN_mod_mul(y, y, r, key->p, ctx))
        goto err;
    
    if (BN_cmp(y, g) != 0)
        goto err;
        
    is_valid = 1;

err:
    BN_free(pmin1);
    BN_free(g);
    BN_CTX_free(ctx);
    BN_free(y);
    BN_free(r);
    if (digest)
        OPENSSL_free(digest);
    if (message)
        OPENSSL_free(message);
    return is_valid;
}

void ELG_key_pair_cleanup(ELG_key_pair *key)
{
    if (!key) return;
    
    BN_free(key->x);
    BN_free(key->y);
    BN_free(key->p);
    BN_free(key->g);
    OPENSSL_free(key);
}

ELG_enc_msg *ELG_enc_msg_new()
{
    ELG_enc_msg *m = OPENSSL_malloc(sizeof(ELG_enc_msg));
    if (!m) return NULL;
    m->a = BN_new();
    m->b = BN_new();
    if (!m->a || !m->b)
    {
        ELG_enc_msg_cleanup(m);
        return NULL;
    }
    return m;
}

void ELG_enc_msg_cleanup(ELG_enc_msg *m)
{
    if (!m) return;
    
    BN_free(m->a);
    BN_free(m->b);
    OPENSSL_free(m);
}

ELG_signed_msg *ELG_signed_msg_new()
{
    ELG_signed_msg *m = OPENSSL_malloc(sizeof(ELG_signed_msg));
    if (!m) return NULL;
    return m;
}

void ELG_signed_msg_cleanup(ELG_signed_msg *m)
{
    if (!m) return;
    
    BN_free(m->m);
    BN_free(m->r);
    BN_free(m->s);
    OPENSSL_free(m);
}