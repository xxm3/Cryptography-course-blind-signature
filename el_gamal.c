#include "el_gamal.h"
#include <stdint.h>
#include <stdio.h>

static const uint8_t rnd_seed[] = "string to make the random number generator";

int generate_key_pair(uint32_t key_size, ELG_key_pair *key)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p, *g = NULL, *pmin1 = NULL, *x = NULL, *y = NULL;
    
    if (!(p = BN_new()))
    {
        printf("Failed to allocate memory\n");
        return ret;
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
    
    do 
    {
        if (!BN_add_word(g, 1))
        {
            printf("Failed to BN_add_word\n");
            goto err;
        }
    } 
    while ((ret = is_primitive_root(g, p, pmin1)) == 0);
    if (ret == -1)
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

    // char *num = BN_bn2dec(x);
    // printf("x=%s\n", num);
    // num = BN_bn2dec(g);
    // printf("g=%s\n", num);
    // num = BN_bn2dec(y);
    // printf("y=%s\n", num);
    // num = BN_bn2dec(p);
    // printf("p=%s\n", num);
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

int main()
{
    ELG_key_pair *key;
    if (!(key = OPENSSL_malloc(sizeof(ELG_key_pair))))
    {
        printf("Failed to allocate memory\n");
        exit(0);
    }

    if (generate_key_pair(14, key) == -1)
    {
        printf("Failed to generate_key_pair\n");
        goto err;
    }
err:
    ELG_key_pair_cleanup(key);
    return 0;
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