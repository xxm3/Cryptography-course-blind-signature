#include "utils.h"

static int isprime(BIGNUM *p, BN_CTX *ctx)
{
    return BN_is_prime_fasttest_ex(p, BN_prime_checks, ctx, 1, NULL);
}

static int nextprime(BIGNUM *p, BN_CTX *ctx)
{
    int test;
    if (BN_mod_word(p, 2) == 0)
    {
        if (!BN_sub_word(p, 1))
        {
            printf("Failed to BN_sub_word\n");
            return 0;
        }
    }
    do
    {
        if (!BN_add_word(p, 2))
        {
            printf("Failed to BN_add_word\n");
            return 0;
        }  
    }
    while((test = isprime(p, ctx)) == 0);
    
    if (test == -1) 
    {
        printf("Failed to check if p is prime\n");
        return 0;
    }
    else return 1;
}

int is_primitive_root(BIGNUM *g, BIGNUM *p, BIGNUM *pmin1)
{
    int ret = -1;
    BIGNUM *tmpq, *tmp_rem, *tmpd;
    BN_CTX *ctx;
    if (!(ctx = BN_CTX_new()) ||
        !(tmp_rem = BN_new()) ||
        !(tmpq = BN_new())    ||
        !(tmpd = BN_new())      )
    {
        printf("Failed to allocate memory");
        goto err;
    }

    if (!BN_mod(tmp_rem, g, p, ctx))
    {
        printf("Failed to BN_mod");
        goto err;
    }
    
    if (BN_is_zero(tmp_rem))
        return 0;

    if (!BN_set_word(tmpq, 2))
    {
        printf("Failed to BN_set_word\n");
        return -1;
    }
    ret = 1;
    do
    {
        if (!BN_div(tmpd, tmp_rem, pmin1, tmpq, ctx))
        {
            printf("Failed to BN_div\n");
            return -1;
        }

        if (BN_is_zero(tmp_rem))
        {
            if (!BN_mod_exp(tmp_rem, g, tmpd, p, ctx))
            {
                printf("Failed to BN_mod_exp\n");
                return -1;
            }
            if (BN_is_one(tmp_rem)) ret = 0;
        }

        if (!nextprime(tmpq, ctx))
        {
            printf("Failed to find next prime\n");
            return -1;
        }    
    }
    while((ret == 1) && (BN_cmp(tmpq, p) == -1));

err:
    BN_free(tmp_rem);
    BN_free(tmpq);
    BN_free(tmpd);
    BN_CTX_free(ctx);
    return ret;
}
