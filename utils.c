#include "utils.h"

static int is_prime(BIGNUM *p, BN_CTX *ctx)
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
    while((test = is_prime(p, ctx)) == 0);
    
    if (test == -1) 
    {
        printf("Failed to check if p is prime\n");
        return 0;
    }
    else return 1;
}

static int is_primroot(BIGNUM *g, BIGNUM *p, BIGNUM *pmin1, BN_CTX *ctx)
{
    BIGNUM *temp_q, *temp_r, *temp_d;
    int ret = 1; /*assume we have a generator */
    
    if (!(temp_r = BN_new()) ||
        !(temp_q = BN_new()) ||
        !(temp_d = BN_new())) 
    {
        ret = -1;
        goto err;
    }

    if (!BN_mod(temp_r, g, p, ctx)) 
        return -1;

    /* do check if g is zero mod p */
    if (BN_is_zero(temp_r))
        return 0;
  
    if (!BN_set_word(temp_q, 2)) 
        return -1;

    do
    {
        if (!BN_div(temp_d, temp_r, pmin1, temp_q, ctx))
    	    return -1;

        if (BN_is_zero(temp_r))
	    {
	        if (!BN_mod_exp(temp_r, g, temp_d, p, ctx))
	           return -1;
            /* if we got one as a small power of g, then g is not a primitive root */
	        if (BN_is_one(temp_r)) ret = 0;
	    }

        if (!nextprime(temp_q, ctx)) 
	        return -1;
    }
    while((ret == 1) && (BN_cmp(temp_q, p) == -1));
  /* repeat until definitely not a generator or q is not less than p */ 

err:
    BN_free(temp_q);
    BN_free(temp_r);
    BN_free(temp_d);
    return ret;
}

int primroot(BIGNUM *g, BIGNUM *p, BIGNUM *pmin1, BN_CTX *ctx)
{
    int test;
    do {
        if (!BN_add_word(g, 1)) return 0;
    }while ((test = is_primroot(g, p, pmin1, ctx)) == 0);

    if (test == -1) return 0;
    else return 1;
}

void print_bn(BIGNUM *n, char *in)
{
    static char buff[] = "Value = ";
    char *str = BN_bn2dec(n);
    if (!in)
        in = buff;
    printf("%s %s\n", in, str);
    free(str);
}