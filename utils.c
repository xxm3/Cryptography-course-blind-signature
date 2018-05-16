#include "utils.h"
int is_primitive_root(BIGNUM *g, BIGNUM *p, BIGNUM *pmin1, BN_CTX *ctx)
{
    int ret = -1;
    BIGNUM *tmpq, *tmp_rem, *tmpd;
    tmp_rem = BN_new();
    tmpq = BN_new();
    tmpd = BN_new();
    if (!BN_mod(tmp_rem, g, p, NULL))
    {
        printf("Failed to BN_mod");
        goto err;
    }
    char *num = BN_bn2dec(g);
    printf("g=%s\n", num);
    num = BN_bn2dec(p);
    printf("p=%s\n", num);
    num = BN_bn2dec(tmp_rem);
    printf("tmp_rem=%s\n", num);
    num = BN_bn2dec(pmin1);
    printf("pmin1=%s\n", num);
    
    if (BN_is_zero(tmp_rem))
        return 0;
err:
    if (ret == -1)
    { 
        BN_free(tmp_rem);
        BN_free(tmpq);
        BN_free(tmpd);
    }
    return 0; // set to 1
}