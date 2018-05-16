#include "el_gamal.h"
#include <stdint.h>
#include <stdio.h>
#include "utils.h"

static const uint8_t rnd_seed[] = "string to make the random number generator";
enum sizes {P_SIZE_1024 = 1024};
static int generate_key_pair()
{
    int ret = 0;
    BIGNUM *p, *g = NULL, *pmin1 = NULL;
    if ((p = BN_new()) == NULL)
    {
        printf("Failed to allocate memory\n");
        return ret;
    }

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    if (!BN_generate_prime_ex(p, 14, 1, NULL, NULL, NULL)) //test with small number
    {
        printf("Failed to generate prime number\n");
        goto err;
    }

    if ((g = BN_new()) == NULL)
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    if ((pmin1 = BN_dup(p)) == NULL)
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    BN_sub_word(pmin1, 1);
    
    do 
    {
        if (!BN_add_word(g, 1))
        {
            printf("Failed to BN_add_word\n");
            goto err;
        }
    } 
    while (is_primitive_root(g, p, pmin1, NULL));

    // char *num = BN_bn2dec(p);
    // printf("p=%s\n", num);
    ret = 1;
err:
    if (!ret)
    {
        BN_free(pmin1);
        BN_free(p);
        BN_free(g);
    }    
    
    return ret;
}

int main()
{
    generate_key_pair();
    return 0;
}