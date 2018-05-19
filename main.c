#include "el_gamal.h"
#include "schnorr.h"
#include "utils.h"

int main()
{
    ELG_key_pair *key;
    BIGNUM *M, *decrypted, *privkey = NULL;
    ELG_enc_msg *encrypted;
    ELG_signed_msg *signature;
    Schnorr_signed_msg * schnorr_signature;
    Schnorr_pub_key *pubkey = NULL;

    uint8_t message[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint32_t message_len = sizeof(message);

    if (!(key = OPENSSL_malloc(sizeof(ELG_key_pair))))
    {
        printf("Failed to allocate memory\n");
        exit(0);
    }
    
    if (gen_elg_key_pair(10, key) == -1) //tested with small nums,
    {                                     //cuz primeroot is expensive in such implementation
        printf("Failed to gen_elg_key_pair\n");
        goto err;
    }

    if (!(M = BN_new()) || !(decrypted = BN_new()))
        goto err;
    
    if (!BN_bin2bn(message, message_len, M))
        goto err;

    if (!(encrypted = ELG_enc_msg_new()))
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    if (!encrypt(key, M, &encrypted))
    {
        printf("Failed to encrypt message\n");
        goto err;
    }

    if (!decrypt(key, encrypted, &decrypted)) // decrypted mod p = message mod p
    {
        printf("Failed to decrypt encrypted\n");
        goto err;
    }

    if (!(signature = ELG_signed_msg_new()))
    {
        printf("Failed to allocate memory\n");
        goto err;
    }

    if (!sign(key, message, message_len, &signature))
    {
        printf("Failed to sign message\n");
        goto err;
    }

    if (!verify(key, signature))
    {
        printf("Failed to verify signature\n");
        goto err;
    }

    if (!(pubkey = Schnorr_pub_key_new()) || !(privkey = BN_new()))
        goto err;

    if (!gen_schnorr_pub_key(pubkey, &privkey))
        goto err;
    
    if (!(schnorr_signature = Schnorr_signed_msg_new()))
        goto err;

    if (!schnorr_sign(M, pubkey, privkey, &schnorr_signature))
    {
        printf("Failed to schnorr_sign\n");
        goto err;
    }

    if (!(schnorr_signature->m = BN_dup(M)))
        goto err;

    if (!schnorr_verify(pubkey, schnorr_signature))
    {
        printf("Verification failed\n");
        goto err;
    }

err:
    ELG_key_pair_cleanup(key);
    BN_free(M);
    ELG_enc_msg_cleanup(encrypted);
    BN_free(decrypted);
    BN_free(privkey);
    ELG_signed_msg_cleanup(signature);
    Schnorr_pub_key_cleanup(pubkey);
    Schnorr_signed_msg_cleanup(schnorr_signature);
    return 0;
}