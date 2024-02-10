#include <relic/relic.h>
#include <relic/relic_err.h>
#include <relic/relic_pc.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */
#include <ascon/ascon.h> /* ASCON AEAD headers for symmetric encryption */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "params.h"

int gen_params(key_params_t *child, char *child_id, size_t id_len, 
        key_params_t *parent, bn_t master, g1_t rp)
{
    if (id_len < 0 ) {
        printf("Identity must be larger than 0 bytes\n");
        return -1;
    }

    int code = RLC_ERR;
    g1_t P; /* Unmapped Private key */
    bn_t N; /* Order of the group */
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */

    RLC_TRY {
        g1_null(P);
        g1_null(child->public_key);
        g1_null(child->k1);
        g2_null(child->k2);
        g1_null(child->Q);
        bn_null(child->secret);
        bn_null(N);


        /* Gen new secret number for the child to become a cluster head if 
         * needed */
        bn_new(N);
        pc_get_ord(N); /* Get the order of the group G1 */
        bn_rand_mod(child->secret, N); /* Gen random number in Zq */

        /* Hash Identity to gen pub key */

        mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
        const EVP_MD *EVP_sha3_256() /* Get the sha3 hash function */;

        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
        EVP_DigestUpdate(mdctx, child_id, strlen(child_id)); /* Hash the node ID */
        EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */

        g1_map(child->public_key, hash, sizeof(hash)); /* Map public key to G1 */

        /* Gen private key */ 
        g1_t temp;
        g1_null(temp);

        g1_mul(temp, child->public_key, master); /* temp = Pk * x */
        g1_add(P, parent->k1, temp); /* PkC = PkP + temp */
        g1_free(temp);

        /* Map private key to groups */
        g1_map(child->k1, (uint8_t *)P, sizeof(P));
        g1_mul(child->k1, child->k1, master);
        g2_map(child->k2, (uint8_t *)P, sizeof(P));
        g2_mul(child->k2, child->k2, master);

        /* Gen public perameter */ 
        g1_mul(child->Q, rp, master); /* Qx = Qx * x */

    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        g1_free(P);
        bn_free(N);
        EVP_MD_CTX_free(mdctx);
    }
    code = RLC_OK;

    return code;
}

int ascon_enc(uint8_t *buffer, char *plaintext, size_t plaintext_len,
        uint8_t *tag, size_t tag_len, uint8_t key[ASCON_AEAD128_KEY_LEN],
        uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    ascon_aead_ctx_t ctx;
    ascon_aead128a_init(&ctx, key, nonce);

    ascon_aead128_assoc_data_update(&ctx, (uint8_t *)associatedData, strlen(associatedData));

    size_t ciphertext_len = 0;

    ciphertext_len += ascon_aead128_encrypt_update(
            &ctx, buffer + ciphertext_len,
            (uint8_t*) plaintext, strlen(plaintext));

    ciphertext_len += ascon_aead128_encrypt_final(
            &ctx, buffer + ciphertext_len,
            tag, tag_len);

    /* Clean up */
    ascon_aead_cleanup(&ctx);

    return ciphertext_len;
}

int ascon_dec(uint8_t *buffer, size_t ciphertext_len, uint8_t *tag, size_t tag_len,
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    ascon_aead_ctx_t ctx;
    ascon_aead128a_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, (uint8_t *)associatedData, strlen(associatedData));

    size_t plaintext_len = 0;

    plaintext_len += ascon_aead128_decrypt_update(
            &ctx, buffer,
            buffer, ciphertext_len);

    bool is_tag_valid = false;

    plaintext_len += ascon_aead128_decrypt_final(
            &ctx, buffer + plaintext_len,
            &is_tag_valid, tag, tag_len);

    if (!is_tag_valid) {
        printf("Tag is invalid: %d\n", is_tag_valid);
        BIO_dump_fp(stdout, (const char *)tag, tag_len);
        return -1;
    }

    buffer[plaintext_len] = '\0'; // Null terminated, because it's text

    ascon_aead_cleanup(&ctx);

    return plaintext_len;
}

int aes_enc(unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len,
        unsigned char *key, unsigned char iv[16], size_t iv_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error creating context\n");
        return 1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        printf("Error initialising encryption\n");
        return 1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen ((char *)plaintext))) {
        printf("Error encrypting\n");
        return 1;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Error finalising\n");
        return 1;
    }
    ciphertext_len += len;

    /* Clean up */ 
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_dec(unsigned char *decryptedtext, unsigned char *ciphertext, int ciphertext_len,
        unsigned char *key, unsigned char iv[16], size_t iv_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */ 
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error creating context\n");
        return 1;
    }

    /* Initialise the decryption operation. */ 
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        printf("Error initialising decryption\n");
        return 1;
    }
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */ 
    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) {
        printf("Error decrypting\n");
        return 1;
    } 
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */ 
    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
        printf("Error finalising\n");
        return 1;
    }
    plaintext_len += len;

    /* Clean up */ 
    EVP_CIPHER_CTX_free(ctx);
    
    /* Add a NULL terminator. We are expecting printable text */ 
    decryptedtext[plaintext_len] = '\0';

    return plaintext_len;
}

int sok_gen(uint8_t *key, key_params_t *sender, char *receiver, size_t id_len)
{        
    int first = 0, code = RLC_ERR;
    size_t size, len1 = strlen((char *)sender->public_key), len2 = strlen(receiver);
    uint8_t *buf, *key2;
    g1_t p;
    g2_t q;
    gt_t e;

    RLC_TRY {
        g1_new(p);
        g2_new(q);
        gt_new(e);

        size = gt_size_bin(e, 0);
        key2 = RLC_ALLOCA(uint8_t, size);
        if (key2 == NULL) {
            RLC_THROW(ERR_NO_MEMORY);
        }

        if (len1 == len2) {
            if (strncmp((char *)sender->public_key, receiver, len1) == 0) {
                RLC_THROW(ERR_NO_VALID);
            }
            first = (strncmp((char *)sender->public_key, receiver, len1) < 0 ? 1 : 2);
        } else {
            if (len1 < len2) {
                if (strncmp((char *)sender->public_key, receiver, len2) == 0) {
                    first = 2;
                } else {
                    first = (strncmp((char *)sender->public_key, receiver, len2) < 0 ? 1 : 2);
                }
            }
        }
        
        if (pc_map_is_type1()) {
            g2_map(q, (uint8_t *)receiver, len2);
            pc_map(e, sender->k1, q);
        } else {
            if (first == 1) {
                g2_map(q, (uint8_t *)receiver, len2);
                pc_map(e, sender->k1, q);
            } else {
                g1_map(p, (uint8_t *)receiver, len2);
                pc_map(e, p, sender->k2);
            }
        }

        buf = RLC_ALLOCA(uint8_t, 128);
        gt_write_bin(key2, size, e, 0);
        md_kdf(buf, 128, key2, size);

        memcpy(key, buf, sizeof(&key));

    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        g1_free(p);
        g2_free(q);
        gt_free(e);
        RLC_FREE(buf);
    }
    code = RLC_OK;
 
    return code;
}

int derive_key(unsigned char *upper, size_t upper_len, unsigned char *lower, size_t lower_len,
        uint8_t *key, size_t key_len)
{
    if (upper_len <= 0 || lower_len <= 0)
    {
        printf("Unsupported upper or lower key length...\n");
        printf("Upper: %ld\n", upper_len);
        printf("Lower: %ld\n", lower_len);
        return -1;
    }

    if (key_len <= 0)
    {
        printf("Output key needs to be initialised\n");
        return -1;
    }

    uint8_t offset = 0;
    char buffer[128];
    memcpy(buffer + offset, upper, 64);
    offset += 64;
    memcpy(buffer + offset, lower, 64);

    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */

    mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
    const EVP_MD *EVP_sha3_256() /* Get the sha3 hash function */;

    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
    EVP_DigestUpdate(mdctx, buffer, strlen(buffer)); /* Hash the node ID */
    EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */

    memcpy(key, hash, key_len);

    return sizeof(key);
}
