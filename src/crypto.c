#include <relic/relic.h>
#include <relic/relic_err.h>
#include <relic/relic_pc.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */
#include <ascon/ascon.h> /* ASCON AEAD headers for symmetric encryption */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

int bilinear_key_pair(key_pair_t *child, char *child_id, size_t id_len, 
        key_pair_t *parent, bn_t master)
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

        /* Gen shared value */
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
        g1_mul(child->Q, parent->Q, master); /* Qx = Qx * x */

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
        uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN],
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    ascon_aead_ctx_t ctx;
    ascon_aead128a_init(&ctx, key, nonce);

    size_t ciphertext_len = 0;

    ciphertext_len += ascon_aead128_encrypt_update(
            &ctx, buffer + ciphertext_len,
            (uint8_t*) plaintext, strlen(plaintext));

    ciphertext_len += ascon_aead128_encrypt_final(
            &ctx, buffer + ciphertext_len,
            tag, sizeof(tag));

    printf("Ciphertext: %s\n", buffer);

    /* Clean up */
    ascon_aead_cleanup(&ctx);
    return ciphertext_len;
}

int ascon_dec(uint8_t *buffer, size_t ciphertext_len, uint8_t *tag,
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    ascon_aead_ctx_t ctx;
    ascon_aead128a_init(&ctx, key, nonce);
    size_t plaintext_len = 0;

    plaintext_len += ascon_aead128_decrypt_update(
            &ctx, buffer,
            buffer, ciphertext_len);

    bool is_tag_valid = false;

    plaintext_len += ascon_aead128_decrypt_final(
            &ctx, buffer + plaintext_len,
            &is_tag_valid, tag, sizeof(tag));

    buffer[plaintext_len] = '\0'; // Null terminated, because it's text
    ascon_aead_cleanup(&ctx);

    return plaintext_len;
}

int aes_enc(unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len,
        unsigned char *key, unsigned char *iv)
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

    printf("\nCiphertext is: \n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    return ciphertext_len;
}

int aes_dec(unsigned char *decryptedtext, unsigned char *ciphertext, int ciphertext_len,
        unsigned char *key, unsigned char *iv)
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
    BIO_dump_fp (stdout, (const char *)decryptedtext, plaintext_len);
    decryptedtext[plaintext_len] = '\0';
    printf("Decrypted text is: %s\n", decryptedtext);

    return plaintext_len;
}

int sok_gen_sym_key(uint8_t *buf, key_pair_t *sender, char *receiver, size_t id_len)
{        
    int first = 0, code = RLC_ERR;
    size_t size, len1 = strlen((char *)sender->public_key), len2 = strlen(receiver);
    uint8_t *key;
    g1_t p;
    g2_t q;
    gt_t e;

    RLC_TRY {
        g1_new(p);
        g2_new(q);
        gt_new(e);

        size = gt_size_bin(e, 0);
        buf = RLC_ALLOCA(uint8_t, size);
        if (buf == NULL) {
            RLC_THROW(ERR_NO_MEMORY);
        }

        printf("Math...\n");
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
        
        printf("Generating shared value...\n");
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

        printf("Writing key to buffer...\n");
        key = RLC_ALLOCA(uint8_t, 128);
        gt_write_bin(buf, size, e, 0);
        md_kdf(key, 128, buf, size);

        /* Print the key */ 
        printf("\nKey: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");

    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        g1_free(p);
        g2_free(q);
        gt_free(e);
        RLC_FREE(buf);
        RLC_FREE(key);
    }
    code = RLC_OK;
 
    return code;
}
