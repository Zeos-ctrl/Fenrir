#include <assert.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */
#include <openssl/aes.h> /* OpenSSL AES headers for symmetric encryption */ 
#include <pthread.h>
#include <relic/relic.h> /* RELIC headers for elliptic curve crypto */
#include <relic/relic_bn.h>
#include <relic/relic_core.h>
#include <relic/relic_cp.h>
#include <relic/relic_err.h>
#include <relic/relic_pc.h>
#include <ascon/ascon.h> /* ASCON headers for symmetric encryption */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int test_hash(void)
{
    printf("\nTesting hash function...\n");
    size_t i;
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */
    char *id = "test"; /* Identity */

    mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
    const EVP_MD *EVP_sha3_256() /* Get the sha3 hash function */;

    if (mdctx == NULL) {
        fprintf(stderr, "Error creating MD context\n");
        return 1; // Return an error code
    }

    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
    EVP_DigestUpdate(mdctx, id, strlen(id)); /* Hash the ID */
    EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */

    /* Print the value for debugging */
    for (i = 0; i < md_len; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}

static int allocate_memory(void)
{
    int code = RLC_ERR;
    RLC_TRY {
        bn_t a;
        bn_null(a);
        bn_new(a);
        bn_free(a);
    }
    RLC_CATCH_ANY {
        RLC_ERROR(end);
    }
    code = RLC_OK;
end:
    return code;
}

static int gen_perams(void)
{
    bn_t secret, N;
    g1_t pub, S, P, priv1, Q;
    g2_t priv2;
    int code = RLC_ERR;

    bn_null(secret); /* Secret number in Zn */
    bn_null(N); /* Order of the curve */
    g1_null(pub); /* Public key of the child */
    g1_null(S); /* Private key of the parent */
    g1_null(P); /* Unmapped private key of the child */
    g1_null(priv1); /* Mapped private key of the child */
    g1_null(Q); /* Public perameter of the child */
    g2_null(priv2); /* Private key of the parent */

    printf("\nGenerating parameters...\n");
    RLC_TRY {
        /* gen secret number */
        bn_new(N);
        pc_get_ord(N);
        bn_rand_mod(secret, N);

        /* gen random keys for testing*/
        g1_rand(pub);
        g1_rand(S);

        g1_t X;
        g1_null(X);

        /* gen private key */
        g1_mul(X, pub, secret);
        g1_add(P, S, X);

        /* map private keys */
        g1_map(priv1, (uint8_t *)P, sizeof(P));
        g1_mul(priv1, priv1, secret);
        g2_map(priv2, (uint8_t *)P, sizeof(P));
        g2_mul(priv2, priv2, secret);

        /* gen public peram */
        g1_mul(Q, S, secret);
    }
    RLC_CATCH_ANY {
        RLC_ERROR(end);
    }
    code = RLC_OK;
end:
    bn_free(secret);
    bn_free(N);
    g1_free(pub);
    g1_free(S);
    g1_free(P);
    g1_free(priv);
    g1_free(Q);

    return code;
}

static int test_pairing_type(void)
{
    int first = 0, code = RLC_ERR;
    char *id1 = "id1";
    char *id2 = "id2";
    size_t size, len1 = strlen(id1), len2 = strlen(id2);
    uint8_t *buf;
    uint8_t *key;
    g1_t p, k1, s1;
    g2_t q, k2, s2;
    gt_t e;
    bn_t n, master;

    g1_null(p);
    g2_null(q);
    gt_null(e);
    g1_null(k1);
    g2_null(k2);
    g1_null(s1);
    g2_null(s2);
    bn_null(n);
    bn_null(master);

    RLC_TRY {
        /* Gen keys for testing */ 
        bn_new(n);
        pc_get_ord(n);
        bn_rand_mod(master, n);
        printf("\nGenerating master value...\n");

        if (pc_map_is_type1()) {
            /* Key pair node 1 */
            printf("Generating key node 1...\n");
            g1_map(k1, (uint8_t *)id1, strlen(id1));
            g1_mul(k1, k1, master);
        } else {
            /* Key pair node 1 */
            printf("Generating keys node 1...\n");
            g1_map(k1, (uint8_t *)id1, strlen(id1));
            g1_mul(k1, k1, master);
            g2_map(k2, (uint8_t *)id1, strlen(id1));
            g2_mul(k2, k2, master);
        }
        
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
            if (strncmp(id1,id2,len1) == 0) {
                RLC_THROW(ERR_NO_VALID);
            }
            first = (strncmp(id1, id2, len1) < 0 ? 1 : 2);
        } else {
            if (len1 < len2) {
                if (strncmp(id1, id2, len2) == 0) {
                    first = 2;
                } else {
                    first = (strncmp(id1, id2, len2) < 0 ? 1 : 2);
                }
            }
        }
        
        printf("Generating shared value...\n");
        if (pc_map_is_type1()) {
            g2_map(q, (uint8_t *)id2, len2);
            pc_map(e, k1, q);
        } else {
            if (first == 1) {
                g2_map(q, (uint8_t *)id2, len2);
                pc_map(e, k1, q);
            } else {
                g1_map(p, (uint8_t *)id2, len2);
                pc_map(e, p, k2);
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

        g1_null(p);
        g2_null(q);
        gt_null(e);

        RLC_FREE(buf);
        RLC_FREE(key);

        printf("Generating shared value using second node...\n");
        if (pc_map_is_type1()) {
            /* Key pair node 2 */
            printf("Generating key node 2...\n");
            g1_map(s1, (uint8_t *)id2, strlen(id2));
            g1_mul(s1, s1, master);
        } else {
            /* Key pair node 2 */
            printf("Generating keys node 2...\n");
            g1_map(s1, (uint8_t *)id2, strlen(id2));
            g1_mul(s1, s1, master);
            g2_map(s2, (uint8_t *)id2, strlen(id2));
            g2_mul(s2, s2, master);
        }

        g1_new(p);
        g2_new(q);
        gt_new(e);

        size = gt_size_bin(e, 0);
        buf = RLC_ALLOCA(uint8_t, size);
        if (buf == NULL) {
            RLC_THROW(ERR_NO_MEMORY);
        }

        printf("Math...\n");
        if (len2 == len1) {
            if (strncmp(id2,id1,len1) == 0) {
                RLC_THROW(ERR_NO_VALID);
            }
            first = (strncmp(id2, id1, len1) < 0 ? 1 : 2);
        } else {
            if (len2 < len1) {
                if (strncmp(id2, id1, len1) == 0) {
                    first = 2;
                } else {
                    first = (strncmp(id2, id1, len1) < 0 ? 1 : 2);
                }
            }
        }
        
        printf("Generating shared value...\n");
        if (pc_map_is_type1()) {
            g2_map(q, (uint8_t *)id1, len1);
            pc_map(e, s1, q);
        } else {
            if (first == 1) {
                g2_map(q, (uint8_t *)id1, len1);
                pc_map(e, s1, q);
            } else {
                g1_map(p, (uint8_t *)id1, len1);
                pc_map(e, p, s2);
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
    }
    RLC_CATCH_ANY {
        RLC_ERROR(end);
    }
    RLC_FINALLY {
        g1_free(p);
        g1_free(k1);
        g2_free(q);
        g2_free(k2);
        g1_free(s1);
        g2_free(s2);
        gt_free(e);
        bn_free(n);
        bn_free(master);
        RLC_FREE(buf);
    }
    code = RLC_OK;
end:
    return code;
}

int test_ascon(void)
{
    // Initialisation
    // We need the key and the nonce, both 128 bits.
    // Note: Ascon80pq uses longer keys
    const uint8_t secret_key[ASCON_AEAD128_KEY_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    const uint8_t unique_nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, secret_key, unique_nonce);

    // Now we feed any associated data into the cipher first
    // Our data is fragmented into 2 parts, so we feed one at the time.
    const char associated_data_pt1[] = "2 messages will foll";
    const char associated_data_pt2[] = "ow, but they are both secret.";
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt1, strlen
            (associated_data_pt1));
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt2, strlen
            (associated_data_pt2));

    // Next, we feed the plaintext, which is also fragmented in 2 parts.
    const char plaintext_pt1[] = "Hello, I'm a secret mes";
    const char plaintext_pt2[] = "sage and I should be encrypted!";
    uint8_t buffer[100];
    // The ciphertext is generated block-wise, so we need the return value
    // to know how to offset the pointer to where the next ciphertext
    // part should be written.
    size_t ciphertext_len = 0;
    ciphertext_len += ascon_aead128_encrypt_update(
            &ctx, buffer + ciphertext_len,
            (uint8_t*) plaintext_pt1, strlen(plaintext_pt1));
    ciphertext_len += ascon_aead128_encrypt_update(
            &ctx, buffer + ciphertext_len,
            (uint8_t*) plaintext_pt2, strlen(plaintext_pt2));

    // Finally, we wrap up the encryption and generate the tag.
    // There may still be some trailing ciphertext to be produced.
    // The tag length can be specified. ASCON_AEAD_TAG_MIN_SECURE_LEN is
    // the minimum recommended (128 b)
    uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    ciphertext_len += ascon_aead128_encrypt_final(
            &ctx, buffer + ciphertext_len,
            tag, sizeof(tag));
    // The final function zeroes out the context automatically.
    // Now the buffer contains our ciphertext, long ciphertext_len bytes.
    printf("Ciphertext: %s\n", buffer);

    // Now we can decrypt, reusing the same key, nonce and associated data
    ascon_aead128_init(&ctx, secret_key, unique_nonce);
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt1,
                                    strlen(associated_data_pt1));
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt2,
                                    strlen(associated_data_pt2));
    // This time, we perform the decryption in-place, in the same buffer
    // where the ciphertext it: to do so, we pass the same pointer for
    // plaintext and ciphertext.
    size_t plaintext_len = 0;
    plaintext_len += ascon_aead128_decrypt_update(
            &ctx, buffer,
            buffer, ciphertext_len);
    // The final decryption step automatically checks the tag
    bool is_tag_valid = false;
    plaintext_len += ascon_aead128_decrypt_final(
            &ctx, buffer + plaintext_len,
            &is_tag_valid, tag, sizeof(tag));
    // The final function zeroes out the context automatically.
    buffer[plaintext_len] = '\0'; // Null terminated, because it's text
    printf("\nDecrypted msg: %s, tag is valid: %d\n", buffer, is_tag_valid);
    // The macros ASCON_TAG_OK=true and ASCON_TAG_INVALID=false are also
    // available if you prefer them over booleans for is_tag_valid.
    // Test taken from the ascon github page https://github.com/TheMatjaz/LibAscon

    return 0;
}

int test_aes(void)
{
    // Initialisation
    // We need the key and the nonce, both 128 bits.

    const unsigned char key[] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    
    /* A 128 bit IV */
    const unsigned char iv[] = {
      0x00, 0x01, 0x02, 0x42, 
      0x04, 0x05, 0x13, 0x07, 
      0x08, 0xa9, 0x0a, 0x0b, 
      0x0c, 0xfd, 0x0e, 0x0f
    };

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */ 
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error creating context\n");
        return 1;
    }

    /* Initialise the encryption operation. */ 
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        printf("Error initialising encryption\n");
        return 1;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */ 
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen ((char *)plaintext))) {
        printf("Error encrypting\n");
        return 1;
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */ 
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Error finalising\n");
        return 1;
    }
    ciphertext_len += len;

    /* Clean up */ 
    EVP_CIPHER_CTX_free(ctx);

    printf("\nCiphertext is: \n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    int len2;
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
    if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len2, ciphertext, ciphertext_len)) {
        printf("Error decrypting\n");
        return 1;
    } 
    plaintext_len = len2;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */ 
    if(1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len2, &len2)) {
        printf("Error finalising\n");
        return 1;
    }
    plaintext_len += len2;

    /* Clean up */ 
    EVP_CIPHER_CTX_free(ctx);
    
    /* Add a NULL terminator. We are expecting printable text */ 
    BIO_dump_fp (stdout, (const char *)decryptedtext, plaintext_len);
    decryptedtext[plaintext_len] = '\0';
    printf("Decrypted text is: %s\n", decryptedtext);

    return 0;
}

int main(void)
{
    printf("Starting tests...\n");

    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    if (pc_param_set_any() != RLC_OK) {
        core_clean();
        return 1;
    }

    if(test_hash() != 0) {
        return 1;
    }
    printf("Hash test passed!\n");

    if (allocate_memory() != RLC_OK){
        return 1;
    }
    printf("\nMemory allocation test passed!\n");

    if (gen_perams() != RLC_OK){
        return 1;
    }
    printf("Parameter generation test passed!\n");


    if (test_pairing_type() != RLC_OK){
        return 1;
    }

    printf("Pairing test passed!\n");

    if (test_ascon() != 0){
        return 1;
    }

    printf("Ascon test passed!\n");

    if (test_aes() != 0){
        return 1;
    }

    printf("AES test passed!\n");

    core_clean();
    return 0;
}
