#include "crypto.h"
#include "crypto.c"
#include "params.h"
#include "setup.c"
#include "setup.h"

#include <ascon/ascon.h>
#include <openssl/bio.h>
#include <relic/relic.h>
#include <relic/relic_pc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 1000


int main(int argc, char *argv[])
{
    printf("Fenrir starting...\n");
    if (core_init() != RLC_OK) {
        printf("Relic library failed to Initialize exiting!\n");
        goto exit;
    }
    printf("Initializing parameters...\n");
    if (pc_param_set_any() != RLC_OK) {
        printf("Failed to set parameters exiting!\n");
        pc_param_print();
        goto exit;
    }
    pc_param_print();
    int level = pc_param_level();
    printf("\nSecurity level: %d\n", level);
    printf("Relic initialized\n\n");
    printf("%s\n\n\n\n",asciiArt);

    /* Start of tests
     * 
     * Test 1: Generate the parameters for the device
     *
     * Test 2: Derive the shared key between the device and the server
     *
     * Test 3: Encrypt a message using the key in AES and ASCON 
     *
     * Test 4: Decrypt the message using the key in AES and ASCON
     */

    clock_t start, end;

    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 1: Generate the parameters for the device\n");
    key_params_t root;
    char *identity = "Fenrir";

    start = clock();

    for (int i = 0; i < ITERATIONS; i++)
    {
        setup_root(&root, identity, strlen(identity));
    }

    end = clock();
    double time_taken = ((double)end - start) / CLOCKS_PER_SEC;
    printf("Time taken to generate the root parameters %d times: %f\n", ITERATIONS, time_taken);
    printf("Root parameters generated\n\n");

    key_params_t gateway;
    char *gateway_id = "Fenrir.Gateway";

    start = clock();

    for (int i = 0; i < ITERATIONS; i++)
    {
    gen_params(&gateway, gateway_id, strlen(gateway_id), &root, root.secret, root.public_key);
    }

    end = clock();
    double time_taken_gen = ((double)end - start) / CLOCKS_PER_SEC;
    printf("Time taken to generate the gateway parameters %d times: %f\n", ITERATIONS, time_taken_gen);
    printf("Gateway parameters generated\n\n");

    key_params_t device;
    char *device_id = "Fenrir.Gateway.Device";

    if (gen_params(&device, device_id, strlen(device_id), &gateway, gateway.secret, root.public_key) < 0) {
        printf("Failed to generate the parameters for the device\n");
        goto exit;
    }
    printf("Device parameters generated\n\n");
    printf("Test 1: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 2: Derive the shared key between the device and the server\n");
    uint8_t gateway_pkey[16] = {0};
    uint8_t device_pkey[16] = {0};

    start = clock();
    for (int i = 0; i < (ITERATIONS / 2); i++)
    {
        sok_gen(gateway_pkey, &gateway, (char *)device.public_key, sizeof(device.public_key));
        sok_gen(device_pkey, &device, (char *)gateway.public_key, sizeof(gateway.public_key));
    }
    end = clock();
    double time_taken_sok = ((double)end - start) / CLOCKS_PER_SEC;
    printf("Time taken to derive the shared key using SOK %d times: %f\n", ITERATIONS, time_taken_sok);

    sok_gen(gateway_pkey, &gateway, (char *)device.public_key, sizeof(device.public_key));
    sok_gen(device_pkey, &device, (char *)gateway.public_key, sizeof(gateway.public_key));

    uint8_t shared_key[16] = {0};

    start = clock();
    for (int i = 0; i < ITERATIONS; i++)
    {
        derive_key(gateway_pkey, sizeof(gateway_pkey), device_pkey, sizeof(device_pkey), shared_key, sizeof(shared_key));
    }
    end = clock();
    double time_taken_der = ((double)end - start) / CLOCKS_PER_SEC;
    printf("Time taken to derive the shared key %d times: %f\n", ITERATIONS, time_taken_der);

    printf("\nShared key derived: ");
    for (int i = 0; i < sizeof(shared_key); i++) {
        printf("%02x", shared_key[i]);
    }
    printf("\n\n");
    printf("Test 2: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 3: Encrypt a message using the key in AES and ASCON\n");
    char plaintext[16] = "plaintex";
    unsigned char ciphertext[sizeof(plaintext)];
    double time_taken_enc;
    
    // AES initializors
    uint8_t iv[16] = {0};

    // ASCON initializors
    const uint8_t nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };

    uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN] = {0};

    start = clock();
    if (CYPHER == AES) {
        for (int i = 0; i < ITERATIONS; i++) {
            unsigned char ciphertext[sizeof(plaintext)];
            aes_enc(ciphertext, (unsigned char *)plaintext, strlen((char *)plaintext), shared_key, iv, sizeof(iv));
        }
        end = clock();
        time_taken_enc = ((double)end - start) / CLOCKS_PER_SEC;
        printf("Time taken to encrypt with AES %d times: %f\n", ITERATIONS, time_taken_enc);

        if (aes_enc(ciphertext, (unsigned char *)plaintext, strlen((char *)plaintext), shared_key, iv, sizeof(iv)) <= 0 ) {
            printf("Failed to encrypt the message using AES\n");
            goto exit;
        }
    } else if (CYPHER == ASCON) {
        for (int i = 0; i < ITERATIONS; i++) {
            unsigned char *ct = malloc(sizeof(plaintext));
            uint8_t *t = malloc(ASCON_AEAD_TAG_MIN_SECURE_LEN);
            ascon_enc(ct, (char *)plaintext, strlen((char *)plaintext), t, sizeof(t), shared_key, (unsigned char *)nonce);
            free(ct);
            free(t);
        }
        end = clock();
        time_taken_enc = ((double)end - start) / CLOCKS_PER_SEC;
        printf("Time taken to encrypt with ASCON %d times: %f\n", ITERATIONS, time_taken_enc);

        if (ascon_enc(ciphertext, (char *)plaintext, strlen((char *)plaintext), tag, sizeof(tag), shared_key, (unsigned char *)nonce) <= 0 ) {
            printf("Failed to encrypt the message using ASCON\n");
            goto exit;
        }
    } else {
        printf("Unknown cypher\n");
        goto exit;
    }
    printf("Test 3: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 4: Decrypt the message using the key in AES and ASCON\n");

    double time_taken_dec;

    start = clock();
    if (CYPHER == AES) {
        for (int i = 0; i < ITERATIONS; i++) {
            unsigned char decryptedtext[sizeof(plaintext)];
            aes_dec((unsigned char *)decryptedtext, ciphertext, sizeof(ciphertext), shared_key, iv, sizeof(iv));
        }
        end = clock();
        time_taken_dec = ((double)end - start) / CLOCKS_PER_SEC;
        printf("Time taken to decrypt with AES %d times: %f\n", ITERATIONS, time_taken_dec);

    } else if (CYPHER == ASCON) {
        for (int i = 0; i < ITERATIONS; i++) {
            unsigned char *ct = malloc(sizeof(ciphertext));
            memcpy(ct, ciphertext, sizeof(ciphertext));
            ascon_dec((unsigned char *)ct, sizeof(ct), tag, sizeof(tag), shared_key, (unsigned char *)nonce);
            free(ct);
        }
        end = clock();
        time_taken_dec = ((double)end - start) / CLOCKS_PER_SEC;
        printf("Time taken to decrypt with ASCON %d times: %f\n", ITERATIONS, time_taken_dec);
    } else {
        printf("Unknown cypher\n");
        goto exit;
    }
    printf("\n\n");
    printf("Test 4: Passed\n\n");
    /* --------------------------------------------------------------------- */ 
    printf("Adding results to file...\n");
    FILE *file;
    if (CYPHER == AES) {
        file = fopen("aes.csv", "a");
    } else if (CYPHER == ASCON) {
        file = fopen("ascon.csv", "a");
    }

    if (file == NULL) {
        perror("Error opening file");
        goto exit;
    }

    fprintf(file, "%f,%f,%f,%f,%f,%f,%d,\n",
            time_taken, time_taken_gen, time_taken_sok, time_taken_der,
            time_taken_enc, time_taken_dec, ITERATIONS);
    fclose(file);
    printf("Fenrir finished\n");
    core_clean();
    return 0;
exit:
    printf("Program failed cleaning up...\n");
    core_clean();
    return 1;
}

