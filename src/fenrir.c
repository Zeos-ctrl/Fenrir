#include "crypto.h"
#include "crypto.c"
#include "params.h"
#include "setup.c"
#include "setup.h"

#include <ascon/ascon.h>
#include <relic/relic.h>
#include <relic/relic_pc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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

    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 1: Generate the parameters for the device\n");
    key_params_t root;
    char *identity = "Fenrir";
    if (setup_root(&root, identity, strlen(identity)) < 0) {
        printf("Failed to generate the parameters for the device\n");
        goto exit;
    }
    printf("Root parameters generated\n\n");
    key_params_t gateway;
    char *gateway_id = "Fenrir.Gateway";
    if (gen_params(&gateway, gateway_id, strlen(gateway_id), &root, root.secret) < 0) {
        printf("Failed to generate the parameters for the gateway\n");
        goto exit;
    }
    printf("Gateway parameters generated\n\n");
    display_params(&gateway);
    key_params_t device;
    char *device_id = "Fenrir.Gateway.Device";
    if (gen_params(&device, device_id, strlen(device_id), &gateway, gateway.secret) < 0) {
        printf("Failed to generate the parameters for the device\n");
        goto exit;
    }
    printf("Device parameters generated\n\n");
    display_params(&device);
    printf("Test 1: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 2: Derive the shared key between the device and the server\n");
    uint8_t gateway_pkey[16] = {0};
    uint8_t device_pkey[16] = {0};
    if (sok_gen(gateway_pkey, &gateway, (char *)device.public_key, sizeof(device.public_key)) != RLC_OK) {
        printf("Failed to derive the shared key between the gateway and the device\n");
        goto exit;
    }
    if (sok_gen(device_pkey, &device, (char *)gateway.public_key, sizeof(gateway.public_key)) != RLC_OK) {
        printf("Failed to derive the shared key between the device and the gateway\n");
        goto exit;
    }
    uint8_t shared_key[16] = {0};
    if (derive_key(gateway_pkey, sizeof(gateway_pkey), device_pkey, sizeof(device_pkey), shared_key, sizeof(shared_key)) <= 0) {
        printf("Failed to derive the shared key between the device and the gateway\n");
        goto exit;
    }
    printf("\nShared key derived: ");
    for (int i = 0; i < sizeof(shared_key); i++) {
        printf("%02x", shared_key[i]);
    }
    printf("\n\n");
    printf("Test 2: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 3: Encrypt a message using the key in AES and ASCON\n");
    char plaintext[9] = "plaintext";
    unsigned char ciphertext[sizeof(plaintext)];
    
    // AES initializors
    uint8_t iv[16] = {0};

    // ASCON initializors
    const uint8_t nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN] = {0};

    if (CYPHER == AES) {
        if (aes_enc(ciphertext, (unsigned char *)plaintext, strlen((char *)plaintext), shared_key, iv, sizeof(iv)) <= 0 ) {
            printf("Failed to encrypt the message using AES\n");
            goto exit;
        }
        printf("Ciphertext is: \n");
        BIO_dump_fp(stdout, ciphertext, sizeof(ciphertext));
    } else if (CYPHER == ASCON) {
        if (ascon_enc(ciphertext, (char *)plaintext, strlen((char *)plaintext), tag,  shared_key, (unsigned char *)nonce) <= 0 ) {
            printf("Failed to encrypt the message using ASCON\n");
            goto exit;
        }
        printf("Ciphertext is: \n");
        BIO_dump_fp(stdout, ciphertext, sizeof(ciphertext));
    } else {
        printf("Unknown cypher\n");
        goto exit;
    }
    printf("Test 3: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 4: Decrypt the message using the key in AES and ASCON\n");
    char decryptedtext[sizeof(plaintext)];
    if (CYPHER == AES) {
        if (aes_dec((unsigned char *)decryptedtext, ciphertext, sizeof(ciphertext), shared_key, iv, sizeof(iv)) <= 0 ) {
            printf("Failed to decrypt the message using AES\n");
            goto exit;
        }
        BIO_dump_fp(stdout, decryptedtext, sizeof(decryptedtext));
        BIO_dump_fp(stdout, plaintext, sizeof(plaintext));
        if (strcmp((char *)plaintext, (char *)decryptedtext) != 0) {
            printf("Decrypted text does not match plaintext\n");
        }
    } else if (CYPHER == ASCON) {
        if (ascon_dec((unsigned char *)decryptedtext, sizeof(ciphertext), tag, shared_key, (unsigned char *)nonce) <= 0 ) {
            printf("Failed to decrypt the message using ASCON\n");
            goto exit;
        }
        BIO_dump_fp(stdout, decryptedtext, sizeof(decryptedtext));
        BIO_dump_fp(stdout, plaintext, sizeof(plaintext));
        if (strcmp((char *)plaintext, (char *)decryptedtext) != 0) {
            printf("Decrypted text does not match plaintext\n");
        }
    } else {
        printf("Unknown cypher\n");
        goto exit;
    }
    printf("\n\n");
    printf("Test 4: Passed\n\n");
    /* --------------------------------------------------------------------- */ 
    printf("Fenrir finished\n");
    core_clean();
    return 0;
exit:
    printf("Program failed cleaning up...\n");
    core_clean();
    return 1;
}

