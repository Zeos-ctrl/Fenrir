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
#include <time.h>


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

    clock_t rtstart, rtend;
    double rtcpu_time_used;
    rtstart = clock();
    if (setup_root(&root, identity, strlen(identity)) < 0) {
        printf("Failed to generate the parameters for the device\n");
        goto exit;
    }
    rtend = clock();
    rtcpu_time_used = ((double) (rtend - rtstart)) / CLOCKS_PER_SEC;
    printf("Time to generate root parameters: %f\n", rtcpu_time_used);
    printf("Root parameters generated\n\n");

    key_params_t gateway;
    char *gateway_id = "Fenrir.Gateway";

    clock_t gtstart, gtend;
    double gtcpu_time_used;
    gtstart = clock();
    if (gen_params(&gateway, gateway_id, strlen(gateway_id), &root, root.secret) < 0) {
        printf("Failed to generate the parameters for the gateway\n");
        goto exit;
    }
    gtend = clock();
    gtcpu_time_used = ((double) (gtend - gtstart)) / CLOCKS_PER_SEC;
    printf("Gateway parameters generated\n\n");
    display_params(&gateway);
    printf("Time to generate gateway parameters: %f\n", gtcpu_time_used);

    key_params_t device;
    char *device_id = "Fenrir.Gateway.Device";

    clock_t dtstart, dtend;
    double dtcpu_time_used;
    dtstart = clock();
    if (gen_params(&device, device_id, strlen(device_id), &gateway, gateway.secret) < 0) {
        printf("Failed to generate the parameters for the device\n");
        goto exit;
    }
    dtend = clock();
    dtcpu_time_used = ((double) (dtend - dtstart)) / CLOCKS_PER_SEC;
    printf("Device parameters generated\n\n");
    display_params(&device);
    printf("Time to generate device parameters: %f\n", dtcpu_time_used);
    printf("Test 1: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 2: Derive the shared key between the device and the server\n");
    uint8_t gateway_pkey[16] = {0};
    uint8_t device_pkey[16] = {0};

    clock_t sokstart, sokend;
    double sokcpu_time_used;
    sokstart = clock();
    if (sok_gen(gateway_pkey, &gateway, (char *)device.public_key, sizeof(device.public_key)) != RLC_OK) {
        printf("Failed to derive the shared key between the gateway and the device\n");
        goto exit;
    }
    sokend = clock();
    sokcpu_time_used = ((double) (sokend - sokstart)) / CLOCKS_PER_SEC;
    printf("Time to generate shared key between gateway and device: %f\n", sokcpu_time_used);

    sokcpu_time_used = 0;
    sokstart = clock();
    if (sok_gen(device_pkey, &device, (char *)gateway.public_key, sizeof(gateway.public_key)) != RLC_OK) {
        printf("Failed to derive the shared key between the device and the gateway\n");
        goto exit;
    }
    sokend = clock();
    sokcpu_time_used = ((double) (sokend - sokstart)) / CLOCKS_PER_SEC;
    printf("Time to generate shared key between device and gateway: %f\n", sokcpu_time_used);

    uint8_t shared_key[16] = {0};
    clock_t drstart, drend;
    double drcpu_time_used;
    drstart = clock();
    if (derive_key(gateway_pkey, sizeof(gateway_pkey), device_pkey, sizeof(device_pkey), shared_key, sizeof(shared_key)) <= 0) {
        printf("Failed to derive the shared key between the device and the gateway\n");
        goto exit;
    }
    drend = clock();
    drcpu_time_used = ((double) (drend - drstart)) / CLOCKS_PER_SEC;
    printf("Time to derive shared key between device and gateway: %f\n", drcpu_time_used);
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

    clock_t encstart, encend;
    double enccpu_time_used;
    encstart = clock();
    if (CYPHER == AES) {
        if (aes_enc(ciphertext, (unsigned char *)plaintext, strlen((char *)plaintext), shared_key, iv, sizeof(iv)) <= 0 ) {
            printf("Failed to encrypt the message using AES\n");
            goto exit;
        }
        encend = clock();
        enccpu_time_used = ((double) (encend - encstart)) / CLOCKS_PER_SEC;
        printf("Ciphertext is: \n");
        BIO_dump_fp(stdout, ciphertext, sizeof(ciphertext));
        printf("Time to encrypt message using AES: %f\n", enccpu_time_used);
    } else if (CYPHER == ASCON) {
        if (ascon_enc(ciphertext, (char *)plaintext, strlen((char *)plaintext), tag, sizeof(tag), shared_key, (unsigned char *)nonce) <= 0 ) {
            printf("Failed to encrypt the message using ASCON\n");
            goto exit;
        }
        encend = clock();
        enccpu_time_used = ((double) (encend - encstart)) / CLOCKS_PER_SEC;
        printf("Ciphertext is: \n");
        BIO_dump_fp(stdout, ciphertext, sizeof(ciphertext));
        printf("Time to encrypt message using ASCON: %f\n", enccpu_time_used);
    } else {
        printf("Unknown cypher\n");
        goto exit;
    }
    printf("Test 3: Passed\n\n");
    /* --------------------------------------------------------------------- */
    printf("---------------------------------------------------------------------\n\n");
    printf("Test 4: Decrypt the message using the key in AES and ASCON\n");
    char decryptedtext[sizeof(plaintext)];

    clock_t decstart, decend;
    double deccpu_time_used;
    decstart = clock();
    if (CYPHER == AES) {

        if (aes_dec((unsigned char *)decryptedtext, ciphertext, sizeof(ciphertext), shared_key, iv, sizeof(iv)) <= 0 ) {
            printf("Failed to decrypt the message using AES\n");
            goto exit;
        }
        decend = clock();
        deccpu_time_used = ((double) (decend - decstart)) / CLOCKS_PER_SEC;
        if (strncmp((char *)plaintext, (char *)decryptedtext, sizeof(decryptedtext)) != 0) {
            printf("Decrypted text does not match plaintext\n");
            goto exit;
        }
        printf("Time to decrypt message using AES: %f\n", deccpu_time_used);
    } else if (CYPHER == ASCON) {
        if (ascon_dec((unsigned char *)ciphertext, sizeof(ciphertext), tag, sizeof(tag), shared_key, (unsigned char *)nonce) <= 0 ) {
            printf("Failed to decrypt the message using ASCON\n");
            goto exit;
        }
        decend = clock();
        deccpu_time_used = ((double) (decend - decstart)) / CLOCKS_PER_SEC;
        if (strncmp((char *)plaintext, (char *)ciphertext, sizeof(ciphertext)) != 0) {
            printf("Decrypted text does not match plaintext\n");
            goto exit;
        }
        printf("Time to decrypt message using ASCON: %f\n", deccpu_time_used);
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

