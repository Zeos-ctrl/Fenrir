#include <relic/relic.h>
#include <relic/relic_bn.h>
#include <relic/relic_cp.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "setup.h"
#include "crypto.h"
#include "network.h"

#define PORT 8080

int device_setup_root(key_pair_t *root, char *identity, size_t id_len)
{
    if (id_len < 0 ) {
        printf("Identity must be larger than 0 bytes\n");
        return -1;
    }

    int code = RLC_ERR;
    bn_t N; /* Master secret and order of group */

    /* Hash Identity to gen pub key */
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */


    RLC_TRY {
        /* Check for null pointers */
        if (root == NULL || identity == NULL) {
            RLC_THROW(ERR_NO_VALID);
        }

        bn_null(N);
        bn_null(root->secret);
        g1_null(root->public_key);
        g1_null(root->k1);
        g2_null(root->k2);
        g1_null(root->Q);

        /* Initialize master secret */
        bn_new(N); 
        pc_get_ord(N); /* Get the order of the group */ 
        bn_rand_mod(root->secret, N); /* Generate random master secret */

        mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
        const EVP_MD *EVP_sha3_256() /* Get the md5 hash function */;

        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
        EVP_DigestUpdate(mdctx, identity, strlen(identity)); /* Hash the node ID */
        EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */
        
        g1_map(root->public_key, hash, md_len); /* Map the hash to a point on the curve */

        /* Map private key to groups */
        g1_map(root->k1, (uint8_t *)root->secret, sizeof(root->secret));
        g2_map(root->k2, (uint8_t *)root->secret, sizeof(root->secret));

        /* Compute Q = s * Pubkey */
        g1_mul(root->Q, root->public_key, root->secret);

        /* Print root for debug */ 
        printf("Root secret: ");
        bn_print(root->secret);
        printf("\n");
        printf("Root public key: ");
        g1_print(root->public_key);
        printf("\n");
        printf("Root k1: ");
        g1_print(root->k1);
        printf("\n");
        printf("Root k2: ");
        g2_print(root->k2);
        printf("\n");
        printf("Root Q: ");
        g1_print(root->Q);
        printf("\n");

    }RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    }RLC_FINALLY {
        bn_free(N);
        EVP_MD_CTX_free(mdctx);
    }

    code = RLC_OK;
    return code;
}

int device_setup_gateway(key_pair_t *gateway, char *identity, size_t id_len)
{
    if (id_len < 0 ) {
        printf("Identity must be larger than 0 bytes\n");
        return -1;
    }

    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    // Connect to root node
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0 ) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr,
                    sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    // Send request
    send(client_fd, identity, strlen(identity), 0);
    printf("Request sent\n");
    valread = read(client_fd, buffer, 1024);
    printf("%s\n", buffer);
    // Deserialize the buffer
    deserialize_k(buffer, sizeof(buffer), gateway);

    // Print the struct for debugging
    printf("Gateway secret: ");
    bn_print(gateway->secret);
    printf("\n");
    printf("Gateway public key: ");
    g1_print(gateway->public_key);
    printf("\n");
    printf("Gateway k1: ");
    g1_print(gateway->k1);
    printf("\n");
    printf("Gateway k2: ");
    g2_print(gateway->k2);
    printf("\n");
    printf("Gateway Q: ");
    g1_print(gateway->Q);
    printf("\n");

    // Close connection 
    close(client_fd);

    return 0;
}

int device_setup_worker(key_pair_t *worker, char *identity, size_t id_len)
{
    if (id_len < 0 ) {
        printf("Identity must be larger than 0 bytes\n");
        return -1;
    }

    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    // Connect to gateway/ KDC
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0 ) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr,
                    sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    // Send request
    send(client_fd, identity, strlen(identity), 0);
    printf("Request sent\n");
    valread = read(client_fd, buffer, 1024);
    printf("%s\n", buffer);
    // Deserialize the buffer
    deserialize_k(buffer, sizeof(buffer), worker);

    // Print the struct for debugging
    printf("Worker secret: ");
    bn_print(worker->secret);
    printf("\n");
    printf("Worker public key: ");
    g1_print(worker->public_key);
    printf("\n");
    printf("Worker k1: ");
    g1_print(worker->k1);
    printf("\n");
    printf("Worker k2: ");
    g2_print(worker->k2);
    printf("\n");
    printf("Worker Q: ");
    g1_print(worker->Q);
    printf("\n");

    // Close connection 
    close(client_fd);

    return 0;
}

