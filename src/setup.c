#include <relic/relic.h>
#include <relic/relic_bn.h>
#include <relic/relic_cp.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "setup.h"
#include "crypto.h"
#include "network.h"
#include "params.h"


int device_setup_root(key_pair_t *root, char *id, size_t id_len)
{
    if (id_len < 0 ) {
        printf("Identity must be larger than 0 bytes\n");
        return -1;
    }
    int code = RLC_ERR;
    bn_t N; /* Order of the Group */
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */

    RLC_TRY {
        g1_null(P);
        g1_null(c->public_key);
        g1_null(c->d1->k1);
        g1_null(c->d2->k1);
        g2_null(c->d1->k2);
        g2_null(c->d2->k2);
        g1_null(c->Q);
        bn_null(c->d1->secret);
        bn_null(c->d2->secret);

        /* Copys the domain secret of the parent to d1, then generate a new 
         * secret for d2 */ 
        bn_new(N);
        pc_get_ord(N); 
        bn_rand_mod(root->d2->secret, N);
        bn_copy(root->d1->secret, root->d2->secret);

        /* Hash the identity to gen the public key */ 
        mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
        const EVP_MD *EVP_sha3_256(); /* Get the sha3 hash function */
        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */ 
        EVP_DigestUpdate(mdctx, id, strlen(id)); /* Hash the node ID */ 
        EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */ 
        
        /* Map the public key to G1 */ 
        g1_map(root->public_key, hash, sizeof(hash));


        /* Map private key to groups */ 
        g1_map(root->d1->k1, (uint8_t *)root->public_key, sizeof(root->public_key)); 
        g2_map(root->d1->k2, (uint8_t *)root->public_key, sizeof(root->public_key));
        g1_map(root->d2->k1, (uint8_t *)root->public_key, sizeof(root->public_key)); 
        g2_map(root->d2->k2, (uint8_t *)root->public_key, sizeof(root->public_key));

        /* Gen public perameter */ 
        g1_mul(root->Q, root->public_key, root->d2->secret); /* Qx = Qx * x */

       /* Print root for debug */ 
        printf("Root secret: ");
        bn_print(root->d1->secret);
        printf("\n");
        printf("Root cluster secret: ");
        bn_print(root->d2->secret);
        printf("\n");
        printf("Root public key: ");
        g1_print(root->public_key);
        printf("\n");
        printf("Root k1: ");
        g1_print(root->d2->k1);
        printf("\n");
        printf("Root k2: ");
        g2_print(root->d2->k2);
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

    int status, client_fd;
    struct sockaddr_in serv_addr;
    uint8_t buffer[sizeof(key_pair_t)];
    // Connect to root node
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(ROOT_PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0 ) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        printf("\nSocket creation error \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr,
                    sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    // Construct a packet to send 
    printf("Constructing packet...\n");
    aes_packet_t packet;
    packet.type = 0;
    memcpy(packet.identity, identity, id_len);

    // Send request
    uint8_t buf[sizeof(packet)];
    serialize_aes(buf, sizeof(buf), &packet);
    send(client_fd, buf, sizeof(buf), 0);
    printf("Request sent\n");
    read(client_fd, buffer, sizeof(buffer));
    // Deserialize the buffer
    deserialize_k(buffer, sizeof(buffer), gateway);

    // Print the struct for debugging
    printf("Received Key Pairing:\n");
    printf("Gateway secret: ");
    bn_print(gateway->d1->secret);
    printf("\n");
    printf("Gateway cluster secret: ");
    bn_print(gateway->d2->secret);
    printf("\n");
    printf("Gateway public key: ");
    g1_print(gateway->public_key);
    printf("\n");
    printf("Gateway k1: ");
    g1_print(gateway->d1->k1);
    printf("\n");
    printf("Gateway k2: ");
    g2_print(gateway->d1->k2);
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

    int status, client_fd;
    struct sockaddr_in serv_addr;
    uint8_t buffer[sizeof(key_pair_t)] = {0};
    // Connect to gateway/ KDC
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(GATEWAY_PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0 ) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        printf("\nSocket creation error \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr,
                    sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    // Construct a packet to send 
    aes_packet_t packet;
    packet.type = 0;
    memcpy(packet.identity, identity, id_len);
    // Send request
    uint8_t buf[1024] = {0};
    serialize_aes(buf, sizeof(buf), &packet);
    send(client_fd, buf, sizeof(buf), 0);
    printf("Request sent\n");
    read(client_fd, buffer, sizeof(buffer));
    // Deserialize the buffer
    deserialize_k(buffer, sizeof(buffer), worker);

    // Print the struct for debugging
    printf("Received Key Pairing:\n");
    printf("Worker secret: ");
    bn_print(worker->d1->secret);
    printf("\n");
    printf("Worker cluster secret: ");
    bn_print(worker->d2->secret);
    printf("\n");
    printf("Worker public key: ");
    g1_print(worker->public_key);
    printf("\n");
    printf("Worker k1: ");
    g1_print(worker->d1->k1);
    printf("\n");
    printf("Worker k2: ");
    g2_print(worker->d1->k2);
    printf("\n");
    printf("Worker Q: ");
    g1_print(worker->Q);
    printf("\n");

    // Close connection 
    close(client_fd);

    return 0;
}

