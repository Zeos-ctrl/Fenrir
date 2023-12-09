#include "crypto.h"
#include "network.c"
#include "crypto.c"
#include "network.h"
#include "setup.c"

#include <ascon/ascon.h>
#include <relic/relic.h>
#include <relic/relic_pc.h>

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEVICE_TYPE 1
#define CYPHER 1
#define PORT 8080

int main(int argc, char *argv[])
{
    // Server socket values
    int server_fd, new_socket;
    size_t readreq;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char reqbuffer[1024] = { 0 };

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
    printf("%s\n\n",asciiArt);

    // Get device type set in params.h and setup device based on type 
    // Root, KDC, or Worker
    if (DEVICE_TYPE == ROOT) {
        printf("Setting up root...\n");
        key_pair_t root;
        char *identity = "root"; /* Identity */
        if (device_setup_root(&root, identity, strlen(identity)) < 0) {
            printf("Failed to setup root exiting!\n");
        }
        printf("Root setup complete\nWaiting for connections...\n");
        // Open a socket and listen for connections and requests
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket failed exiting!\n");
            goto exit;
        }

        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                    &opt, sizeof(opt))) {
            perror("Setsockopt failed exiting!\n");
            goto exit;
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("Bind failed exiting!\n");
            goto exit;
        }

        if (listen(server_fd, 3) < 0) {
            perror("Listen failed exiting!\n");
            goto exit;
        }

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                        (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed exiting!\n");
            goto exit;
        }
        printf("Connection established!\n");

        if ((readreq = read(new_socket, reqbuffer, 1024 - 1)) < 0) {
            perror("Read failed exiting!\n");
            goto exit;
        }

        ascon_packet_t packet;
        deserialize_ascon(reqbuffer, readreq, &packet);
        printf("Received request from client\n");
        if (packet.type == 0 ) {
            key_pair_t child;
            if (bilinear_key_pair(&child, packet.identity, 
                        sizeof(packet.identity), &root, (bn_st *)&root.secret) != RLC_OK) {
                printf("Failed to generate key pair exiting!\n");
                goto exit;
            }
            printf("Key pair generated\n");
            // Serialize and send the struct
            serialize_k(reqbuffer, sizeof(reqbuffer), &child);
            send(new_socket, reqbuffer, sizeof(reqbuffer), 0);
            printf("Key pair sent\n");
        } else {
            printf("Invalid request type exiting!\n");
            close(new_socket);
            close(server_fd);
            goto exit;
        }

        close(new_socket);
        close(server_fd);
    } else if (DEVICE_TYPE == GATEWAY) {
        printf("Setting up KDC...\n");
        key_pair_t gateway;
        char *identity = "gateway"; /* Identity */
        if (device_setup_gateway(&gateway, identity, strlen(identity)) != RLC_OK) {
            printf("Failed to setup KDC exiting!\n");
        }
        // Open a socket and listen for connections and requests
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket failed exiting!\n");
            goto exit;
        }
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                    &opt, sizeof(opt))) {
            perror("Setsockopt failed exiting!\n");
            goto exit;
        }
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("Bind failed exiting!\n");
            goto exit;
        }
        if (listen(server_fd, 3) < 0) {
            perror("Listen failed exiting!\n");
            goto exit;
        }
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                        (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed exiting!\n");
            goto exit;
        }
        // Either gen key pair for requesting node or decrypt request
        ascon_packet_t packet;
        readreq = read(new_socket, reqbuffer, 1024 - 1);
        printf("Received request from client\n");
        deserialize_ascon(reqbuffer, readreq, &packet);
        printf("%s\n", reqbuffer);

        if (packet.type == 0) {
            printf("Generating key pair...\n");
            key_pair_t child;
            bilinear_key_pair(&child, reqbuffer, sizeof(reqbuffer),
                    &gateway, (bn_st *)&gateway.secret);
            serialize_k(reqbuffer, sizeof(reqbuffer), &child);
            send(new_socket, reqbuffer, sizeof(reqbuffer), 0);
            printf("Key pair sent\n");

        } else if (packet.type == 1){
            printf("Decrypting request...\n");
            if (CYPHER == AES) {
                printf("Decrypting AES...\n");
                aes_packet_t packet;
                unsigned char *key;
                unsigned char plaintext[1024];

                deserialize_aes(reqbuffer, readreq, &packet);
                sok_gen_sym_key(key, &gateway, packet.identity, sizeof(packet.identity));
                aes_dec(plaintext, (unsigned char*)packet.payload, sizeof(packet.payload), key, packet.iv, sizeof(packet.iv));
                printf("AES decrypted\n");
                printf("Msg: %s\n", plaintext);
            } else if (CYPHER == ASCON) {
                printf("Decrypting ASCON...\n");
                ascon_packet_t packet;
                unsigned char *key;
                char *plaintext;

                deserialize_ascon(reqbuffer, readreq, &packet);
                sok_gen_sym_key(key, &gateway, packet.identity, sizeof(packet.identity));
                ascon_dec((unsigned char*)plaintext, sizeof(packet.payload), packet.tag, key, packet.nonce);
                printf("ASCON decrypted\n");
                printf("Msg: %s\n", plaintext);
            } else {
                printf("Invalid cypher exiting!\n");
                close(new_socket);
                close(server_fd);
                goto exit;
            }

        } else {
            printf("Invalid request type exiting!\n");
            close(new_socket);
            close(server_fd);
            goto exit;
        }
        close(new_socket);
        close(server_fd);
    } else if (DEVICE_TYPE == NODE) {
        printf("Setting up worker...\n");
        key_pair_t node;
        int status, client_fd;
        struct sockaddr_in serv_addr;
        char *identity = "node"; /* Identity */
        if (device_setup_worker(&node, identity, strlen(identity)) != RLC_OK) {
            printf("Failed to setup worker exiting!\n");
        }
        // Connect to gateway/ KDC
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0 ) {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }
        if ((status = connect(client_fd, (struct sockaddr*)&serv_addr,
                        sizeof(serv_addr))) < 0) {
            printf("\nConnection Failed \n");
            return -1;
        }
        char *request = "node";
        char *gateway = "gateway";
        // Encrypt and send request 
        if (CYPHER == AES) {
            printf("Encrypting AES...\n");
            aes_packet_t packet;
            unsigned char *key;
            char *iv = "1234567890123456";
            unsigned char ciphertext[1024];
            char *buffer;

            sok_gen_sym_key(key, &node, gateway, strlen(gateway));
            aes_enc(ciphertext, (unsigned char*)request, strlen(request), key, (unsigned char*)iv, strlen(iv));
            serialize_aes(buffer, sizeof(buffer), &packet);
            send(client_fd, buffer, sizeof(buffer), 0);

        } else if (CYPHER == ASCON) {
            printf("Encrypting ASCON...\n");
            ascon_packet_t packet;
            unsigned char *key;
            uint8_t nonce[ASCON_AEAD_NONCE_LEN] = {0};
            uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
            char *buffer;

            sok_gen_sym_key(key, &node, gateway, strlen(gateway));
            ascon_enc((unsigned char*)buffer, request, strlen(request), tag,  key, nonce);
            serialize_ascon(buffer, sizeof(buffer), &packet);
            send(client_fd, buffer, sizeof(buffer), 0);

        } else {
            printf("Invalid cypher exiting!\n");
            close(client_fd);
            goto exit;
        }
        close(client_fd);
        close(server_fd);
    } else {
        printf("Invalid device type exiting!\n");
        goto exit;
    }

    core_clean();
    return 0;

exit:
    printf("Program failed cleaning up...\n");
    core_clean();
    return 1;
}

