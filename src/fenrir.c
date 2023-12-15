#include "crypto.h"
#include "network.c"
#include "crypto.c"
#include "network.h"
#include "params.h"
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

int main(int argc, char *argv[])
{
    // Server socket values
    int server_fd, new_socket;
    size_t readreq;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    uint8_t reqbuffer[1024] = { 0 };

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

    if (DEVICE_TYPE == ROOT) {
        printf("Setting up root...\n");
        key_pair_t root;
        char *identity = "root"; /* Identity */
        if (device_setup_root(&root, identity, strlen(identity)) < 0) {
            printf("Failed to setup root exiting!\n");
        }
        printf("Root setup complete\n");
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
        address.sin_port = htons(ROOT_PORT);
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("Bind failed exiting!\n");
            goto exit;
        }
        printf("Listening for connections...\nServer IP: %s\n", inet_ntoa(address.sin_addr));
        printf("Server port: %d\n", ROOT_PORT);

        while (1) {
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

            aes_packet_t packet;
            deserialize_aes(reqbuffer, sizeof(reqbuffer), &packet);
            printf("Received request from client\n");
            if (packet.type == 0 ) {
                key_pair_t child;
                if (bilinear_key_pair(&child, packet.identity, 
                            sizeof(packet.identity), &root, (bn_st *)&root.cluster_secret) != RLC_OK) {
                    printf("Failed to generate key pair exiting!\n");
                    goto exit;
                }
                printf("Key pair generated\n");
                // Serialize and send the struct
                uint8_t buffer[sizeof(child)];
                serialize_k(buffer, sizeof(buffer), &child);
                send(new_socket, buffer, sizeof(buffer), 0);
                printf("Key pair sent\n");
            } else {
                printf("Invalid request type exiting!\n");
                close(new_socket);
                close(server_fd);
                goto exit;
            }
        }
        close(new_socket);
        close(server_fd);
    } else if (DEVICE_TYPE == GATEWAY) {
        printf("Setting up KDC...\n");
        key_pair_t gateway;
        key_pair_t gateway2;
        char *identity = "gateway"; /* Identity */
        if (device_setup_gateway(&gateway, identity, strlen(identity)) != RLC_OK) {
            printf("Failed to setup KDC exiting!\n");
        }
        printf("Setting up connection...\n");
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
        address.sin_port = htons(GATEWAY_PORT);
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("Bind failed exiting!\n");
            goto exit;
        }
        printf("Listening for connections...\nServer IP: %s\n", inet_ntoa(address.sin_addr));
        printf("Server port: %d\n", GATEWAY_PORT);
        while (1) {
            // MAKE MULTITHREADED
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
            aes_packet_t packet;
            if ((readreq = read(new_socket, reqbuffer, 1024 - 1)) < 0) {
                perror("Read failed exiting!\n");
                goto exit;
            }
            printf("Received request from client\n");
            deserialize_aes(reqbuffer, sizeof(reqbuffer), &packet);

           if (packet.type == 0) {
                printf("Generating key pair...\n");
                key_pair_t child;
                if (bilinear_key_pair(&child, packet.identity, 
                            sizeof(packet.identity), &gateway, (bn_st *)&gateway.cluster_secret) != RLC_OK) {
                    printf("Failed to generate key pair exiting!\n");
                    goto exit;
                }
                printf("Key pair generated\n");
                uint8_t keybuffer[sizeof(child)];
                serialize_k(keybuffer, sizeof(keybuffer), &child);
                send(new_socket, keybuffer, sizeof(keybuffer), 0);
                printf("Key pair sent\n");

            } else if (packet.type == 1){
                printf("Decrypting request...\n");
                if (CYPHER == AES) {
                    printf("Decrypting AES...\n");
                    aes_packet_t packet;
                    uint8_t *key;
                    key = RLC_ALLOCA(uint8_t, 128);

                    deserialize_aes(reqbuffer, sizeof(packet), &packet);
                    sok_gen_sym_key(key, &gateway, packet.identity, sizeof(packet.identity));
                    printf("\nKey: ");
                    for (int i = 0; i < 16; i++) {
                        printf("%02x", key[i]);
                    }
                    printf("\n");

                    unsigned char *plaintext = malloc(sizeof(packet.payload));
                    aes_dec(plaintext, (unsigned char*)packet.payload, sizeof(packet.payload), key, packet.iv, sizeof(packet.iv));

                    printf("AES decrypted\n");
                    printf("Msg: %s\n", plaintext);
                } else if (CYPHER == ASCON) {
                    printf("Decrypting ASCON...\n");
                    ascon_packet_t packet;
                    unsigned char *key;
                    char *plaintext;

                    deserialize_ascon((char *)reqbuffer, sizeof(reqbuffer), &packet);
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
        serv_addr.sin_port = htons(GATEWAY_PORT);
        if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0 ) {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }
        client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client_fd < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }

        if ((status = connect(client_fd, (struct sockaddr*)&serv_addr,
                        sizeof(serv_addr))) < 0) {
            printf("\nConnection Failed \n");
            return -1;
        }
        char *gateway = "gateway";
        // Encrypt and send request 
        if (CYPHER == AES) {
            printf("Encrypting AES...\n");
            uint8_t *key;
            key = RLC_ALLOCA(uint8_t, 128);
            uint8_t iv[16] = {0};
            unsigned char ciphertext[1024];

            sok_gen_sym_key(key, &node, gateway, strlen(gateway));
            printf("\nKey: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", key[i]);
            }
            printf("\n");
            aes_enc(ciphertext, (unsigned char*)identity, strlen(identity), key, (unsigned char*)iv, sizeof(iv));
            uint8_t buffer[sizeof(aes_packet_t)];

            // Construct the packet 
            printf("Constructing packet...\n");
            aes_packet_t packet;
            packet.type = 1;
            memcpy(packet.identity, node.public_key, sizeof(node.public_key));
            memcpy(packet.iv, iv, sizeof(iv));
            packet.payload_length = strlen((char *)ciphertext);
            packet.payload = strdup((char *)ciphertext);
            packet.payload[strlen(packet.payload)] = '\0';

            serialize_aes(buffer, sizeof(buffer), &packet);
            printf("Sending request to gateway...\n");
            send(client_fd, buffer, sizeof(buffer), 0);
            free(packet.payload);

        } else if (CYPHER == ASCON) {
            printf("Encrypting ASCON...\n");
            ascon_packet_t packet;
            uint8_t *key;
            uint8_t nonce[ASCON_AEAD_NONCE_LEN] = {0};
            uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
            char *buffer;

            sok_gen_sym_key(key, &node, gateway, strlen(gateway));
            ascon_enc((unsigned char*)buffer, identity, strlen(identity), tag,  key, nonce);
            serialize_ascon(buffer, sizeof(buffer), &packet);
            send(client_fd, buffer, sizeof(buffer), 0);

        } else {
            printf("Invalid cypher exiting!\n");
            close(client_fd);
            goto exit;
        }
        close(client_fd);
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

