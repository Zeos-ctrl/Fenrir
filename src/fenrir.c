#include "network.c"
#include "crypto.c"
#include "setup.c"

#include <relic/relic.h>
#include <relic/relic_pc.h>

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEVICE_TYPE 1
#define PORT 8080

int main(int argc, char *argv[])
{
    // Server socket values
    int server_fd, new_socket;
    size_t valread;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[1024] = { 0 };

    printf("Fenrir starting...\n");

    // Initialize the relic library
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
        char identity[] = "root"; /* Identity */
        if (device_setup_root(&root, &identity) < 0) {
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

        valread = read(new_socket, buffer, 1024 - 1);
        printf("%s\n", buffer);
        // Init the key pairs
        key_pair_t child;
        if (gen_key_pair(&child, buffer, &root, &root.secret) <= 0) {
            printf("Failed to generate key pair exiting!\n");
            goto exit;
        }
        // Serialize and send the struct
        send(new_socket, "Hello from server", strlen("Hello from server"), 0);
        printf("Hello message sent\n");

        // Close connection 
        close(new_socket);
        close(server_fd);


    } else if (DEVICE_TYPE == GATEWAY) {
        printf("Setting up KDC...\n");
        key_pair_t gateway;
        char identity[] = "gateway"; /* Identity */
        if (device_setup_gateway(&gateway, &identity) != RLC_OK) {
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
        valread = read(new_socket, buffer, 1024 - 1);

        // If buffer contains a request for a key pair then generate one
        printf("%s\n", buffer);
        // Init the key pairs
        key_pair_t child;
        gen_key_pair(&child, buffer, &gateway, &gateway.secret);
        // Serialize and send the struct
        send(new_socket, "Hello from server", strlen("Hello from server"), 0);
        printf("Hello message sent\n");

        // Else decrypt the request and send a confirmation

        // Close connection 
        close(new_socket);
        close(server_fd);

    } else if (DEVICE_TYPE == NODE) {
        printf("Setting up worker...\n");
        key_pair_t node;
        char identity[] = "node"; /* Identity */
        if (device_setup_worker(&node, &identity) != RLC_OK) {
            printf("Failed to setup worker exiting!\n");
        }
        // Open a socket and send requests to the gateway

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

