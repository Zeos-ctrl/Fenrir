#include "crypto.h"
#include "crypto.c"
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

exit:
    printf("Program failed cleaning up...\n");
    core_clean();
    return 1;
}

