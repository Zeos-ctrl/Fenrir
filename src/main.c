#include "network.c"
#include "crypto.c"
#include "setup.c"

#include "../include/params.h"
#include "../include/crypto.h"

#include <relic/relic.h>
#include <relic/relic_pc.h>

int main(int argc, char *argv[])
{
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

    printf("Relic initialized\n\n");

    printf("%s\n\n",asciiArt);

    device_setup_root();

    core_clean();
    return 0;

exit:
    printf("Program failed cleaning up...\n");
    core_clean();
    return 1;
}

