#include <stdio.h>
#include <stdlib.h>

#include "params.h"
#include "crypto.h"

int serialize(key_pair_t *key_pair, char *buffer, size_t size)
{
    if (size < sizeof(key_pair_t))
    {
        printf("Buffer too small to serialize key pair\n");
        return -1;
    }

    memcpy(buffer, key_pair, sizeof(key_pair_t));

    return 0;
}

int deserialize(key_pair_t *key_pair, char *buffer, size_t size)
{
    if (size < sizeof(key_pair_t))
    {
        printf("Buffer too small to deserialize key pair\n");
        return -1;
    }

    memcpy(key_pair, buffer, sizeof(key_pair_t));

    return 0;
}
