#include <stdio.h>
#include <stdlib.h>

#include "network.h"
#include "params.h"
#include "crypto.h"

int serialize_k(char *buffer, size_t size, key_pair_t *key_pair)
{
    if (size < sizeof(key_pair_t))
    {
        printf("Buffer too small to serialize key pair\n");
        return -1;
    }

    memcpy(buffer, key_pair, sizeof(key_pair_t));

    return 0;
}

int deserialize_k(char *buffer, size_t size, key_pair_t *key_pair)
{
    if (size < sizeof(key_pair_t))
    {
        printf("Buffer too small to deserialize key pair\n");
        return -1;
    }

    memcpy(key_pair, buffer, sizeof(key_pair_t));

    return 0;
}

int serialize_ascon(char *buffer, size_t size, ascon_packet_t *packet)
{
    if (size < sizeof(ascon_packet_t))
    {
        printf("Buffer too small to serialize key pair\n");
        return -1;
    }

    memcpy(buffer, packet, sizeof(ascon_packet_t));

    return 0;
}

int deserialize_ascon(char *buffer, size_t size, ascon_packet_t *packet)
{
    if (size < sizeof(ascon_packet_t))
    {
        printf("Buffer too small to deserialize key pair\n");
        return -1;
    }

    memcpy(packet, buffer, sizeof(ascon_packet_t));

    return 0;
}

int serialize_aes(char *buffer, size_t size, aes_packet_t *packet)
{
    if (size < sizeof(aes_packet_t))
    {
        printf("Buffer too small to serialize key pair\n");
        return -1;
    }

    memcpy(buffer, packet, sizeof(aes_packet_t));

    return 0;
}

int deserialize_aes(char *buffer, size_t size, aes_packet_t *packet)
{
    if (size < sizeof(aes_packet_t))
    {
        printf("Buffer too small to deserialize key pair\n");
        return -1;
    }

    memcpy(packet, buffer, sizeof(aes_packet_t));

    return 0;
}
