#include <stdio.h>
#include <stdlib.h>

#include "network.h"
#include "params.h"
#include "crypto.h"

int serialize_k(char *buffer, size_t size, key_pair_t *key_pair)
{
    printf("Serializing key pair\n");
    if (size < sizeof(key_pair_t)) {
        printf("Buffer too small to serialize key pair\n");
        return -1;
    }
    memcpy(buffer, key_pair, sizeof(key_pair_t));
    return 0;
}

int deserialize_k(char *buffer, size_t size, key_pair_t *key_pair)
{
    printf("Deserializing key pair\n");
    if (size < sizeof(key_pair_t)) {
        printf("Buffer too small to deserialize key pair\n");
        return -1;
    }
    memcpy(key_pair, buffer, sizeof(key_pair_t));
    return 0;
}

int serialize_ascon(char *buffer, size_t size, ascon_packet_t *packet)
{
    printf("Serializing ASCON packet\n");
    if (size < sizeof(ascon_packet_t)) {
        printf("Buffer too small to serialize ascon packet\n");
        return -1;
    }
    memcpy(buffer, packet, sizeof(ascon_packet_t));
    return 0;
}

int deserialize_ascon(char *buffer, size_t size, ascon_packet_t *packet)
{
    printf("Deserializing ASCON packet\n");
    if (size < sizeof(ascon_packet_t)) {
        printf("Buffer too small to deserialize ascon packet\n");
        return -1;
    }
    memcpy(packet, buffer, sizeof(ascon_packet_t));
    return 0;
}

int serialize_aes(uint8_t *buffer, size_t size, aes_packet_t *packet)
{
    printf("Serializing AES packet\n");
    if (size < sizeof(aes_packet_t)) {
        printf("Buffer too small to serialize aes packet\n");
        return -1;
    }

    buffer[0] = packet->type;
    memcpy(buffer + 1, packet->identity, 128);
    memcpy(buffer + 129, packet->iv, 16);
    memcpy(buffer + 145, packet->payload, PACKET_SIZE - 145);

    return 0;
}

int deserialize_aes(char *buffer, size_t size, aes_packet_t *packet)
{
    printf("Deserializing AES packet\n");
    if (size < sizeof(aes_packet_t)) {
        printf("Buffer too small to deserialize aes packet\n");
        return -1;
    }
    packet->type = buffer[0];
    memcpy(packet->identity, buffer + 1, 128);
    memcpy(packet->iv, buffer + 129, 16);
    memcpy(packet->payload, buffer + 145, PACKET_SIZE - 145);

    return 0;
}
