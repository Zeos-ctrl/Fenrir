#include <stdio.h>
#include <stdlib.h>

#include "network.h"
#include "params.h"
#include "crypto.h"

int serialize_k(uint8_t *buffer, size_t size, key_pair_t *key_pair)
{
    printf("Serializing key pair\n");
    if (size < sizeof(key_pair_t)) {
        printf("Buffer too small to serialize key pair\n");
        return -1;
    }
    memcpy(buffer, key_pair, sizeof(key_pair_t));
    return 0;
}

int deserialize_k(uint8_t *buffer, size_t size, key_pair_t *key_pair)
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
    if (size < sizeof(uint8_t) + sizeof(packet->identity) + sizeof(packet->nonce) +
               sizeof(packet->tag) + sizeof(size_t)) {
        printf("Buffer too small to serialize ascon packet\n");
        return -1;
    }

    // Serialize the fixed-size fields
    size_t offset = 0;
    buffer[offset++] = packet->type;
    memcpy(buffer + offset, packet->identity, sizeof(packet->identity));
    offset += sizeof(packet->identity);
    memcpy(buffer + offset, packet->nonce, sizeof(packet->nonce));
    offset += sizeof(packet->nonce);
    memcpy(buffer + offset, packet->tag, sizeof(packet->tag));
    offset += sizeof(packet->tag);

    // Serialize the payload length and the payload itself
    memcpy(buffer + offset, &packet->payload_length, sizeof(size_t));
    offset += sizeof(size_t);
    if (packet->payload_length > 0) {
        if (size - offset < packet->payload_length) {
            printf("Buffer too small to serialize payload\n");
            return -1;
        }
        memcpy(buffer + offset, packet->payload, packet->payload_length);
        offset += packet->payload_length;
    }

    return 0;
}

int deserialize_ascon(char *buffer, size_t size, ascon_packet_t *packet)
{
    if (size < sizeof(uint8_t) + sizeof(packet->identity) + sizeof(packet->nonce) +
               sizeof(packet->tag) + sizeof(size_t)) {
        printf("Buffer too small to deserialize ascon packet\n");
        return -1;
    }

    // Deserialize the fixed-size fields
    size_t offset = 0;
    packet->type = buffer[offset++];
    memcpy(packet->identity, buffer + offset, sizeof(packet->identity));
    offset += sizeof(packet->identity);
    memcpy(packet->nonce, buffer + offset, sizeof(packet->nonce));
    offset += sizeof(packet->nonce);
    memcpy(packet->tag, buffer + offset, sizeof(packet->tag));
    offset += sizeof(packet->tag);

    // Deserialize the payload length
    memcpy(&packet->payload_length, buffer + offset, sizeof(size_t));
    offset += sizeof(size_t);

    // Allocate memory for the payload
    if (packet->payload_length > 0) {
        packet->payload = malloc(packet->payload_length);
        if (packet->payload == NULL) {
            printf("Memory allocation failed\n");
            return -1;
        }

        // Deserialize the payload
        if (size - offset < packet->payload_length) {
            printf("Buffer too small to deserialize payload\n");
            free(packet->payload);
            return -1;
        }
        memcpy(packet->payload, buffer + offset, packet->payload_length);
    } else {
        // No payload, set payload pointer to NULL
        packet->payload = NULL;
    }

    return 0;
}

int serialize_aes(uint8_t *buffer, size_t size, aes_packet_t *packet)
{
    if (size < sizeof(uint8_t) + sizeof(packet->identity) + sizeof(packet->iv) + sizeof(size_t)) {
        printf("Buffer too small to serialize aes packet\n");
        return -1;
    }

    // Serialize the fixed-size fields
    size_t offset = 0;
    buffer[offset++] = packet->type;
    memcpy(buffer + offset, packet->identity, sizeof(packet->identity));
    offset += sizeof(packet->identity);
    memcpy(buffer + offset, packet->iv, sizeof(packet->iv));
    offset += sizeof(packet->iv);

    // Serialize the payload length
    memcpy(buffer + offset, &packet->payload_length, sizeof(size_t));
    offset += sizeof(size_t);

    // Serialize the payload
    if (packet->payload_length > 0) {
        if (size - offset < packet->payload_length) {
            printf("Buffer too small to serialize payload\n");
            return -1;
        }
        memcpy(buffer + offset, packet->payload, packet->payload_length);
        offset += packet->payload_length;
    }

    return 0;
}

int deserialize_aes(uint8_t *buffer, size_t size, aes_packet_t *packet)
{
    if (size < sizeof(uint8_t) + sizeof(packet->identity) + sizeof(packet->iv) + sizeof(size_t)) {
        printf("Buffer too small to deserialize aes packet\n");
        return -1;
    }

    // Deserialize the fixed-size fields
    size_t offset = 0;
    packet->type = buffer[offset++];
    memcpy(packet->identity, buffer + offset, sizeof(packet->identity));
    offset += sizeof(packet->identity);
    memcpy(packet->iv, buffer + offset, sizeof(packet->iv));
    offset += sizeof(packet->iv);

    // Deserialize the payload length
    memcpy(&packet->payload_length, buffer + offset, sizeof(size_t));
    offset += sizeof(size_t);

    // Allocate memory for the payload
    if (packet->payload_length > 0) {
        packet->payload = malloc(packet->payload_length);
        if (packet->payload == NULL) {
            printf("Memory allocation failed\n");
            return -1;
        }

        // Deserialize the payload
        if (size - offset < packet->payload_length) {
            printf("Buffer too small to deserialize payload\n");
            free(packet->payload);
            return -1;
        }
        memcpy(packet->payload, buffer + offset, packet->payload_length);
    } else {
        // No payload, set payload pointer to NULL
        packet->payload = NULL;
    }

    return 0;
}
