#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include <ascon/ascon.h>

#include "crypto.h"
#include "params.h"

/* The ascon packet structure */
typedef struct {
    char identity[128]; /* The identity of the sender */ 
    char partial_key[128]; /* The partial SOK key */
    unsigned char nonce[ASCON_AEAD_NONCE_LEN]; /* The nonce */
    unsigned char tag[ASCON_AEAD_TAG_MIN_SECURE_LEN]; /* The tag to verify the enc */
    size_t payload_length; /* The length of the payload */
    char *payload; /* The encrypted payload */
} ascon_packet_t;

/* The aes packet structure */
typedef struct {
    char identity[128]; /* The identity of the sender */
    char partial_key[128]; /* The partial SOK key */
    uint8_t iv[16]; /* The iv */
    size_t payload_length; /* The length of the payload */
    char *payload; /* The encrypted payload */
} aes_packet_t;

/**
 *  The Packet header structure, the type is the type of packet encapsulated
 *  in the buffer and the operation is the requested operation to be performed 
 *  on the packet.
 */
typedef struct {
    enum PacketType type;
    enum NetworkOperation operation;
    uint8_t *buffer;
} PacketHeader;

void serializePacket(PacketHeader *header, uint8_t *buffer, size_t data_size);

void deserializePacket(PacketHeader *header, void* data, size_t data_size);
/**
 * Serializes the key pair into a buffer
 *
 * @param[out] buffer - The buffer to serialize into
 * @param[in] size - The size of the buffer
 * @param[in] key_pair - The key pair to serialize
 * @return 0 on success, -1 on failure
 */
int serialize_k(uint8_t *buffer, size_t size, key_pair_t *key_pair);

/**
 * Deserializes the key pair from a buffer
 *
 * @param[in] buffer - The buffer to deserialize from
 * @param[in] size - The size of the buffer
 * @param[out] key_pair - The key pair to deserialize into
 * @return 0 on success, -1 on failure
 */
int deserialize_k(uint8_t *buffer, size_t size, key_pair_t *key_pair);

/**
 * Serializes the ascon packet into a buffer
 *
 * @param[out] buffer - The buffer to serialize into
 * @param[in] size - The size of the buffer
 * @param[in] packet - The packet to serialize
 * @return 0 on success, -1 on failure
 */
int serialize_ascon(char *buffer, size_t size, ascon_packet_t *packet);

/**
 * Deserializes the ascon packet from a buffer
 *
 * @param[in] buffer - The buffer to deserialize from
 * @param[in] size - The size of the buffer
 * @param[out] packet - The packet to deserialize into
 * @return 0 on success, -1 on failure
 */
int deserialize_ascon(char *buffer, size_t size, ascon_packet_t *packet);

/**
 * Serializes the aes packet into a buffer
 *
 * @param[out] buffer - The buffer to serialize into
 * @param[in] size - The size of the buffer
 * @param[in] packet - The packet to serialize
 * @return 0 on success, -1 on failure
 */
int serialize_aes(uint8_t *buffer, size_t size, aes_packet_t *packet);

/**
 * Deserializes the aes packet from a buffer
 *
 * @param[in] buffer - The buffer to deserialize from
 * @param[in] size - The size of the buffer
 * @param[out] packet - The packet to deserialize into
 * @return 0 on success, -1 on failure
 */
int deserialize_aes(uint8_t *buffer, size_t size, aes_packet_t *packet);

#endif // NETWORK_H
