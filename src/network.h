#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include <ascon/ascon.h>

#include "crypto.h"
/**
 * Packet Types:
 *
 *     COMPILED WITH ASCON BIT LAYOUT:
 *     |.....1...........128.......128....128.......X......|
 *     | DECRYPT TAG | IDENTITY | NONCE | TAG | CIPHERTEXT |
 *
 *     COMPILED WITH AES BIT LAYOUT:
 *     |.....1...........128......128......X......|
 *     | DECRYPT TAG | IDENTITY | IV | CIPHERTEXT |
 *
 *     GEN KEY PAIR:
 *     |.....1........X.....|
 *     | GEN TAG | IDENTITY |
 */

/* The ascon packet structure */
typedef struct {
    uint8_t type; /* The type of operation, 0 - gen key, 1 - decrypt message */
    char identity[128]; /* The identity of the sender */ 
    unsigned char nonce[ASCON_AEAD_NONCE_LEN]; /* The nonce */
    unsigned char tag[ASCON_AEAD_TAG_MIN_SECURE_LEN]; /* The tag to verify the enc */
    char *payload; /* The encrypted payload */
} ascon_packet_t;

/* The aes packet structure */
typedef struct {
    uint8_t type; /* The type of operation, 0 - gen key, 1 - decrypt message */ 
    char identity[128]; /* The identity of the sender */
    uint8_t iv[16]; /* The iv */
    char *payload; /* The encrypted payload */
} aes_packet_t;

/**
 * Serializes the key pair into a buffer
 *
 * @param[out] buffer - The buffer to serialize into
 * @param[in] size - The size of the buffer
 * @param[in] key_pair - The key pair to serialize
 * @return 0 on success, -1 on failure
 */
int serialize_k(char *buffer, size_t size, key_pair_t *key_pair);

/**
 * Deserializes the key pair from a buffer
 *
 * @param[in] buffer - The buffer to deserialize from
 * @param[in] size - The size of the buffer
 * @param[out] key_pair - The key pair to deserialize into
 * @return 0 on success, -1 on failure
 */
int deserialize_k(char *buffer, size_t size, key_pair_t *key_pair);

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
int serialize_aes(char *buffer, size_t size, aes_packet_t *packet);

/**
 * Deserializes the aes packet from a buffer
 *
 * @param[in] buffer - The buffer to deserialize from
 * @param[in] size - The size of the buffer
 * @param[out] packet - The packet to deserialize into
 * @return 0 on success, -1 on failure
 */
int deserialize_aes(char *buffer, size_t size, aes_packet_t *packet);

#endif // NETWORK_H
