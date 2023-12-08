#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include <ascon/ascon.h>

#include "crypto.h"

//     COMPILED WITH ASCON BIT LAYOUT:
//     |.....1...........128.......128....128.......X......|
//     | DECRYPT TAG | IDENTITY | NONCE | TAG | CIPHERTEXT |
//
//     COMPILED WITH AES BIT LAYOUT:
//     |.....1...........128......128......X......|
//     | DECRYPT TAG | IDENTITY | IV | CIPHERTEXT |
//
//     GEN KEY PAIR:
//     |.....1........X.....|
//     | GEN TAG | IDENTITY |

typedef struct {
    uint8_t type;
    char *identity[128];
    uint16_t nonce[ASCON_AEAD_NONCE_LEN];
    uint16_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    char *payload;
} ascon_packet_t;

typedef struct {
    uint8_t type;
    char *identity[128];
    uint16_t iv;
    char *payload;
} aes_packet_t;


int serialize_k(char *buffer, size_t size, key_pair_t *key_pair);
int deserialize_k(char *buffer, size_t size, key_pair_t *key_pair);
int serialize_ascon(char *buffer, size_t size, ascon_packet_t *packet);
int deserialize_ascon(char *buffer, size_t size, ascon_packet_t *packet);
int serialize_aes(char *buffer, size_t size, aes_packet_t *packet);
int deserialize_aes(char *buffer, size_t size, aes_packet_t *packet);

#endif // NETWORK_H
