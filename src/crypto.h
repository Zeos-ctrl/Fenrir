#ifndef CRYPTO_H
#define CRYPTO_H

#include <relic/relic.h>
#include <ascon/ascon.h>

#define BUF_SIZE 4096

typedef struct key_pair /* Key pair struct */
{
    g1_t public_key; /* Public key member of G1 */
    g1_t k1; /* Private key member of G1 */
    g2_t k2; /* Private key member of G2 */
    g1_t Q; /* Public perameter member of G1 */
    bn_t secret; /* Secret value member of Z */
} key_pair_t;

/**
 * Generates the bilinear key pair for a requesting node
 *
 * @param[out] key_pair_t *key_pair - The key pair to be generated
 * @param[in] char *id - The id of the requesting node
 * @param[in] size_t id_len - The length of the id
 * @param[in] key_pair_t *parent - The key pair of the parent node
 * @param[in] bn_t master - The master secret value
 * @return int - RLC_OK if successful, RLC_ERR otherwise
 */
int bilinear_key_pair(key_pair_t *child, char *child_id, size_t child_id_len,
        key_pair_t *parent, bn_t master);
/**
 * Encrypts a message using the ascon cipher 
 *
 * @param[out] uint8_t *buffer - The buffer to store the ciphertext 
 * @param[out] uint8_t tag - The tag for the ciphertext 
 * @param[in] char *plaintext - The plaintext to be encrypted
 * @param[in] size_t plaintext_len - The length of the plaintext 
 * @param[in] uint8_t key - The key to be used for encryption
 * @param[in] uint8_t nonce - The nonce to be used for encryption
 * @return int - length of the ciphertext
 */
int ascon_enc(uint8_t *buffer, char *plaintext, size_t plaintext_len,
        uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN],
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN]);
/**
 * Decrypts a message using the ascon cipher 
 * 
 * @param[out] uint8_t *buffer - The buffer to store the plaintext 
 * @param[in] size_t ciphertext_len - The length of the ciphertext 
 * @param[in] uint8_t *tag - The tag for the ciphertext 
 * @param[in] uint8_t key - The key to be used for decryption
 * @param[in] uint8_t nonce - The nonce to be used for decryption
 * @return int - length of the plaintext
 */
int ascon_dec(uint8_t *buffer, size_t ciphertext_len, uint8_t *tag,
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN]);
/** 
 * Encrypts a message using the AES cipher 
 *
 * @param[out] unsigned char *ciphertext - The buffer to store the ciphertext 
 * @param[in] unsigned char *plaintext - The plaintext to be encrypted
 * @param[in] int plaintext_len - The length of the plaintext 
 * @param[in] unsigned char *key - The key to be used for encryption 
 * @param[in] unsigned char *iv - The initialization vector to be used for encryption
 * @return int - The length of the ciphertext
 */
int aes_enc(unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len,
        unsigned char *key, unsigned char *iv);
/** 
 * Decrypts a message using the AES cipher 
 *
 * @param[out] unsigned char *decryptedtext - The buffer to store the plaintext 
 * @param[in] unsigned char *ciphertext - The ciphertext to be decrypted 
 * @param[in] int ciphertext_len - The length of the ciphertext 
 * @param[in] unsigned char *key - The key to be used for decryption 
 * @param[in] unsigned char *iv - The initialization vector to be used for decryption
 * @return int - The length of the decrypted text
 */
int aes_dec(unsigned char *decryptedtext, unsigned char *ciphertext, int ciphertext_len,
        unsigned char *key, unsigned char *iv);
/**
 * Generates a symmetric key for a given sender and receiver 
 * using sakai-kasahara non-interactive key exchange 
 *
 * @param[out] uint8_t *buf - The buffer to store the symmetric key 
 * @param[in] key_pair_t *sender - The key pair of the sender 
 * @param[in] char *receiver - The id of the receiver
 * @param[in] size_t id_len - The length of the id
 * @return int - RLC_OK if successful, RLC_ERR otherwise
 */
int sok_gen_sym_key(uint8_t *buf, key_pair_t *sender, char *receiver, size_t id_len);

#endif // CRYPTO_H
