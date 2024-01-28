#ifndef CRYPTO_H
#define CRYPTO_H

#include <relic/relic.h>
#include <ascon/ascon.h>

#define BUF_SIZE 4096

typedef struct key_params /* Key parameters struct */
{
    g1_t public_key; /* Public key member of G1 */
    g1_t k1; /* Private key member of G1 */
    g2_t k2; /* Private key member of G2 */
    g1_t Q; /* Public perameter member of G1 */
    bn_t secret; /* Secret value member of Z */
} key_params_t;

/**
 * Generates the key parameters for a requesting node
 *
 * @param[out] key_pair_t *key_pair - The key pair to be generated
 * @param[in] char *id - The id of the requesting node
 * @param[in] size_t id_len - The length of the id
 * @param[in] key_pair_t *parent - The key pair of the parent node
 * @param[in] bn_t master - The master secret value
 * @return int - RLC_OK if successful, RLC_ERR otherwise
 */
int gen_params(key_params_t *child, char *child_id, size_t child_id_len,
        key_params_t *parent, bn_t master);
/**
 * Encrypts a message using the ascon cipher 
 *
 * @param[out] uint8_t *buffer - The buffer to store the ciphertext 
 * @param[out] uint8_t tag - The tag for the ciphertext 
 * @param[in] size_t tag_len - The length of the tag
 * @param[in] char *plaintext - The plaintext to be encrypted
 * @param[in] size_t plaintext_len - The length of the plaintext 
 * @param[in] uint8_t key - The key to be used for encryption
 * @param[in] uint8_t nonce - The nonce to be used for encryption
 * @return int - length of the ciphertext
 */
int ascon_enc(uint8_t *buffer, char *plaintext, size_t plaintext_len,
        uint8_t *tag, size_t tag_len, uint8_t key[ASCON_AEAD128_KEY_LEN],
        uint8_t nonce[ASCON_AEAD_NONCE_LEN]);
/**
 * Decrypts a message using the ascon cipher 
 * 
 * @param[out] uint8_t *buffer - The buffer to store the plaintext 
 * @param[in] size_t ciphertext_len - The length of the ciphertext 
 * @param[in] uint8_t *tag - The tag for the ciphertext 
 * @param[in] size_t tag_len - The length of the tag
 * @param[in] uint8_t key - The key to be used for decryption
 * @param[in] uint8_t nonce - The nonce to be used for decryption
 * @return int - length of the plaintext
 */
int ascon_dec(uint8_t *buffer, size_t ciphertext_len, uint8_t *tag, size_t tag_len,
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
        unsigned char *key, unsigned char iv[16], size_t iv_len);
/** 
 * Decrypts a message using the AES cipher 
 *
 * @param[out] unsigned char *decryptedtext - The buffer to store the plaintext 
 * @param[in] unsigned char *ciphertext - The ciphertext to be decrypted 
 * @param[in] int ciphertext_len - The length of the ciphertext 
 * @param[in] unsigned char *key - The key to be used for decryption 
 * @param[in] unsigned char *iv - The initialization vector to be used for decryption
 * @param[in] size_t iv_len - The length of the initialization vector
 * @return int - The length of the decrypted text
 */
int aes_dec(unsigned char *decryptedtext, unsigned char *ciphertext, int ciphertext_len,
        unsigned char *key, unsigned char iv[16], size_t iv_len);
/**
 * Generates a partial symmetric key for a given sender and receiver 
 * using sakai-kasahara non-interactive key exchange 
 *
 * @param[out] uint8_t *key - The buffer to store the symmetric key 
 * @param[in] key_pair_t *sender - The key pair of the sender 
 * @param[in] char *receiver - The id of the receiver
 * @param[in] size_t id_len - The length of the id
 * @return int - RLC_OK if successful, RLC_ERR otherwise
 */
int sok_gen(uint8_t *buf, key_params_t *sender, char *receiver, size_t id_len);

/**
 *  Derives the full symmetric key from the two partial keys, the upper half 
 *  of the key is derived from the higher level in the heirarchy and the lower 
 *  half of the key is derived from the lower level in the heirarchy.
 *
 *  @param[out] unsigned char *key - The buffer to store the symmetric key 
 *  @param[in] unsigned char *partial_key_upper - The upper half of the key 
 *  @param[in] unsigned char *partial_key_lower - The lower half of the key 
 *  @param[in] size_t key_len - The length of the key 
 *  @return int - The length of the key
 */
int derive_key(unsigned char *upper, size_t upper_len, unsigned char *lower, size_t lower_len,
        uint8_t *key, size_t key_len);

#endif // CRYPTO_H
