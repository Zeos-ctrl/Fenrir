#ifdef CRYPTO_H
#define CRYPTO_H

#include <relic/relic.h>

#define BUF_SIZE 4096

struct key_pair /* Key pair struct */
{
    g1_t public_key; /* Public key member of G1 */
    g1_t private_key; /* Private key member of G1 */
    g1_t public_peram; /* Public perameter member of G1 */
    bn_t secret; /* Secret value member of Z */
};

void gen_key_pair(struct key_pair *child, char *child_id,
        struct key_pair *parent, bn_t master);

int ascon_enc(uint8_t *buffer, size_t plaintext_len, char *plaintext, 
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN]);

int ascon_dec(uint8_t *buffer, size_t ciphertext_len, uint8_t *tag,
        uint8_t key[ASCON_AEAD128_KEY_LEN], uint8_t nonce[ASCON_AEAD_NONCE_LEN]);

int aes_enc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        unsigned char *iv, unsigned char *ciphertext);

int aes_dec(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *decryptedtext)

#endif // CRYPTO_H
