#include <relic/relic.h>
#include <relic/relic_err.h>
#include <relic/relic_pc.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../include/crypto.h"

struct key_pair /* Key pair struct */
{
    g1_t public_key; /* Public key member of G1 */
    g1_t private_key; /* Private key member of G1 */
    g1_t public_peram; /* Public perameter member of G1 */
    bn_t secret; /* Secret value member of Z */
};

/*
 * This function is ran on the Parent node and gens the public and private keys 
 * for the requesting Child node, returning the public key, private key, shared value, and 
 * secret value. <sPk, Pk, x, Qx> 
 * Path: crypto.c 
 * Parameters:
 *  int node_id: The ID of the node requesting to join the network 
 *  struct key_pair *parent: The perameters for the parent node 
 *  struct key_pair *child: The empty struct for the child node 
*/
void gen_key_pair(char *child_id, struct key_pair *parent, struct key_pair *child)
{
    size_t i;
    bn_t secret_value;
    bn_t order;
    g1_t public_key;
    g1_t private_key;
    g1_t public_peram;

    bn_null(secret_value);
    bn_null(order);
    g1_null(private_key);
    g1_null(public_key);
    g1_null(public_peram);

    /* Hash Identity to gen pub key */
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */

    mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
    const EVP_MD *EVP_sha3_256() /* Get the sha3 hash function */;

    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
    EVP_DigestUpdate(mdctx, child_id, strlen(child_id)); /* Hash the node ID */
    EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */

    g1_map(public_key, hash, sizeof(hash)); /* Map public key to G1 */

    /* Gen private key: priv_key = gateway_root_secret * public_key + private_key_gateway */
    g1_t str; 
    g1_add(str, parent->secret, public_key); /* Should be mul */
    g1_add(private_key, parent->private_key, str);

    bn_new(secret_value); /* Gen secret value */
    pc_get_ord(order); /* Get the order of the group */ 
    bn_rand_mod(secret_value, order); /* Gen random value in Zq */

    /* Gen public perameter: public_peram = shared_value * private_key_root */
    g1_mul(public_peram, secret_value, parent->private_key);

    /* Prints values for debugging */
    printf("Node secret: \n");
    bn_print(secret_value);
    printf("\nPublic key: \n");
    /* Print the value for debugging */
    for (i = 0; i < md_len; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\nPrivate key node: \n");
    g1_print(private_key);
    printf("\nIdentity node: %s\n", child_id);

    /* Save key info */

    /* Clean up memory */ 
    bn_free(master);
    g1_free(public_key);
    g1_free(private_key);
    g1_free(str);
    EVP_MD_CTX_free(mdctx);

    return;
}

/* 
 * This function is used to encrypt a message using the symmetric key gend 
 * to send to the other node using the PRESENT cipher.
 * Path: crypto.c
 * Parameters:
 *  char *message: The message to be encrypted 
 *  int message_len: The length of the message 
 *  char *key: The symmetric key to encrypt the message with 
 *  int key_len: The length of the symmetric key 
void encrypt_with_sym_key(char *message, int message_len, char *key, int key_len)
{
    return;
}
*/

/* 
 * This function is used to decrypt a message using the symmetric key send 
 * using the PRESENT cipher.
 * Path: crypto.c
 * Parameters:
 *  char *message: The message to be decrypted 
 *  int message_len: The length of the message 
 *  char *key: The symmetric key to decrypt the message with 
 *  int key_len: The length of the symmetric key
void decrypt_with_sym_key(char *message, int message_len, char *key, int key_len)
{
    return;
}
*/

/* 
 * This function is used to decrypt a message sent from outside the local domain 
 *
 * Received as Ciphertext = <C0, C1, V> the worker can decrypt the message using 
 * its secret key as follows: 
 *
 * nodes secret key = gateway secret key + nodes public key * secret element pG, 
 * where pG is the secret point known only by the gateway and the worker node. 
 * d = (e(C0, nodes secret key) / e(public perameter Qw, C1)) 
 * m = V XOR H2(d) 
 * Path: crypto.c 
 * Parameters: 
 *  char *message: The message to be decrypted 
 *  int message_len: The length of the message 
 *  struct key_pair *receiver: The public, private key pair of the receiving node  
 *  char *pub_key: The public key of the sending node
void dec_cipher_inter(char *message, int message_len, struct key_pair *receiver, char *pub_key)
{
    return;
}
*/

// This function is used to encrypt a message to send to a node outside the local domain
//
// Ciphertext = <rPkr, rPkn, H2(g^r) XOR m>, where 
// r is a random number in the set Zq not including 0, Pkr is the public key of
// the root node, Pkn is the public key of the node receiving the message, H2 is 
// a hash function, g is a generator of the group G1, and m is the message.
// Path: crypto.c
// Parameters:
//  char *message: The message to be encrypted
//  int message_len: The length of the message 
//  struct key_pair *sender: The public, private key pair of the sending node 
//  char *pub_key_receiver: The public key of the receiving node
/*
void enc_cipher_inter(char *message, int message_len, struct key_pair *sender, char *pub_key_receiver)
{
    return;
}
*/
// This function is used to gen the symmetric key using the public key of 
// the receiving node and the public, private key pair of the sending node using 
// bilinear pairing. (SOK key agreement)
// Path: crypto.c
// Parameters:
//   struct key_pair *sender: The public, private key pair of the sending node 
//   char *receiver: The public key of the receiving node 
/*
void sok_gen_sym_key(struct key_pair *sender, char *receiver)
{
    return;
}
*/
