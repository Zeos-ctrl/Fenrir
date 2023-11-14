#include <relic/relic.h>
#include <relic/relic_bn.h>
#include <relic/relic_cp.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../include/crypto.h"

// This function is called to set up the root node. It generates the bilinear 
// pairing groups, the master secret key, and the public parameter Qr.
// Path: setup.c
// Parameters:
//    none
void device_setup_root()
{
    size_t i;
    bn_t master; /* Master secret */
    bn_t order; /* Order of the group */
    g1_t public_key; /* Public key */
    g1_t private_key; /* Private key */
    char *identity = "root"; /* Identity */

    bn_null(master);
    bn_null(order);
    g1_null(public_key);
    g1_null(private_key);

    bn_new(master); /* Initialize master secret */
    pc_get_ord(order); /* Get the order of the group */ 
    bn_rand_mod(master, order); /* Generate random master secret */

    /* Hash Identity to gen pub key */
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */

    mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
    const EVP_MD *EVP_sha3_256() /* Get the md5 hash function */;

    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
    EVP_DigestUpdate(mdctx, identity, strlen(identity)); /* Hash the node ID */
    EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */

    g1_map(public_key, hash, sizeof(hash)); /* Map public key to G1 */

    /* Gen public parameter: Q = master secret + public key */ 
    g1_t master_public;
    g1_add(master_public, master, public_key);

    // Prints values for debugging
    printf("Master secret root: \n");
    bn_print(master);
    printf("\nQ: \n");
    g1_print(master_public);
    printf("\nPublic key root: \n");
    /* Print the value for debugging */
    for (i = 0; i < md_len; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n\nPrivate key root: \n");
    g1_print(private_key);
    printf("\nIdentity root: %s\n", identity);

    /* Clean up memory */ 
    bn_free(master);
    g1_free(public_key);
    g1_free(private_key);
    g1_free(master_public);
    EVP_MD_CTX_free(mdctx);

    return;
}

// This function is called to set up the gateway node. It sends the gateways 
// id to the root node and receives the public key, private key, shared value 
// and secret value from the root node.
// Path: setup.c
// Parameters:
//   none
void device_setup_gateway()
{
    char *identity = "gateway";
    return;
}

// This function is called to set up the worker node. It sends the workers id
// to the gateway node and receives the public key, private key, shared value 
// and secret value from the gateway node.
// Path: setup.c
// Parameters:
//  none
void device_setup_worker()
{
    char *identity = "worker";
    return;
}

