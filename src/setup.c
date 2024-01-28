#include <relic/relic.h>
#include <relic/relic_bn.h>
#include <relic/relic_cp.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "setup.h"
#include "crypto.h"
#include "params.h"


int setup_root(key_params_t *root, char *identity, size_t id_len)
{
    if (id_len < 0 ) {
        printf("Identity must be larger than 0 bytes\n");
        return -1;
    }

    int code = RLC_ERR;
    bn_t N; /* Master secret and order of group */

    /* Hash Identity to gen pub key */
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */


    RLC_TRY {
        /* Check for null pointers */
        if (root == NULL || identity == NULL) {
            RLC_THROW(ERR_NO_VALID);
        }

        bn_null(N);
        bn_null(root->secret);
        g1_null(root->public_key);
        g1_null(root->k1);
        g2_null(root->k2);
        g1_null(root->Q);

        /* Initialize master secret */
        bn_new(N); 
        pc_get_ord(N); /* Get the order of the group */ 
        bn_rand_mod(root->secret, N); /* Generate random master secret */

        mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
        const EVP_MD *EVP_sha3_256() /* Get the md5 hash function */;

        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
        EVP_DigestUpdate(mdctx, identity, strlen(identity)); /* Hash the node ID */
        EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */
        
        g1_map(root->public_key, hash, md_len); /* Map the hash to a point on the curve */

        /* Map private key to groups */
        g1_map(root->k1, (uint8_t *)root->secret, sizeof(root->secret));
        g2_map(root->k2, (uint8_t *)root->secret, sizeof(root->secret));

        /* Compute Q = s * Pubkey */
        g1_mul(root->Q, root->public_key, root->secret);

        display_params(root);

    }RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    }RLC_FINALLY {
        bn_free(N);
        EVP_MD_CTX_free(mdctx);
    }

    code = RLC_OK;
    return code;
}

void display_params(key_params_t *params)
{
    printf("Secret: ");
    bn_print(params->secret);
    printf("\n");
    printf("Public key: ");
    g1_print(params->public_key);
    printf("\n");
    printf("k1: ");
    g1_print(params->k1);
    printf("\n");
    printf("k2: ");
    g2_print(params->k2);
    printf("\n");
    printf("Q: ");
    g1_print(params->Q);
    printf("\n");
}
