#include <assert.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */
#include <relic/relic.h> /* RELIC headers for elliptic curve crypto */
#include <relic/relic_bn.h>
#include <relic/relic_core.h>
#include <relic/relic_err.h>
#include <relic/relic_pc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int test_hash(void)
{
    printf("\nTesting hash function...\n");
    size_t i;
    unsigned int md_len; /* Hash length */
    EVP_MD_CTX *mdctx; /* Hashing context */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Hash value */
    char *id = "test"; /* Identity */

    mdctx = EVP_MD_CTX_new(); /* Initialize ctx */ 
    const EVP_MD *EVP_sha3_256() /* Get the sha3 hash function */;

    if (mdctx == NULL) {
        fprintf(stderr, "Error creating MD context\n");
        return 1; // Return an error code
    }

    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL); /* Initialize the hash function */
    EVP_DigestUpdate(mdctx, id, strlen(id)); /* Hash the ID */
    EVP_DigestFinal_ex(mdctx, hash, &md_len); /* Finalize the hash function */

    /* Print the value for debugging */
    for (i = 0; i < md_len; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}

static int allocate_memory(void)
{
    int code = RLC_ERR;
    RLC_TRY {
        bn_t a;
        bn_null(a);
        bn_new(a);
        bn_free(a);
    }
    RLC_CATCH_ANY {
        RLC_ERROR(end);
    }
    code = RLC_OK;
end:
    return code;
}

static int gen_perams(void)
{
    bn_t secret;
    bn_t n;
    g1_t public;
    g1_t parent_private;
    g1_t priv;
    g1_t Q;
    int code = RLC_ERR;

    bn_null(secret);
    bn_null(n);
    g1_null(public);
    g1_null(parent_private);
    g1_null(priv);
    g1_null(Q);

    printf("\nGenerating parameters...\n");
    RLC_TRY {
        bn_new(n);
        pc_get_ord(n);
        bn_rand_mod(secret, n);

        g1_new(public);
        g1_new(parent_private);

        g1_t str;
        g1_null(str);

        g1_add(str, secret, public);
        g1_add(priv, parent_private, str);

        g1_add(Q, secret, parent_private);

        printf("Public key: \n");
        g1_print(public);
        printf("Private key: \n");
        g1_print(priv);
        printf("Q: \n");
        g1_print(Q);
        printf("Secret: \n");
        bn_print(secret);
    }
    RLC_CATCH_ANY {
        RLC_ERROR(end);
    }
    code = RLC_OK;
end:
    bn_free(secret);
    bn_free(order);
    g1_free(public);
    g1_free(parent_private);
    g1_free(priv);
    g1_free(Q);

    return code;
}

int main(void)
{
    printf("Starting tests...\n");

    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    if (pc_param_set_any() != RLC_OK) {
        core_clean();
        return 1;
    }

    if(test_hash() != 0) {
        return 1;
    }

    printf("Hash test passed!\n");

    if (allocate_memory() != RLC_OK){
        return 1;
    }

    printf("\nMemory allocation test passed!\n");

    if (gen_perams() != RLC_OK){
        return 1;
    }

    printf("Parameter generation test passed!\n");
    
    core_clean();
    return 0;
}
