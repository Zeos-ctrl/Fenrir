#include <assert.h>
#include <openssl/evp.h> /* OpenSSL EVP headers for hashing */
#include <string.h>

int test_hash()
{
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
    
    return 0;
}

int main()
{
    assert(test_hash() == 0);

    return 0;
}
