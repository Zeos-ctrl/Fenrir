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

void gen_key_pair(char *child_id, struct key_pair *parent, struct key_pair *child);

#endif // CRYPTO_H
