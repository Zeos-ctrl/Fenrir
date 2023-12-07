#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include "crypto.h"

int serialize(key_pair_t *key_pair, char *buffer, size_t size);
int deserialize(key_pair_t *key_pair, char *buffer, size_t size);

#endif // NETWORK_H
