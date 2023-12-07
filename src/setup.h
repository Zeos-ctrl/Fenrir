#ifndef SETUP_H
#define SETUP_H

#include "crypto.h"

int device_setup_root(key_pair_t *root, char *identity);
int device_setup_gateway(key_pair_t *gateway, char *identity);
int device_setup_worker(key_pair_t *worker, char *identity);

#endif // SETUP_H
