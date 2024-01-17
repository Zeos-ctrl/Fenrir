#ifndef SETUP_H
#define SETUP_H

#include "crypto.h"

/**
 * Sets up the root key server
 *
 * @param[out] root_key_params - The key information for the root node
 * @param[in] identity - The identity of the device
 * @param[in] id_len - The length of the identity
 * @return 0 on success, -1 on failure
 */
int setup_root(key_params_t *root, char *identity, size_t id_len);

#endif // SETUP_H
