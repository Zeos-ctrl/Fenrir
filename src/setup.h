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

/**
 * Displays the key parameters to the user
 * @param[in] params - The key parameters to display
 * @return void
 */
void display_params(key_params_t *params);

#endif // SETUP_H
