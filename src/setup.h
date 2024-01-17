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
 * Sets up the gateway
 *
 * @param[out] gateway_key_params - The key information for the gateway
 * @param[in] identity - The identity of the device
 * @param[in] id_len - The length of the identity
 * @return 0 on success, -1 on failure
 */
int setup_gateway(key_params_t *gateway, char *identity, size_t id_len);

/**
 * Sets up the node
 *
 * @param[out] node_key_params - The key information for the worker
 * @param[in] identity - The identity of the device
 * @param[in] id_len - The length of the identity
 * @return 0 on success, -1 on failure
 */
int setup_node(key_params_t *worker, char *identity, size_t id_len);

#endif // SETUP_H
