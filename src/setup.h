#ifndef SETUP_H
#define SETUP_H

#include "crypto.h"

/**
 * Sets up the root key server device
 *
 * @param[out] root_key_pair - The key information for the root node
 * @param[in] identity - The identity of the device
 * @param[in] id_len - The length of the identity
 * @return 0 on success, -1 on failure
 */
int device_setup_root(key_pair_t *root, char *identity, size_t id_len);

/**
 * Sets up the gateway device
 *
 * @param[out] gateway_key_pair - The key information for the gateway
 * @param[in] identity - The identity of the device
 * @param[in] id_len - The length of the identity
 * @return 0 on success, -1 on failure
 */
int device_setup_gateway(key_pair_t *gateway, char *identity, size_t id_len);

/**
 * Sets up the worker device
 *
 * @param[out] worker_key_pair - The key information for the worker
 * @param[in] identity - The identity of the device
 * @param[in] id_len - The length of the identity
 * @return 0 on success, -1 on failure
 */
int device_setup_worker(key_pair_t *worker, char *identity, size_t id_len);

#endif // SETUP_H
