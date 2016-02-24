/**
 * @file configuration.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli configuration header
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <dirent.h>

/**
 * @brief The CLI XML config options.
 */
struct cli_opts {
	char* config_editor;
};

/**
 * @brief Finds the current user's netconf dir
 * @return NULL on failure, dynamically allocated netconf dir path
 * otherwise
 */
char *get_netconf_dir(void);

/**
 * @brief Finds the default certificate and optionally key file,
 * the supplied pointers must be empty (*cert == NULL)
 * @param[out] cert path to the certificate (and perhaps also key),
 * no change on error
 * @param[out] key path to the private key, no change if the key
 * is included in cert
 */
void get_default_client_cert(char **cert, char **key);

/**
 * @brief Finds the default trusted CA certificate directory
 * @return ret_dir == NULL: NULL on failure, dynamically allocated trusted CA dir path
 * otherwise, ret_dir != NULL: always NULL, on success *ret_dir is opened trusted CA
 * dir, not modified on error
 */
char *get_default_trustedCA_dir(DIR **ret_dir);

/**
 * @brief Finds the default CRL directory
 * @return ret_dir == NILL: NULL on failure, dynamically allocated CRL dir path otherwise,
 * ret_dir != NULL: always NULL, on success *ret_dir is opened CRL dir, not modified
 * on error
 */
char *get_default_CRL_dir(DIR **ret_dir);

/**
 * @brief Checks all the relevant files and directories creating any
 * that are missing, sets the saved configuration
 */
void load_config(void);

/**
 * @brief Saves the current configuration and command history
 */
void store_config(void);

#endif /* CONFIGURATION_H_ */
