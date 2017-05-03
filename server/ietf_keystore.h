/**
 * @file ietf_keystore.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-keystore libnetconf2 callbacks
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_IETF_KEYSTORE_H_
#define NP2SRV_IETF_KEYSTORE_H_

int np_hostkey_clb(const char *name, void *user_data, char **privkey_path, char **privkey_data, int *privkey_data_rsa);

int np_server_cert_clb(const char *name, void *user_data, char **cert_path, char **cert_data, char **privkey_path,
                       char **privkey_data, int *privkey_data_rsa);

int np_trusted_cert_list_clb(const char *name, void *user_data, char ***cert_paths, int *cert_path_count,
                             char ***cert_data, int *cert_data_count);

#endif
