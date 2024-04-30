/**
 * @file np2_sr_setup.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server sysrepo YANG module setup library header
 *
 * @copyright
 * Copyright (c) 2024 Deutsche Telekom AG.
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2_SR_SETUP_H_
#define NP2_SR_SETUP_H_

#include <sys/stat.h>

/**
 * @brief Install all YANG modules required by netopeer2-server into sysrepo.
 *
 * Logs to stderr.
 *
 * @param[in] owner Optional owner of the installed modules, process user by default.
 * @param[in] group Optional group of the installed modules, process group or configured sysrepo group by default.
 * @param[in] perm Optional specific permissions of the installed modules.
 * @return 0 on success.
 * @return non-zero on error.
 */
int np2_sr_setup(const char *owner, const char *group, mode_t perm);

#endif /* NP2_SR_SETUP_H_ */
