/**
 * @file np_test.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief base header for netopeer2 testing
 *
 * @copyright
 * Copyright 2021 Deutsche Telekom AG.
 * Copyright 2021 CESNET, z.s.p.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _NP_TEST_H_
#define _NP_TEST_H_

#include <string.h>
#include <unistd.h>

#include <nc_client.h>

/* global setup function specific for a test */
#define NP_GLOB_SETUP_FUNC \
static int \
np_glob_setup(void **state) \
{ \
    char file[64]; \
\
    strcpy(file, __FILE__); \
    file[strlen(file) - 2] = '\0'; \
    return _np_glob_setup(state, strrchr(file, '/') + 1); \
}

/* test state structure */
struct np_test {
    pid_t server_pid;
    struct nc_session *nc_sess;
};

int _np_glob_setup(void **state, const char *test_name);

int np_glob_teardown(void **state);

#endif /* _NP_TEST_H_ */
