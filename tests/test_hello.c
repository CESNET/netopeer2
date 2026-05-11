/**
 * @file test_hello.c
 * @author Vincent Jardin
 * @brief test NETCONF hello capability advertisement
 *
 * @copyright
 * Copyright (c) 2026 Free Mobile, Vincent Jardin.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>

#include "np2_test.h"
#include "np2_test_config.h"

static int
local_setup(void **state)
{
    char test_name[256];
    const char *modules[] = {
        NP_TEST_MODULE_DIR "/edit1.yang",   /* YANG 1.0 */
        NP_TEST_MODULE_DIR "/notif2.yang",  /* YANG 1.1 */
        NULL
    };
    int rc;

    np2_glob_test_setup_test_name(test_name);

    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    rc = np2_glob_test_setup_server(state, test_name, modules, NULL, 0);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"edit1", "notif2", NULL};

    if (*state) {
        return np2_glob_test_teardown(state, modules);
    }

    return 0;
}

static void
test_yang10_in_hello(void **state)
{
    struct np2_test *st = *state;
    const char *cpblt;

    /* YANG 1.0 modules must be advertised in hello capabilities (RFC 6241) */
    cpblt = nc_session_cpblt(st->nc_sess, "urn:ed1?module=edit1");
    assert_non_null(cpblt);
}

static void
test_yang11_not_in_hello(void **state)
{
    struct np2_test *st = *state;
    const char *cpblt;

    /* YANG 1.1 modules must NOT be in hello capabilities per RFC 7950 section 1.1:
     * "A server advertises support for YANG 1.1 modules by using ietf-yang-library
     *  instead of listing them as capabilities in the <hello> message."
     * Clients should discover YANG 1.1 modules via ietf-yang-library. */
    cpblt = nc_session_cpblt(st->nc_sess, "urn:n2?module=notif2");
    assert_null(cpblt);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_yang10_in_hello),
        cmocka_unit_test(test_yang11_not_in_hello),
    };

    if (argc > 1) {
        parse_arg(argc, argv);
    }

    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
