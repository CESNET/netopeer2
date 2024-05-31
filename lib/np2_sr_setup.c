/**
 * @file np2_sr_setup.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server sysrepo YANG module setup library
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "np2_sr_yang.h"

#define ERR(msg, ...) fprintf(stderr, msg "\n", __VA_ARGS__)
#define ERRMSG(msg) fprintf(stderr, msg "\n")

int
np2_sr_setup(const char *owner, const char *group, mode_t perm)
{
    int rc = 0, fd, r, i, mod_count;
    sr_conn_ctx_t *conn = NULL;
    sr_install_mod_t *mods = NULL;

    /* log */
    sr_log_stderr(SR_LL_WRN);

    /* connect */
    if (sr_connect(0, &conn)) {
        ERRMSG("Failed to connect to sysrepo.");
        rc = 1;
        goto cleanup;
    }

    /* print all the modules into files */
    for (i = 0; yang_files[i].file; ++i) {
        fd = open(yang_files[i].file, O_WRONLY | O_CREAT | O_TRUNC, 00600);
        if (fd < 0) {
            ERR("Failed to create \"%s\".", yang_files[i].file);
            rc = 1;
            goto cleanup;
        }

        r = write(fd, yang_files[i].data, yang_files[i].len);
        close(fd);

        if (r != yang_files[i].len) {
            ERR("Failed to write \"%s\".", yang_files[i].file);
            rc = 1;
            goto cleanup;
        }
    }

    /* prepare modules to install */
    mods = calloc(yang_install_count, sizeof *mods);
    if (!mods) {
        ERRMSG("Failed to allocate memory.");
        rc = 1;
        goto cleanup;
    }
    mod_count = 0;
    for (i = 0; i < yang_install_count; ++i) {
        mods[mod_count].schema_path = yang_install[i];
        mods[mod_count].features = yang_features[i];
        mods[mod_count].owner = owner;
        mods[mod_count].group = group;
        mods[mod_count].perm = perm;

        ++mod_count;
    }

    /* install modules */
    if (mod_count && sr_install_modules2(conn, mods, mod_count, ".", NULL, NULL, 0)) {
        ERRMSG("Failed to install modules.");
        rc = 1;
        goto cleanup;
    }

cleanup:
    free(mods);
    sr_disconnect(conn);
    for (i = 0; yang_files[i].file; ++i) {
        unlink(yang_files[i].file);
    }
    return rc;
}
