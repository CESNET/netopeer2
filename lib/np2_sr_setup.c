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

#include "netopeer2.h"

#include <stdint.h>
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

/**
 * @brief libyang import callback.
 */
static LY_ERR
np2_sr_setup_ly_imp_cb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *submod_rev,
        void *user_data, LYS_INFORMAT *format, const char **module_data, ly_module_imp_data_free_clb *free_module_data)
{
    uint32_t i;
    const char *name, *revision;

    (void)user_data;

    if (submod_name) {
        name = submod_name;
        revision = submod_rev;
    } else {
        name = mod_name;
        revision = mod_rev;
    }

    for (i = 0; yang_files[i].file; ++i) {
        if (!strcmp(yang_files[i].name, name) && (!revision || !strcmp(yang_files[i].revision, revision))) {
            *format = LYS_IN_YANG;
            *module_data = yang_files[i].data;
            *free_module_data = NULL;
            return LY_SUCCESS;
        }
    }

    return LY_ENOTFOUND;
}

int
np2_sr_setup(const char *owner, const char *group, mode_t perm)
{
    int rc = 0, i;
    uint32_t j, mod_count;
    sr_conn_ctx_t *conn = NULL;
    sr_install_mod_t *mods = NULL;
    struct ly_ctx *ly_ctx;

    /* log */
    sr_log_stderr(SR_LL_WRN);

    /* connect */
    if (sr_connect(0, &conn)) {
        ERRMSG("Failed to connect to sysrepo.");
        rc = 1;
        goto cleanup;
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
        /* find the module */
        for (j = 0; yang_files[j].file; ++j) {
            if (!strcmp(yang_files[j].file, yang_install[i])) {
                break;
            }
        }
        if (!yang_files[j].file) {
            ERR("Failed to find YANG data of \"%s\".", yang_install[i]);
            rc = 1;
            goto cleanup;
        }

        mods[mod_count].schema_yang = yang_files[j].data;
        mods[mod_count].features = yang_features[i];
        mods[mod_count].owner = owner;
        mods[mod_count].group = group;
        mods[mod_count].perm = perm;

        ++mod_count;
    }

    /* use import callback to provide all the YANG modules */
    ly_ctx = (struct ly_ctx *)sr_acquire_context(conn);
    ly_ctx_set_module_imp_clb(ly_ctx, np2_sr_setup_ly_imp_cb, NULL);
    sr_release_context(conn);

    /* install modules */
    if (mod_count && sr_install_modules2(conn, mods, mod_count, NULL, NULL, NULL, 0)) {
        ERRMSG("Failed to install modules.");
        rc = 1;
        goto cleanup;
    }

cleanup:
    free(mods);
    sr_disconnect(conn);
    return rc;
}
