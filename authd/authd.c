/**
 * @file authd.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Authd plugin for sysrepo
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <sysrepo.h>
#include <sysrepo/plugins.h>

#include "config.h"

struct authd_ctx {
    sr_subscription_ctx_t *subscription;
    sr_session_ctx_t *session;
};

static char *
authd_read_pubkey_skip_type(const char *path)
{
    char *content = NULL;
    unsigned long size;
    FILE *file;

    file = fopen(path, "r");
    if (!file) {
        SRP_LOG_ERR("Opening the file \"%s\" failed (%s).", path, strerror(errno));
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    content = malloc(size + 1);
    if (!content) {
        SRP_LOG_ERR("Memory allocation error (%s).", strerror(errno));
        goto error;
    }

    if (size < 55) {
        SRP_LOG_ERR("File \"%s\" is not a public key in PEM format.", path);
        goto error;
    }

    if (fread(content, 1, 27, file) < 27) {
        SRP_LOG_ERR("Reading from \"%s\" failed (%s).", path, strerror(ferror(file)));
        goto error;
    }
    size -= 27;

    if (strncmp(content, "-----BEGIN PUBLIC KEY-----\n", 27)) {
        SRP_LOG_ERR("File \"%s\" is not a public key in PEM format.", path);
        goto error;
    }

    if (fread(content, 1, size, file) < size) {
        SRP_LOG_ERR("Reading from \"%s\" failed (%s).", path, strerror(ferror(file)));
        goto error;
    }

    if (content[size - 1] == '\n') {
        --size;
    }
    if (strncmp(content + size - 24, "-----END PUBLIC KEY-----", 24)) {
        SRP_LOG_ERR("File \"%s\" is not a public key in PEM format.", path);
        goto error;
    }

    content[size - 24] = '\0';
    fclose(file);
    return content;

error:
    fclose(file);
    free(content);
    return NULL;
}

static int
sysr_add_val(sr_val_t *new, sr_val_t **values, size_t *values_cnt)
{
    void *buf;

    buf = realloc(*values, (*values_cnt + 1) * sizeof **values);
    if (!buf) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        return -1;
    }
    ++(*values_cnt);
    *values = buf;
    (*values)[*values_cnt - 1] = *new;
    return 0;
}

static int
kc_privkey_change_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(module_name), sr_notif_event_t UNUSED(event),
                     void *UNUSED(private_ctx))
{
    /* TODO forbid adding keys this way */
    return SR_ERR_OK;
}

static int
kc_privkey_get_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *UNUSED(private_ctx))
{
    int rc, ret;
    char name[256], *path;
    sr_val_t *val;
    DIR *dir;
    struct dirent buf, *dent;

    SRP_LOG_INF("Providing node \"%s\".", xpath);

    dir = opendir(AUTHD_KEYS_DIR);
    if (!dir) {
        SRP_LOG_ERR("Opening the dir \"%s\" failed (%s).", AUTHD_KEYS_DIR, strerror(errno));
        return SR_ERR_IO;
    }

    while (!(rc = readdir_r(dir, &buf, &dent)) && dent) {
        if ((strlen(dent->d_name) < 4) || strcmp(dent->d_name + strlen(dent->d_name) - 4, ".pem")) {
            continue;
        }
        if ((strlen(dent->d_name) > 8) && !strcmp(dent->d_name + strlen(dent->d_name) - 8, ".pub.pem")) {
            continue;
        }
        strncpy(name, dent->d_name, strlen(dent->d_name) - 4);
        name[strlen(dent->d_name) - 4] = '\0';

        if (!strcmp(strrchr(xpath, '/'), "/algorithm")) {
            /* algorithm */
            val = calloc(1, sizeof *val);
            if (!val) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }

            if (asprintf(&val->xpath, "/ietf-system-keychain:keychain/private-keys/private-key[name='%s']/algorithm", name) == -1) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }
            val->type = SR_IDENTITYREF_T;
            val->data.identityref_val = strdup("rsa");
            if (!val->data.identityref_val) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }

            if (sysr_add_val(val, values, values_cnt)) {
                ret = SR_ERR_NOMEM;
                goto error;
            }
        } else if (!strcmp(strrchr(xpath, '/'), "/key-length")) {
            /* no key-length */

        } else if (!strcmp(strrchr(xpath, '/'), "/public-key")) {
            /* public-key */
            val = calloc(1, sizeof *val);
            if (!val) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }

            if (asprintf(&val->xpath, "/ietf-system-keychain:keychain/private-keys/private-key[name='%s']/public-key", name) == -1) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }
            val->type = SR_BINARY_T;
            if (asprintf(&path, "%s/%s.pub.pem", AUTHD_KEYS_DIR, name) == -1) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }
            val->data.binary_val = authd_read_pubkey_skip_type(path);
            free(path);
            if (!val->data.binary_val) {
                SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
                ret = SR_ERR_NOMEM;
                goto error;
            }

            if (sysr_add_val(val, values, values_cnt)) {
                ret = SR_ERR_NOMEM;
                goto error;
            }
        } else {
            SRP_LOG_ERR("Unknown node \"%s\" value requested.", xpath);
            ret = SR_ERR_INTERNAL;
            goto error;
        }
    }
    if (rc) {
        SRP_LOG_ERR("Reading from a directory failed (%s).", strerror(ret));
        ret = SR_ERR_IO;
        goto error;
    }
    closedir(dir);

    return SR_ERR_OK;

error:
    sr_free_values(*values, *values_cnt);
    *values = NULL;
    *values_cnt = 0;
    sr_free_val(val);
    closedir(dir);
    return ret;
}

static int
kc_privkey_gen_cb(const char *UNUSED(xpath), const sr_node_t *input, const size_t input_cnt, sr_node_t **UNUSED(output),
                  size_t *UNUSED(output_cnt), void *private_ctx)
{
    struct authd_ctx *ctx = (struct authd_ctx *)private_ctx;
    pid_t pid;
    int ret, status;
    sr_val_t *val = NULL;
    char *priv_path = NULL, *pub_path = NULL, len_arg[27];

    if ((input_cnt < 2) || (input[0].type != SR_STRING_T) || (input[1].type != SR_IDENTITYREF_T)
            || ((input_cnt == 3) && (input[2].type != SR_UINT32_T))) {
        SRP_LOG_ERR_MSG("Unexpected input from sysrepo.");
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    if (strcmp(input[1].data.string_val, "rsa")) {
        SRP_LOG_ERR_MSG("Generating EC private keys not supported yet.");
        ret = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    /* TODO check that name is unique */

    if (input_cnt == 3) {
        sprintf(len_arg, "rsa_keygen_bits:%u", input[2].data.uint32_val);
    } else {
        len_arg[0] = '\0';
    }

    priv_path = malloc(strlen(AUTHD_KEYS_DIR) + 1 + strlen(input[0].data.string_val) + 4 + 1);
    pub_path = malloc(strlen(AUTHD_KEYS_DIR) + 1 + strlen(input[0].data.string_val) + 4 + 4 + 1);
    if (!priv_path || !pub_path) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        ret = SR_ERR_NOMEM;
        goto cleanup;
    }
    sprintf(priv_path, "%s/%s.pem", AUTHD_KEYS_DIR, input[0].data.string_val);
    sprintf(pub_path, "%s/%s.pub.pem", AUTHD_KEYS_DIR, input[0].data.string_val);

    if (!(pid = fork())) {
        /* child */
        if (len_arg[0]) {
            execl(OPENSSL_EXECUTABLE, "genrsa", "-out", priv_path, len_arg, NULL);
        } else {
            execl(OPENSSL_EXECUTABLE, "genrsa", "-out", priv_path, NULL);
        }
        SRP_LOG_ERR("Exec failed (%s).", strerror(errno));
        exit(1);
    }

    /* parent */
    if (pid == -1) {
        SRP_LOG_ERR("Fork failed (%s).", strerror(errno));
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    waitpid(pid, &status, 0);
    /* since we are not catching SIGCHLD, we cannot do more... seriously Linux?
    if (waitpid(pid, &status, 0) == -1) {
        SRP_LOG_ERR("Waiting for child process failed (%s).", strerror(errno));
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (!WIFEXITED(status)) {
        SRP_LOG_ERR_MSG("Child process ended in a non-standard way.");
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (WEXITSTATUS(status)) {
        SRP_LOG_ERR("OpenSSL utility returned %d.", WEXITSTATUS(status));
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }*/

    if (!(pid = fork())) {
        /* child */
        execl(OPENSSL_EXECUTABLE, "rsa", "-pubout", "-in", priv_path, "-out", pub_path, NULL);

        SRP_LOG_ERR("Exec failed (%s).", strerror(errno));
        exit(1);
    }

    /* parent */
    if (pid == -1) {
        SRP_LOG_ERR("Fork failed (%s).", strerror(errno));
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    waitpid(pid, &status, 0);
    /*
    if (waitpid(pid, &status, 0) == -1) {
        SRP_LOG_ERR("Waiting for child process failed (%s).", strerror(errno));
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (!WIFEXITED(status)) {
        SRP_LOG_ERR_MSG("Child process ended in a non-standard way.");
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (WEXITSTATUS(status)) {
        SRP_LOG_ERR("OpenSSL utility returned %d.", WEXITSTATUS(status));
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }*/

    /* add the key to the configuration */
    val = calloc(1, sizeof *val);
    if (!val) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        ret = SR_ERR_NOMEM;
        goto cleanup;
    }
    if (asprintf(&val->xpath, "/ietf-system-keychain:keychain/private-keys/private-key[name='%s']",
            input[0].data.string_val) == -1) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        ret = SR_ERR_NOMEM;
        goto cleanup;
    }
    val->type = SR_LIST_T;
    ret = sr_set_item(ctx->session, val->xpath, val, 0);

cleanup:
    free(priv_path);
    free(pub_path);
    sr_free_val(val);
    return ret;
}

static int
sys_auth_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(xpath), sr_notif_event_t UNUSED(event), void *UNUSED(private_ctx))
{
    /* TODO */
    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc;
    struct authd_ctx *ctx;

    ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        goto error;
    }

    /* private keys (for server) */
    rc = sr_subtree_change_subscribe(session, "/ietf-system-keychain:keychain/private-keys/private-key",
                                     kc_privkey_change_cb, ctx, 0, SR_SUBSCR_DEFAULT, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(session, "/ietf-system-keychain:keychain/private-keys/private-key/*",
                                   kc_privkey_get_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    /*rc = sr_action_subscribe_tree(session, "/ietf-system-keychain:keychain/private-keys/private-key/generate-certificate-signing-request",
                                  callback, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    rc = sr_action_subscribe_tree(session, "/ietf-system-keychain:keychain/private-keys/generate-private-key",
                                  kc_privkey_gen_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    /*rc = sr_action_subscribe(session, "/ietf-system-keychain:keychain/private-keys/load-private-key",
                             kc_privkey_load_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    /* trusted certificates (for server/client) */
    rc = sr_subtree_change_subscribe(session, "/ietf-system-keychain:keychain/trusted-certificates",
                                     NULL, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    /*rc = sr_event_notif_subscribe_tree(session, "/ietf-system-keychain:keychain/certificate-expiration",
                                       callback, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    /* trusted SSH host keys (for client) */
    /*rc = sr_subtree_change_subscribe(session, "/ietf-system-keychain:keychain/trusted-ssh-host-keys",
                                     privkeys_change_cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    /* user auth credentials (for client) */
    /*rc = sr_subtree_change_subscribe(session, "/ietf-system-keychain:keychain/user-auth-credentials",
                                       cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    /* user authentication (for server) */
    rc = sr_subtree_change_subscribe(session, "/ietf-system:system/authentication",
                                     sys_auth_cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("authd plugin initialized successfully.");

    ctx->session = session;
    *private_ctx = ctx;
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("authd plugin initialization failed (%s).", sr_strerror(rc));
    sr_unsubscribe(session, ctx->subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    struct authd_ctx *ctx = (struct authd_ctx *)private_ctx;

    sr_unsubscribe(session, ctx->subscription);
    free(ctx);
    SRP_LOG_DBG_MSG("authd plugin cleanup finished.");
}
