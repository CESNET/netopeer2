/**
 * @file keystored.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief keystored plugin for sysrepo
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

#include <sysrepo.h>
#include <sysrepo/plugins.h>

#include "config.h"

struct keystored_ctx {
    sr_subscription_ctx_t *subscription;
    sr_session_ctx_t *session;
};

static char *
keystored_read_pubkey_skip_type(const char *path)
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
    size -= 24;

    if (content[size - 1] == '\n') {
        --size;
    }

    content[size] = '\0';
    fclose(file);
    return content;

error:
    fclose(file);
    free(content);
    return NULL;
}

static int
ks_privkey_change_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(module_name), sr_notif_event_t UNUSED(event),
                     void *UNUSED(private_ctx))
{
    /* TODO forbid adding keys this way */
    return SR_ERR_OK;
}

static int
ks_cert_change_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(module_name), sr_notif_event_t UNUSED(event),
                  void *UNUSED(private_ctx))
{
    /* nothing to do */
    return 0;
}

static int
ks_privkey_get_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *UNUSED(private_ctx))
{
    int ret;
    const char *name;
    char *path;
    sr_val_t *val = NULL;

    SRP_LOG_INF("Providing node \"%s\".", xpath);

    name = strstr(xpath, "private-key[name='");
    if (!name) {
        SRP_LOG_ERR("Internal error (%s:%d).", __FILE__, __LINE__);
        return SR_ERR_INTERNAL;
    }
    name += 18;

    if (asprintf(&path, "%s/%.*s.pub.pem", KEYSTORED_KEYS_DIR, (int)(strchr(name, '\'') - name), name) == -1) {
        SRP_LOG_ERR("Memory allocation failed (%s:%d).", __FILE__, __LINE__);
        return SR_ERR_NOMEM;
    }

    if (access(path, F_OK) == -1) {
        SRP_LOG_ERR("File \"%s\" could not be accessed (%s).", path, strerror(errno));
        ret = SR_ERR_IO;
        goto error;
    }

    if (!strcmp(xpath + strlen(xpath) - 9, "algorithm")) {
        /* algorithm */
        val = calloc(1, sizeof *val);
        if (!val) {
            SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
            ret = SR_ERR_NOMEM;
            goto error;
        }

        val->xpath = strdup(xpath);
        val->type = SR_IDENTITYREF_T;
        val->data.identityref_val = strdup("rsa");
        if (!val->xpath || !val->data.identityref_val) {
            SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
            ret = SR_ERR_NOMEM;
            goto error;
        }
    } else if (!strcmp(xpath + strlen(xpath) - 10, "key-length")) {
        /* no key-length */

    } else if (!strcmp(xpath + strlen(xpath) - 10, "public-key")) {
        /* public-key */
        val = calloc(1, sizeof *val);
        if (!val) {
            SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
            ret = SR_ERR_NOMEM;
            goto error;
        }

        val->xpath = strdup(xpath);
        val->type = SR_BINARY_T;
        val->data.binary_val = keystored_read_pubkey_skip_type(path);
        if (!val->xpath || !val->data.binary_val) {
            SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
            ret = SR_ERR_NOMEM;
            goto error;
        }
    } else {
        SRP_LOG_ERR("Unknown node \"%s\" value requested.", xpath);
        ret = SR_ERR_INTERNAL;
        goto error;
    }

    if (val) {
        *values = val;
        *values_cnt = 1;
    }

    return SR_ERR_OK;

error:
    sr_free_val(val);
    free(path);
    return ret;
}

struct thread_arg {
    sr_session_ctx_t *session;
    char *key_name;
};

static void *
ks_privkey_add_thread(void *arg)
{
    struct thread_arg *targ = (struct thread_arg *)arg;
    int ret;
    char *xpath;

    if (asprintf(&xpath, "/ietf-keystore:keystore/private-keys/private-key[name='%s']", targ->key_name) == -1) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        return NULL;
    }

    ret = sr_session_switch_ds(targ->session, SR_DS_RUNNING);
    if (ret != SR_ERR_OK) {
        SRP_LOG_ERR("Failed to switch datastore (%s).", sr_strerror(ret));
        goto cleanup;
    }
    ret = sr_set_item(targ->session, xpath, NULL, 0);
    if (ret != SR_ERR_OK) {
        SRP_LOG_ERR("Failed to set item (%s).", sr_strerror(ret));
        goto cleanup;
    }
    ret = sr_commit(targ->session);
    if (ret != SR_ERR_OK) {
        SRP_LOG_ERR("Failed to commit (%s).", sr_strerror(ret));
        goto cleanup;
    }

    ret = sr_session_switch_ds(targ->session, SR_DS_STARTUP);
    if (ret != SR_ERR_OK) {
        SRP_LOG_ERR("Failed to switch datastore (%s).", sr_strerror(ret));
        goto cleanup;
    }
    ret = sr_set_item(targ->session, xpath, NULL, 0);
    if (ret != SR_ERR_OK) {
        SRP_LOG_ERR("Failed to set item (%s).", sr_strerror(ret));
        goto cleanup;
    }
    ret = sr_commit(targ->session);
    if (ret != SR_ERR_OK) {
        SRP_LOG_ERR("Failed to commit (%s).", sr_strerror(ret));
        goto cleanup;
    }

cleanup:
    free(xpath);
    free(targ->key_name);
    free(targ);
    return NULL;
}

static int
ks_privkey_add(sr_session_ctx_t *session, const char *key_name)
{
    int ret;
    pthread_t tid;
    struct thread_arg *targ;

    targ = malloc(sizeof *targ);
    if (!targ) {
        SRP_LOG_ERR("Memory allocation failed (%s:%d).", __FILE__, __LINE__);
        return 1;
    }

    targ->session = session;
    targ->key_name = strdup(key_name);
    if (!targ->key_name) {
        SRP_LOG_ERR("Memoy allocation failed (%s:%d).", __FILE__, __LINE__);
        return 1;
    }

    ret = pthread_create(&tid, NULL, ks_privkey_add_thread, targ);
    if (ret) {
        SRP_LOG_ERR("Creating new thread failed (%s).", strerror(ret));
        return 1;
    }
    pthread_detach(tid);

    return 0;
}

static int
ks_privkey_gen_cb(const char *UNUSED(xpath), const sr_node_t *input, const size_t input_cnt, sr_node_t **UNUSED(output),
                  size_t *UNUSED(output_cnt), void *private_ctx)
{
    struct keystored_ctx *ctx = (struct keystored_ctx *)private_ctx;
    pid_t pid;
    int ret = SR_ERR_OK, status;
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

    priv_path = malloc(strlen(KEYSTORED_KEYS_DIR) + 1 + strlen(input[0].data.string_val) + 4 + 1);
    pub_path = malloc(strlen(KEYSTORED_KEYS_DIR) + 1 + strlen(input[0].data.string_val) + 4 + 4 + 1);
    if (!priv_path || !pub_path) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        ret = SR_ERR_NOMEM;
        goto cleanup;
    }
    sprintf(priv_path, "%s/%s.pem", KEYSTORED_KEYS_DIR, input[0].data.string_val);
    sprintf(pub_path, "%s/%s.pub.pem", KEYSTORED_KEYS_DIR, input[0].data.string_val);

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

    if (chmod(priv_path, 00600) == -1) {
        SRP_LOG_ERR("Changing private key permissions failed (%s).", strerror(errno));
        ret = SR_ERR_IO;
        goto cleanup;
    }

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
    ks_privkey_add(ctx->session, input[0].data.string_val);

cleanup:
    free(priv_path);
    free(pub_path);
    return ret;
}

static int
ks_privkey_load_cb(const char *UNUSED(xpath), const sr_node_t *input, const size_t input_cnt, sr_node_t **UNUSED(output),
                   size_t *UNUSED(output_cnt), void *private_ctx)
{
    struct keystored_ctx *ctx = (struct keystored_ctx *)private_ctx;
    pid_t pid;
    int ret = SR_ERR_OK, status, len, fd;
    char *priv_path = NULL, *pub_path = NULL;
    FILE *privkey = NULL;

    if ((input_cnt != 2) || (input[0].type != SR_STRING_T) || (input[1].type != SR_BINARY_T)) {
        SRP_LOG_ERR_MSG("Unexpected input from sysrepo.");
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    SRP_LOG_INF_MSG("Only RSA keys can be loaded, key presumed to be RSA.");

    /* TODO check that name is unique */

    priv_path = malloc(strlen(KEYSTORED_KEYS_DIR) + 1 + strlen(input[0].data.string_val) + 4 + 1);
    pub_path = malloc(strlen(KEYSTORED_KEYS_DIR) + 1 + strlen(input[0].data.string_val) + 4 + 4 + 1);
    if (!priv_path || !pub_path) {
        SRP_LOG_ERR("Memory allocation failed (%s).", strerror(errno));
        ret = SR_ERR_NOMEM;
        goto cleanup;
    }
    sprintf(priv_path, "%s/%s.pem", KEYSTORED_KEYS_DIR, input[0].data.string_val);
    sprintf(pub_path, "%s/%s.pub.pem", KEYSTORED_KEYS_DIR, input[0].data.string_val);

    fd = open(priv_path, O_CREAT | O_TRUNC | O_WRONLY, 00600);
    if (fd == -1) {
        SRP_LOG_ERR("Failed to open file \"%s\" for writing (%s).", priv_path, strerror(errno));
        ret = SR_ERR_IO;
        goto cleanup;
    }
    privkey = fdopen(fd, "w");
    if (!privkey) {
        SRP_LOG_ERR("Failed to open file \"%s\" for writing (%s).", priv_path, strerror(errno));
        ret = SR_ERR_IO;
        close(fd);
        goto cleanup;
    }
    if ((status = fwrite("-----BEGIN RSA PRIVATE KEY-----\n", 1, 32, privkey)) < 32) {
        if (status == -1) {
            SRP_LOG_ERR("Failed to write to \"%s\" (%s).", priv_path, strerror(errno));
        } else {
            SRP_LOG_ERR("Failed to write to \"%s\" (witten %d instead %d).", priv_path, status, 32);
        }
        ret = SR_ERR_IO;
        goto cleanup;
    }
    len = strlen(input[1].data.binary_val);
    if ((status = fwrite(input[1].data.binary_val, 1, len, privkey)) < len) {
        if (status == -1) {
            SRP_LOG_ERR("Failed to write to \"%s\" (%s).", priv_path, strerror(errno));
        } else {
            SRP_LOG_ERR("Failed to write to \"%s\" (witten %d instead %d).", priv_path, status, len);
        }
        ret = SR_ERR_IO;
        goto cleanup;
    }
    if ((status = fwrite("\n-----END RSA PRIVATE KEY-----\n", 1, 31, privkey)) < 31) {
        if (status == -1) {
            SRP_LOG_ERR("Failed to write to \"%s\" (%s).", priv_path, strerror(errno));
        } else {
            SRP_LOG_ERR("Failed to write to \"%s\" (witten %d instead %d).", priv_path, status, 31);
        }
        ret = SR_ERR_IO;
        goto cleanup;
    }
    fflush(privkey);

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
    ks_privkey_add(ctx->session, input[0].data.string_val);

cleanup:
    if (privkey) {
        fclose(privkey);
    }
    free(priv_path);
    free(pub_path);
    return ret;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc;
    struct keystored_ctx *ctx;

    ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        rc = SR_ERR_NOMEM;
        goto error;
    }

    /* private keys (for server) */
    rc = sr_subtree_change_subscribe(session, "/ietf-keystore:keystore/private-keys/private-key",
                                     ks_privkey_change_cb, ctx, 0, SR_SUBSCR_DEFAULT, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(session, "/ietf-keystore:keystore/private-keys/private-key",
                                   ks_privkey_get_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    /*rc = sr_action_subscribe_tree(session, "/ietf-keystore:keystore/private-keys/private-key/generate-certificate-signing-request",
                                  callback, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    rc = sr_action_subscribe_tree(session, "/ietf-keystore:keystore/private-keys/generate-private-key",
                                  ks_privkey_gen_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_action_subscribe_tree(session, "/ietf-keystore:keystore/private-keys/load-private-key",
                                  ks_privkey_load_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    /* trusted certificates (for server/client) */
    rc = sr_subtree_change_subscribe(session, "/ietf-keystore:keystore/trusted-certificates",
                                     ks_cert_change_cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    /*rc = sr_event_notif_subscribe_tree(session, "/ietf-keystore:keystore/certificate-expiration",
                                       callback, ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    /* trusted SSH host keys (for client) */
    /*rc = sr_subtree_change_subscribe(session, "/ietf-keystore:keystore/trusted-ssh-host-keys",
                                     privkeys_change_cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    /* user auth credentials (for client) */
    /*rc = sr_subtree_change_subscribe(session, "/ietf-keystore:keystore/user-auth-credentials",
                                       cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }*/

    SRP_LOG_DBG_MSG("keystored plugin initialized successfully.");

    ctx->session = session;
    *private_ctx = ctx;
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("keystored plugin initialization failed (%s).", sr_strerror(rc));
    sr_unsubscribe(session, ctx->subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    struct keystored_ctx *ctx = (struct keystored_ctx *)private_ctx;

    sr_unsubscribe(session, ctx->subscription);
    free(ctx);
    SRP_LOG_DBG_MSG("keystored plugin cleanup finished.");
}
