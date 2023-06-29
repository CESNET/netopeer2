/**
 * @file configuration.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli configuration
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#ifndef HAVE_EACCESS
#define eaccess access
#endif

#include "commands.h"
#include "compat.h"
#include "configuration.h"
#include "linenoise/linenoise.h"

struct cli_opts opts = { .output_format = LYD_XML };

/* NetConf Client home (appended to ~/) */
#define NCC_DIR ".netopeer2-cli"
/* all these appended to NCC_DIR */
#define CA_DIR "certs"
#define CRL_DIR "crl"
#define CERT_CRT "client.crt"
#define CERT_PEM "client.pem"
#define CERT_KEY "client.key"

char *
get_netconf_dir(void)
{
    int ret;
    struct passwd *pw;
    char *user_home, *netconf_dir;

    if (!(pw = getpwuid(getuid()))) {
        ERROR("get_netconf_dir", "Determining home directory failed: getpwuid: %s.", strerror(errno));
        return NULL;
    }
    user_home = pw->pw_dir;

    if (asprintf(&netconf_dir, "%s/%s", user_home, NCC_DIR) == -1) {
        ERROR("get_netconf_dir", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        return NULL;
    }

    ret = mkdir(netconf_dir, 00700);
    if (!ret) {
        ERROR("get_netconf_dir", "Configuration directory \"%s\" did not exist, created.", netconf_dir);
    } else if (errno != EEXIST) {
        ERROR("get_netconf_dir", "Configuration directory \"%s\" cannot be created: %s", netconf_dir, strerror(errno));
        free(netconf_dir);
        return NULL;
    }

    return netconf_dir;
}

void
get_default_client_cert(char **cert, char **key)
{
    char *netconf_dir;
    struct stat st;
    int ret;

    assert(cert && !*cert);
    assert(key && !*key);

    if (!(netconf_dir = get_netconf_dir())) {
        return;
    }

    // trying to use *.crt and *.key format
    if ((asprintf(cert, "%s/%s", netconf_dir, CERT_CRT) == -1) || (asprintf(key, "%s/%s", netconf_dir, CERT_KEY) == -1)) {
        ERROR("get_default_client_cert", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR("get_default_client_cert", "Unable to use the default client certificate due to the previous error.");
        free(netconf_dir);
        return;
    }

    if ((eaccess(*cert, R_OK) == -1) || (eaccess(*key, R_OK) == -1)) {
        if (errno != ENOENT) {
            ERROR("get_default_client_cert", "Unable to access \"%s\" and \"%s\": %s", *cert, *key, strerror(errno));
            free(*key);
            *key = NULL;
            free(*cert);
            *cert = NULL;
            free(netconf_dir);
            return;
        }

        // *.crt & *.key failed, trying to use *.pem format
        free(*key);
        *key = NULL;
        free(*cert);
        if (asprintf(cert, "%s/%s", netconf_dir, CERT_PEM) == -1) {
            ERROR("get_default_client_cert", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
            ERROR("get_default_client_cert", "Unable to use the default client certificate due to the previous error.");
            free(netconf_dir);
            return;
        }

        ret = eaccess(*cert, R_OK);
        if (ret == -1) {
            if (errno != ENOENT) {
                ERROR("get_default_client_cert", "Unable to access \"%s\": %s", *cert, strerror(errno));
            } else {
                // *.pem failed as well
                ERROR("get_default_client_cert", "Unable to find the default client certificate.");
            }
            free(*cert);
            *cert = NULL;
            free(netconf_dir);
            return;
        } else {
            /* check permissions on *.pem */
            if (stat(*cert, &st) != 0) {
                ERROR("get_default_client_cert", "Stat on \"%s\" failed: %s", *cert, strerror(errno));
            } else if (st.st_mode & 0066) {
                ERROR("get_default_client_cert", "Unsafe permissions on \"%s\"", *cert);
            }
        }
    } else {
        /* check permissions on *.key */
        if (stat(*key, &st) != 0) {
            ERROR("get_default_client_cert", "Stat on \"%s\" failed: %s", *key, strerror(errno));
        } else if (st.st_mode & 0066) {
            ERROR("get_default_client_cert", "Unsafe permissions on \"%s\"", *key);
        }
    }

    free(netconf_dir);
}

char *
get_default_trustedCA_dir(DIR **ret_dir)
{
    char *netconf_dir, *cert_dir;

    if (!(netconf_dir = get_netconf_dir())) {
        return NULL;
    }

    if (asprintf(&cert_dir, "%s/%s", netconf_dir, CA_DIR) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to use the trusted CA directory due to the previous error.");
        free(netconf_dir);
        return NULL;
    }
    free(netconf_dir);

    if (ret_dir) {
        if (!(*ret_dir = opendir(cert_dir))) {
            ERROR(__func__, "Unable to open the default trusted CA directory (%s).", strerror(errno));
        }
        free(cert_dir);
        return NULL;
    }

    errno = 0;
    if (eaccess(cert_dir, R_OK | W_OK | X_OK)) {
        if (errno == ENOENT) {
            ERROR(__func__, "Default trusted CA directory does not exist, creating it.");
            if (mkdir(cert_dir, 00777)) {
                ERROR(__func__, "Failed to create the default trusted CA directory (%s).", strerror(errno));
                free(cert_dir);
                return NULL;
            }
        } else {
            ERROR(__func__, "Unable to access the default trusted CA directory (%s).", strerror(errno));
            free(cert_dir);
            return NULL;
        }
    }

    return cert_dir;
}

char *
get_default_CRL_dir(DIR **ret_dir)
{
    char *netconf_dir, *crl_dir;

    if (!(netconf_dir = get_netconf_dir())) {
        return NULL;
    }

    if (asprintf(&crl_dir, "%s/%s", netconf_dir, CRL_DIR) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to use the trusted CA directory due to the previous error.");
        free(netconf_dir);
        return NULL;
    }
    free(netconf_dir);

    if (ret_dir) {
        if (!(*ret_dir = opendir(crl_dir))) {
            ERROR(__func__, "Unable to open the default CRL directory (%s).", strerror(errno));
        }
        free(crl_dir);
        return NULL;
    }

    errno = 0;
    if (eaccess(crl_dir, R_OK | W_OK | X_OK)) {
        if (errno == ENOENT) {
            ERROR(__func__, "Default CRL dir does not exist, creating it.");
            if (mkdir(crl_dir, 00777)) {
                ERROR(__func__, "Failed to create the default CRL directory (%s).", strerror(errno));
                free(crl_dir);
                return NULL;
            }
        } else {
            ERROR(__func__, "Unable to access the default CRL directory (%s).", strerror(errno));
            free(crl_dir);
            return NULL;
        }
    }

    return crl_dir;
}

void
load_history(void)
{
    char *netconf_dir = NULL, *history_file = NULL;

    if ((netconf_dir = get_netconf_dir()) == NULL) {
        goto cleanup;
    }

    if (asprintf(&history_file, "%s/history", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to load commands history due to the previous error.");
        history_file = NULL;
        goto cleanup;
    }

    if (eaccess(history_file, F_OK) && (errno == ENOENT)) {
        ERROR(__func__, "No saved history.");
    } else if (linenoiseHistoryLoad(history_file)) {
        ERROR(__func__, "Failed to load history.");
    }

cleanup:
    free(netconf_dir);
    free(history_file);
}

void
store_history(void)
{
    char *netconf_dir = NULL, *history_file = NULL;

    if ((netconf_dir = get_netconf_dir()) == NULL) {
        goto cleanup;
    }

    if (asprintf(&history_file, "%s/history", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to store commands history due to the previous error.");
        history_file = NULL;
        goto cleanup;
    }

    if (linenoiseHistorySave(history_file)) {
        ERROR(__func__, "Failed to save history.");
    }

cleanup:
    free(netconf_dir);
    free(history_file);
}

void
load_config(void)
{
    char *netconf_dir = NULL, *config_file = NULL;
    struct lyd_node *config = NULL, *child;
    struct ly_ctx *ctx = NULL;

#ifdef NC_ENABLED_SSH
    const char *key_pub, *key_priv;
    struct lyd_node *auth_child, *pref_child, *key_child, *pair_child;
#endif

    if ((netconf_dir = get_netconf_dir()) == NULL) {
        goto cleanup;
    }

    if (ly_ctx_new(NULL, 0, &ctx)) {
        ERROR(__func__, "Failed to create context.");
        ERROR(__func__, "Unable to load configuration due to the previous error.");
        goto cleanup;
    }

    if (asprintf(&config_file, "%s/config.xml", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to load configuration due to the previous error.");
        config_file = NULL;
        goto cleanup;
    } else if (eaccess(config_file, F_OK) && (errno == ENOENT)) {
        ERROR(__func__, "No saved configuration.");
        goto cleanup;
    }

    if (lyd_parse_data_path(ctx, config_file, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ, 0, &config)) {
        ERROR(__func__, "Failed to load configuration of NETCONF client (lyxml_read_path failed).");
        goto cleanup;
    }

    if (strcmp(LYD_NAME(config), "netconf-client")) {
        ERROR(__func__, "Unknown stored configuration data.");
        goto cleanup;
    }

    LY_LIST_FOR(lyd_child(config), child) {
        if (!strcmp(LYD_NAME(child), "editor")) {
            /* <netconf-client> -> <editor> */
            free(opts.config_editor);
            opts.config_editor = strdup(lyd_get_value(child));
        } else if (!strcmp(LYD_NAME(child), "searchpath")) {
            /* <netconf-client> -> <searchpath> */
            errno = 0;
            if (!mkdir(lyd_get_value(child), 00700) || (errno == EEXIST)) {
                if (errno == 0) {
                    ERROR(__func__, "Search path \"%s\" did not exist, created.", lyd_get_value(child));
                }
                nc_client_set_schema_searchpath(lyd_get_value(child));
            } else {
                ERROR(__func__, "Search path \"%s\" cannot be created (%s).", lyd_get_value(child), strerror(errno));
            }
        } else if (!strcmp(LYD_NAME(child), "output-format")) {
            /* <netconf-client> -> <output-format> */
            if (!strcmp(lyd_get_value(child), "json")) {
                opts.output_format = LYD_JSON;
                opts.output_flag = 0;
            } else if (!strcmp(lyd_get_value(child), "json_noformat")) {
                opts.output_format = LYD_JSON;
                opts.output_flag = LYD_PRINT_SHRINK;
            } else if (!strcmp(lyd_get_value(child), "xml_noformat")) {
                opts.output_format = LYD_XML;
                opts.output_flag = LYD_PRINT_SHRINK;
            } /* else default (formatted XML) */
        }
#ifdef NC_ENABLED_SSH
        else if (!strcmp(LYD_NAME(child), "authentication")) {
            /* <netconf-client> -> <authentication> */
            LY_LIST_FOR(lyd_child(child), auth_child) {
                if (!strcmp(LYD_NAME(auth_child), "pref")) {
                    LY_LIST_FOR(lyd_child(auth_child), pref_child) {
                        if (!strcmp(LYD_NAME(pref_child), "publickey")) {
                            nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, atoi(lyd_get_value(pref_child)));
                        } else if (!strcmp(LYD_NAME(pref_child), "interactive")) {
                            nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, atoi(lyd_get_value(pref_child)));
                        } else if (!strcmp(LYD_NAME(pref_child), "password")) {
                            nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, atoi(lyd_get_value(pref_child)));
                        }
                    }
                } else if (!strcmp(LYD_NAME(auth_child), "keys")) {
                    LY_LIST_FOR(lyd_child(auth_child), key_child) {
                        if (!strcmp(LYD_NAME(key_child), "pair")) {
                            key_pub = NULL;
                            key_priv = NULL;
                            LY_LIST_FOR(lyd_child(key_child), pair_child) {
                                if (!strcmp(LYD_NAME(pair_child), "public")) {
                                    key_pub = lyd_get_value(pair_child);
                                } else if (!strcmp(LYD_NAME(pair_child), "private")) {
                                    key_priv = lyd_get_value(pair_child);
                                }
                            }
                            if (key_pub && key_priv) {
                                nc_client_ssh_ch_add_keypair(key_pub, key_priv);
                                nc_client_ssh_add_keypair(key_pub, key_priv);
                            }
                        }
                    }
                }
            }
        }
#endif /* ENABLE_SSH */
    }

cleanup:
    lyd_free_tree(config);
    ly_ctx_destroy(ctx);
    free(config_file);
    free(netconf_dir);
}

void
store_config(void)
{
    char *netconf_dir = NULL, *history_file = NULL, *config_file = NULL, buf[23];
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL, *auth, *pref, *keys, *pair;
    const char *str, *ns = "urn:cesnet:netconf-client";

    if (ly_ctx_new(NULL, 0, &ctx)) {
        ERROR(__func__, "Failed to create context.");
        ERROR(__func__, "Unable to store configuration due to the previous error.");
        goto cleanup;
    }

    if (lyd_new_opaq2(NULL, ctx, "netconf-client", NULL, NULL, ns, &root)) {
        goto cleanup;
    }

    /* editor */
    if (lyd_new_opaq2(root, NULL, "editor", opts.config_editor, NULL, ns, NULL)) {
        goto cleanup;
    }

    /* search-path */
    if (nc_client_get_schema_searchpath()) {
        if (lyd_new_opaq2(root, NULL, "searchpath", nc_client_get_schema_searchpath(), NULL, ns, NULL)) {
            goto cleanup;
        }
    }

    /* output-format */
    if (opts.output_format == LYD_JSON) {
        str = opts.output_flag ? "json_noformat" : "json";
    } else {
        str = opts.output_flag ? "xml_noformat" : "xml";
    }
    if (lyd_new_opaq2(root, NULL, "output-format", str, NULL, ns, NULL)) {
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    /* SSH authentication */
    if (lyd_new_opaq2(root, NULL, "authentication", NULL, NULL, ns, &auth)) {
        goto cleanup;
    }

    /* pref */
    if (lyd_new_opaq2(auth, NULL, "pref", NULL, NULL, ns, &pref)) {
        goto cleanup;
    }

    sprintf(buf, "%d", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY));
    if (lyd_new_opaq2(pref, NULL, "publickey", buf, NULL, ns, NULL)) {
        goto cleanup;
    }
    sprintf(buf, "%d", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD));
    if (lyd_new_opaq2(pref, NULL, "password", buf, NULL, ns, NULL)) {
        goto cleanup;
    }
    sprintf(buf, "%d", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE));
    if (lyd_new_opaq2(pref, NULL, "interactive", buf, NULL, ns, NULL)) {
        goto cleanup;
    }

    /* keys */
    if (nc_client_ssh_get_keypair_count()) {
        if (lyd_new_opaq2(auth, NULL, "keys", NULL, NULL, ns, &keys)) {
            goto cleanup;
        }

        /* pair(s) */
        for (int i = 0; i < nc_client_ssh_get_keypair_count(); ++i) {
            const char *priv_key, *pub_key;

            nc_client_ssh_get_keypair(i, &pub_key, &priv_key);
            if (lyd_new_opaq2(keys, NULL, "pair", NULL, NULL, ns, &pair)) {
                goto cleanup;
            }
            if (lyd_new_opaq2(pair, NULL, "public", pub_key, NULL, ns, NULL)) {
                goto cleanup;
            }
            if (lyd_new_opaq2(pair, NULL, "private", priv_key, NULL, ns, NULL)) {
                goto cleanup;
            }
        }
    }
#endif

    /* get netconf dir */
    if ((netconf_dir = get_netconf_dir()) == NULL) {
        goto cleanup;
    }

    /* store the config */
    if (asprintf(&config_file, "%s/config.xml", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to store configuration due to the previous error.");
        config_file = NULL;
        goto cleanup;
    }
    if (lyd_print_path(config_file, root, LYD_XML, 0)) {
        goto cleanup;
    }

cleanup:
    lyd_free_tree(root);
    ly_ctx_destroy(ctx);
    free(history_file);
    free(netconf_dir);
    free(config_file);
}
