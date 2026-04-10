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
#include <stdint.h>
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
#include "netopeer2-cli.h"

struct cli_opts opts = {.output_format = LYD_XML};

/* NetConf Client home (appended to ~/) */
#define NCC_DIR ".netopeer2-cli"
/* all these appended to NCC_DIR */
#define CA_DIR "certs"
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


/**
 * @brief Loads the authentication method preference from the configuration.

 * @param node Node to load from.
 * @param auth_pref_type Type of the authentication method preference to set.
 */
static void
load_auth_pref(const struct lyd_node *node, int auth_pref_type)
{
    int pref_value;

    if (!strcmp(lyd_get_value(node), "disabled")) {
        pref_value = -1;
    } else {
        pref_value = strtoul(lyd_get_value(match), NULL, 10);
    }
    nc_client_ssh_set_auth_pref(auth_pref_type, pref_value);
}

void
load_config(void)
{
    char *netconf_dir = NULL, *config_file = NULL;
    struct lyd_node *config = NULL, *match = NULL, *client;
    struct ly_ctx *ctx = NULL;

#ifdef NC_ENABLED_SSH_TLS
    const char *key_pub, *key_priv;
    struct lyd_node *auth_pref, *parent, *key;
#endif

    if ((netconf_dir = get_netconf_dir()) == NULL) {
        goto cleanup;
    }

    if (ly_ctx_new(NULL, 0, &ctx)) {
        ERROR(__func__, "Failed to create context.");
        ERROR(__func__, "Unable to load configuration due to the previous error.");
        goto cleanup;
    }

    if (lys_parse_mem(ctx, netopeer2_cli_yang, LYS_IN_YANG, NULL)) {
        ERROR(__func__, "Failed to load netopeer2-cli YANG module from memory.");
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

    if (lyd_parse_data_path(ctx, config_file, LYD_XML, 0, LYD_VALIDATE_PRESENT, &config)) {
        ERROR(__func__, "Failed to load configuration of NETCONF client (lyxml_read_path failed).");
        goto cleanup;
    }

    if (!config || strcmp(LYD_NAME(config), "netconf-client")) {
        ERROR(__func__, "Unknown stored configuration data.");
        goto cleanup;
    }

    client = config;

    /* <netconf-client> -> <editor> */
    lyd_find_path(client, "editor", 0, &match);
    if (match) {
        free(opts.config_editor);
        opts.config_editor = strdup(lyd_get_value(match));
    }

    /* <netconf-client> -> <search-path> */
    lyd_find_path(client, "search-path", 0, &match);
    if (match) {
        errno = 0;
        if (!mkdir(lyd_get_value(match), 00700) || (errno == EEXIST)) {
            if (errno == 0) {
                ERROR(__func__, "Search path \"%s\" did not exist, created.", lyd_get_value(match));
            }
            nc_client_set_schema_searchpath(lyd_get_value(match));
        } else {
            ERROR(__func__, "Search path \"%s\" cannot be created (%s).", lyd_get_value(match), strerror(errno));
        }
    }

    /* <netconf-client> -> <output-format> */
    lyd_find_path(client, "output-format", 0, &match);
    if (!strcmp(lyd_get_value(match), "json")) {
        opts.output_format = LYD_JSON;
    } /* else default (formatted XML) */

    /* <netconf-client> -> <shrink> */
    lyd_find_path(client, "shrink", 0, &match);
    if (!strcmp(lyd_get_value(match), "true")) {
        opts.output_flag = 1;
    } /* else default (formatted XML) */
#ifdef NC_ENABLED_SSH_TLS
    lyd_find_path(client, "authentication", 0, &auth_pref);

    /* <netconf-client> -> <authentication> -> <method-preference>*/
    lyd_find_path(auth_pref, "method-preference", 0, &parent);
    lyd_find_path(parent, "publickey", 0, &match);
    load_auth_pref(match, NC_SSH_AUTH_PUBLICKEY);

    lyd_find_path(parent, "interactive", 0, &match);
    load_auth_pref(match, NC_SSH_AUTH_INTERACTIVE);

    lyd_find_path(parent, "password", 0, &match);
    load_auth_pref(match, NC_SSH_AUTH_PASSWORD);

    /* <netconf-client> -> <authentication> -> <keys>*/
    lyd_find_path(auth_pref, "keys", 0, &parent);
    if (parent) {
        LY_LIST_FOR(lyd_child(parent), key) {
            key_pub = NULL;
            key_priv = NULL;

            lyd_find_path(key, "public", 0, &match);
            key_pub = lyd_get_value(match);

            lyd_find_path(key, "private", 0, &match);
            key_priv = lyd_get_value(match);

            if (key_pub && key_priv) {
                nc_client_ssh_ch_add_keypair(key_pub, key_priv);
                nc_client_ssh_add_keypair(key_pub, key_priv);
            }
        }
    }

    /* <netconf-client> -> <authentication> -> <knownhost-mode>*/
    lyd_find_path(auth_pref, "knownhost-mode", 0, &match);
    str2knownhosts_mode(lyd_get_value(match), &opts.knownhosts_mode);

    nc_client_ssh_set_knownhosts_mode(opts.knownhosts_mode);
    nc_client_ssh_ch_set_knownhosts_mode(opts.knownhosts_mode);
#endif /* NC_ENABLED_SSH_TLS */

cleanup:
    lyd_free_tree(config);
    ly_ctx_destroy(ctx);
    free(config_file);
    free(netconf_dir);
}


/**
 * @brief Stores the current configuration of the authentication method preference to a file.
 *
 * @param pref_type Type of the authentication method preference to store.
 * @param auth_parent Parent node for the authentication method.
 * @param auth_name Name of the authentication method.
 * @return 0 on success.
 * @return 1 on failure.
 */
static int
store_auth_pref(int pref_type, struct lyd_node *auth_parent, const char *auth_name)
{
    int pref_value;
    char buf[23];

    pref_value = nc_client_ssh_get_auth_pref(pref_type);
    if (pref_value < 0) {
        if (lyd_new_term(auth_parent, NULL, auth_name, "disabled", 0, NULL)) {
            return 1;
        }
    } else {
        sprintf(buf, "%d", pref_value);
        if (lyd_new_term(auth_parent, NULL, auth_name, buf, 0, NULL)) {
            return 1;
        }
    }

    return 0;
}

void
store_config(void)
{
#ifdef NC_ENABLED_SSH_TLS
    struct lyd_node *auth, *pref, *keys, *pair;
#endif /* NC_ENABLED_SSH_TLS */
    char *netconf_dir = NULL, *history_file = NULL, *config_file = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;
    struct lys_module *cli = NULL;
    const char *str;

    if (ly_ctx_new(NULL, 0, &ctx)) {
        ERROR(__func__, "Failed to create context.");
        ERROR(__func__, "Unable to store configuration due to the previous error.");
        goto cleanup;
    }

    if (lys_parse_mem(ctx, netopeer2_cli_yang, LYS_IN_YANG, &cli)) {
        ERROR(__func__, "Failed to load netopeer2-cli YANG module from memory.");
        goto cleanup;
    }

    if (lyd_new_inner(NULL, cli, "netconf-client", 0, &root)) {
        ERROR(__func__, "Failed to create contanier netconf-client.");
        goto cleanup;
    }

    /* editor */
    if (lyd_new_term(root, NULL, "editor", opts.config_editor, 0, NULL)) {
        goto cleanup;
    }

    /* output-format */
    if (opts.output_format == LYD_JSON) {
        str = "json";
    } else if (opts.output_format == LYD_XML) {
        str = "xml";
    } else {
        ERROR(__func__, "Unknown format.");
        goto cleanup;
    }   

    if (lyd_new_term(root, NULL, "output-format", str, 0, NULL)) {
        goto cleanup;
    }

    /* shrink*/
    if (lyd_new_term(root, NULL, "shrink", opts.output_flag ? "true" : "false", 0, NULL)) {
        goto cleanup;
    }

    /* search-path */
    if (nc_client_get_schema_searchpath()) {
        if (lyd_new_term(root, NULL, "searchpath", nc_client_get_schema_searchpath(), 0, NULL)) {
            goto cleanup;
        }
    }

#ifdef NC_ENABLED_SSH_TLS
    /* SSH authentication */
    if (lyd_new_inner(root, NULL, "authentication", 0, &auth)) {
        goto cleanup;
    }

    /* pref */
    if (lyd_new_inner(auth, NULL, "method-preference", 0,&pref)) {
        goto cleanup;
    }
    
    if (store_auth_pref(NC_SSH_AUTH_PUBLICKEY, pref, "publickey")) {
        goto cleanup;
    }
    
    if (store_auth_pref(NC_SSH_AUTH_PASSWORD, pref, "password")) {
        goto cleanup;
    }
    
    if (store_auth_pref(NC_SSH_AUTH_INTERACTIVE, pref, "interactive")) {
        goto cleanup;
    }

    /* keys */
    if (nc_client_ssh_get_keypair_count()) {
        if (lyd_new_inner(auth, NULL, "keys", 0, &keys)) {
            goto cleanup;
        }

        /* pair(s) */
        for (int i = 0; i < nc_client_ssh_get_keypair_count(); ++i) {
            const char *priv_key, *pub_key;

            nc_client_ssh_get_keypair(i, &pub_key, &priv_key);
            if (lyd_new_list(keys, NULL, "pair", 0, &pair, pub_key)) {
                goto cleanup;
            }
            if (lyd_new_term(pair, NULL, "private", priv_key, 0, NULL)) {
                goto cleanup;
            }
        }
    }
#endif /* NC_ENABLED_SSH_TLS */

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