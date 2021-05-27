/**
 * @file configuration.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli configuration
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
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

extern LYD_FORMAT output_format;
extern uint32_t output_flag;
extern char *config_editor;

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
            free(cert_dir);
            return NULL;
        }
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
            free(crl_dir);
            return NULL;
        }
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
load_config(void)
{
    char *netconf_dir, *history_file, *config_file = NULL;
    struct lyd_node *config = NULL, *child;
    struct ly_ctx *ctx;

#ifdef NC_ENABLED_SSH
    const char *key_pub, *key_priv;
    struct lyd_node *auth_child, *pref_child, *key_child, *pair_child;
#endif

    if ((netconf_dir = get_netconf_dir()) == NULL) {
        return;
    }

    if (asprintf(&history_file, "%s/history", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to load commands history due to the previous error.");
        history_file = NULL;
    } else {
        if (eaccess(history_file, F_OK) && (errno == ENOENT)) {
            ERROR(__func__, "No saved history.");
        } else if (linenoiseHistoryLoad(history_file)) {
            ERROR(__func__, "Failed to load history.");
        }
    }

    if (ly_ctx_new(NULL, 0, &ctx)) {
        ERROR(__func__, "Failed to create context.");
        ERROR(__func__, "Unable to load configuration due to the previous error.");
        ctx = NULL;
    } else {
        if (asprintf(&config_file, "%s/config.xml", netconf_dir) == -1) {
            ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
            ERROR(__func__, "Unable to load configuration due to the previous error.");
            config_file = NULL;
        } else if (eaccess(config_file, F_OK) && (errno == ENOENT)) {
            ERROR(__func__, "No saved configuration.");
        } else {
            if (lyd_parse_data_path(ctx, config_file, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ, 0, &config)) {
                ERROR(__func__, "Failed to load configuration of NETCONF client (lyxml_read_path failed).");
                config = NULL;
            } else {
                /* doc -> <netconf-client/>*/
                if (!strcmp(LYD_NAME(config), "netconf-client")) {
                    LY_LIST_FOR(lyd_child(config), child) {
                        if (!strcmp(LYD_NAME(child), "editor")) {
                            /* doc -> <netconf-client> -> <editor> */
                            if (config_editor) {
                                free(config_editor);
                            }
                            config_editor = strdup(lyd_get_value(child));
                        } else if (!strcmp(LYD_NAME(child), "searchpath")) {
                            /* doc -> <netconf-client> -> <searchpath> */
                            errno = 0;
                            if (!mkdir(lyd_get_value(child), 00700) || (errno == EEXIST)) {
                                if (errno == 0) {
                                    ERROR(__func__, "Search path \"%s\" did not exist, created.", lyd_get_value(child));
                                }
                                nc_client_set_schema_searchpath(lyd_get_value(child));
                            } else {
                                ERROR(__func__, "Search path \"%s\" cannot be created: %s", lyd_get_value(child), strerror(errno));
                            }
                        } else if (!strcmp(LYD_NAME(child), "output-format")) {
                            /* doc -> <netconf-client> -> <output-format> */
                            if (!strcmp(lyd_get_value(child), "json")) {
                                output_format = LYD_JSON;
                                output_flag = 0;
                            } else if (!strcmp(lyd_get_value(child), "json_noformat")) {
                                output_format = LYD_JSON;
                                output_flag = LYD_PRINT_SHRINK;
                            } else if (!strcmp(lyd_get_value(child), "xml_noformat")) {
                                output_format = LYD_XML;
                                output_flag = LYD_PRINT_SHRINK;
                            } /* else default (formatted XML) */
                        }
#ifdef NC_ENABLED_SSH
                        else if (!strcmp(LYD_NAME(child), "authentication")) {
                            /* doc -> <netconf-client> -> <authentication> */
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
                }
            }
        }
    }

    lyd_free_tree(config);
    ly_ctx_destroy(ctx);
    free(config_file);
    free(history_file);
    free(netconf_dir);
}

void
store_config(void)
{
    char *netconf_dir, *history_file, *config_file;
    int indent;
    FILE *config_f = NULL;

    if ((netconf_dir = get_netconf_dir()) == NULL) {
        return;
    }

    if (asprintf(&history_file, "%s/history", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to store commands history due to the previous error.");
        history_file = NULL;
    } else {
        if (linenoiseHistorySave(history_file)) {
            ERROR(__func__, "Failed to save history.");
        }
    }

    if (asprintf(&config_file, "%s/config.xml", netconf_dir) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to store configuration due to the previous error.");
        config_file = NULL;
    } else if ((config_f = fopen(config_file, "w")) == NULL) {
        ERROR(__func__, "fopen failed (%s).", strerror(errno));
        ERROR(__func__, "Unable to store configuration due to the previous error.");
    } else {
        indent = 0;
        fprintf(config_f, "%*.s<netconf-client xmlns=\"urn:cesnet:netconf-client\">\n", indent, "");
        ++indent;

        /* editor */
        fprintf(config_f, "%*.s<editor>%s</editor>\n", indent, "", config_editor);

        /* search-path */
        if (nc_client_get_schema_searchpath()) {
            fprintf(config_f, "%*.s<searchpath>%s</searchpath>\n", indent, "", nc_client_get_schema_searchpath());
        }

        /* output-format */
        fprintf(config_f, "%*.s<output-format>", indent, "");
        if (output_format == LYD_JSON) {
            if (output_flag) {
                fprintf(config_f, "json_noformat");
            } else {
                fprintf(config_f, "json");
            }
        } else {
            if (output_flag) {
                fprintf(config_f, "xml_noformat");
            } else {
                fprintf(config_f, "xml");
            }
        }
        fprintf(config_f, "</output-format>\n");

#ifdef NC_ENABLED_SSH
        /* SSH authentication */
        fprintf(config_f, "%*.s<authentication>\n", indent, "");
        ++indent;

        /* pref */
        fprintf(config_f, "%*.s<pref>\n", indent, "");
        ++indent;

        fprintf(config_f, "%*.s<publickey>%d</publickey>\n", indent, "", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY));
        fprintf(config_f, "%*.s<password>%d</password>\n", indent, "", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD));
        fprintf(config_f, "%*.s<interactive>%d</interactive>\n", indent, "",
                nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE));

        --indent;
        fprintf(config_f, "%*.s</pref>\n", indent, "");

        /* keys */
        if (nc_client_ssh_get_keypair_count()) {
            fprintf(config_f, "%*.s<keys>\n", indent, "");
            ++indent;

            /* pair(s) */
            for (int i = 0; i < nc_client_ssh_get_keypair_count(); ++i) {
                const char *priv_key, *pub_key;

                nc_client_ssh_get_keypair(i, &pub_key, &priv_key);
                fprintf(config_f, "%*.s<pair>\n", indent, "");
                ++indent;

                fprintf(config_f, "%*.s<public>%s</public>\n", indent, "", pub_key);
                fprintf(config_f, "%*.s<private>%s</private>\n", indent, "", priv_key);

                --indent;
                fprintf(config_f, "%*.s</pair>\n", indent, "");
            }

            --indent;
            fprintf(config_f, "%*.s</keys>\n", indent, "");
        }

        --indent;
        fprintf(config_f, "%*.s</authentication>\n", indent, "");
#endif

        --indent;
        fprintf(config_f, "%*.s</netconf-client>\n", indent, "");

        fclose(config_f);
    }

    free(history_file);
    free(netconf_dir);
    free(config_file);
}
