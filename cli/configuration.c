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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <dirent.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#ifndef HAVE_EACCESS
#define eaccess access
#endif

#include "configuration.h"
#include "commands.h"
#include "linenoise/linenoise.h"

extern LYD_FORMAT output_format;
extern int output_flag;
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

    ret = eaccess(netconf_dir, R_OK | X_OK);
    if (ret == -1) {
        if (errno == ENOENT) {
            /* directory does not exist */
            ERROR("get_netconf_dir", "Configuration directory \"%s\" does not exist, creating it.", netconf_dir);
            if (mkdir(netconf_dir, 00700)) {
                ERROR("get_netconf_dir", "Configuration directory \"%s\" cannot be created: %s", netconf_dir, strerror(errno));
                free(netconf_dir);
                return NULL;
            }
        } else {
            ERROR("get_netconf_dir", "Configuration directory \"%s\" exists but something else failed: %s", netconf_dir, strerror(errno));
            free(netconf_dir);
            return NULL;
        }
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
    if (asprintf(cert, "%s/%s", netconf_dir, CERT_CRT) == -1 || asprintf(key, "%s/%s", netconf_dir, CERT_KEY) == -1) {
        ERROR("get_default_client_cert", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR("get_default_client_cert", "Unable to use the default client certificate due to the previous error.");
        free(netconf_dir);
        return;
    }

    if (eaccess(*cert, R_OK) == -1 || eaccess(*key, R_OK) == -1) {
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
    struct lyxml_elem *config_xml = NULL, *child;
    struct ly_ctx *ctx;

#ifdef NC_ENABLED_SSH
    const char *key_pub, *key_priv;
    struct lyxml_elem *auth_child, *pref_child, *key_child, *pair_child;
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

    ctx = ly_ctx_new(NULL, 0);
    if (!ctx) {
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
            if ((config_xml = lyxml_parse_path(ctx, config_file, 0)) == NULL) {
                ERROR(__func__, "Failed to load configuration of NETCONF client (lyxml_read_path failed).");
                config_xml = NULL;
            } else {
                /* doc -> <netconf-client/>*/
                if (!strcmp(config_xml->name, "netconf-client")) {
                    LY_TREE_FOR(config_xml->child, child) {
                        if (!strcmp(child->name, "editor")) {
                            /* doc -> <netconf-client> -> <editor> */
                            if (config_editor) {
                                free(config_editor);
                            }
                            config_editor = strdup(child->content);
                        } else if (!strcmp(child->name, "searchpath")) {
                            /* doc -> <netconf-client> -> <searchpath> */
                            errno = 0;
                            if (eaccess(child->content, R_OK | W_OK | X_OK) && (errno == ENOENT)) {
                                ERROR(__func__, "Search path \"%s\" does not exist, creating it.", child->content);
                                if (mkdir(child->content, 00700)) {
                                    ERROR(__func__, "Search path \"%s\" cannot be created: %s", child->content, strerror(errno));
                                } else {
                                    nc_client_set_schema_searchpath(child->content);
                                }
                            } else {
                                nc_client_set_schema_searchpath(child->content);
                            }
                        } else if (!strcmp(child->name, "output-format")) {
                            /* doc -> <netconf-client> -> <output-format> */
                            if (!strcmp(child->content, "json")) {
                                output_format = LYD_JSON;
                                output_flag = LYP_FORMAT;
                            } else if (!strcmp(child->content, "json_noformat")) {
                                output_format = LYD_JSON;
                                output_flag = 0;
                            } else if (!strcmp(child->content, "xml_noformat")) {
                                output_format = LYD_XML;
                                output_flag = 0;
                            } /* else default (formatted XML) */
                        }
#ifdef NC_ENABLED_SSH
                        else if (!strcmp(child->name, "authentication")) {
                            /* doc -> <netconf-client> -> <authentication> */
                            LY_TREE_FOR(child->child, auth_child) {
                                if (!strcmp(auth_child->name, "pref")) {
                                    LY_TREE_FOR(auth_child->child, pref_child) {
                                        if (!strcmp(pref_child->name, "publickey")) {
                                            nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, atoi(pref_child->content));
                                        } else if (!strcmp(pref_child->name, "interactive")) {
                                            nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, atoi(pref_child->content));
                                        } else if (!strcmp(pref_child->name, "password")) {
                                            nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, atoi(pref_child->content));
                                        }
                                    }
                                } else if (!strcmp(auth_child->name, "keys")) {
                                    LY_TREE_FOR(auth_child->child, key_child) {
                                        if (!strcmp(key_child->name, "pair")) {
                                            key_pub = NULL;
                                            key_priv = NULL;
                                            LY_TREE_FOR(key_child->child, pair_child) {
                                                if (!strcmp(pair_child->name, "public")) {
                                                    key_pub = pair_child->content;
                                                } else if (!strcmp(pair_child->name, "private")) {
                                                    key_priv = pair_child->content;
                                                }
                                            }
                                            if (key_pub && key_priv) {
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

    lyxml_free(ctx, config_xml);
    ly_ctx_destroy(ctx, NULL);
    free(config_file);
    free(history_file);
    free(netconf_dir);
}

void
store_config(void)
{
    char *netconf_dir, *history_file, *config_file;
    const char *priv_key, *pub_key;
    int i, indent;
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
        fprintf(config_f, "%*.s<netconf-client>\n", indent, "");
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
                fprintf(config_f, "json");
            } else {
                fprintf(config_f, "json_noformat");
            }
        } else {
            if (output_flag) {
                fprintf(config_f, "xml");
            } else {
                fprintf(config_f, "xml_noformat");
            }
        }
        fprintf(config_f, "</output-format>\n");

        /* authentication */
        fprintf(config_f, "%*.s<authentication>\n", indent, "");
        ++indent;

        /* pref */
        fprintf(config_f, "%*.s<pref>\n", indent, "");
        ++indent;

        fprintf(config_f, "%*.s<publickey>%d</publickey>\n", indent, "", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY));
        fprintf(config_f, "%*.s<password>%d</password>\n", indent, "", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD));
        fprintf(config_f, "%*.s<interactive>%d</interactive>\n", indent, "", nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE));

        --indent;
        fprintf(config_f, "%*.s</pref>\n", indent, "");

        /* keys */
        if (nc_client_ssh_get_keypair_count()) {
            fprintf(config_f, "%*.s<keys>\n", indent, "");
            ++indent;

            /* pair(s) */
            for (i = 0; i < nc_client_ssh_get_keypair_count(); ++i) {
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

        --indent;
        fprintf(config_f, "%*.s</netconf-client>\n", indent, "");

        fclose(config_f);
    }

    free(history_file);
    free(netconf_dir);
    free(config_file);
}
